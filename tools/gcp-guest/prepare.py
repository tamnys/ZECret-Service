#!/usr/bin/env python3
"""Offline candidate staging, never image publication or release approval.

Run inside the managed Linux container. No package installer, cloud client,
credential discovery, image builder, signing operation or scheduler is invoked.
"""
import argparse
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid

import debian_snapshot
import verify_builder_closure

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "deploy/gcp/guest"
PACKAGE_CLOSURE_LOCK = PROFILE / "package-closure.lock.json"
PACKAGE_CLOSURE_SHA256 = "a6994a27c6bcfbed584751ed6eb10cb393c21808c58b628b3ff1584a570b0ca5"
PROJECT_SYSUSERS_SHA256 = "bb73c9f2f8cc45f160ffde8f21870e588cf728e2c7f7ec6f47978cfde14fd8d6"
# Reviewed deterministic transform of the signed-input account diagnostic:
# root's shell is nologin and its password is permanently invalid. The
# generator's host dynamic runtime is not part of the production build path.
ACCOUNT_OUTPUTS = {
    "passwd": (1100, "f42d295b4a2ad2a9d9a82865bc4ba6043fafe03e77e5b57e7081a8d67450c2ff", 0o644, 0o644),
    "group": (661, "c2209f60f6d80a4b10479c1ba9e2df7877bb8a648911a45629f0dc6d86bb1b00", 0o644, 0o644),
    "shadow": (509, "92ec1ef612eb9c38cbe22403a595d268bf38546cadded7d8e0471bf271f15d13", 0o644, 0o400),
}
SOURCE_COMMIT = "54c625c380ef5500f17460981a3c67b109b6a847"
KERNEL_VERSION = "6.12.107+deb13-cloud-amd64"
KERNEL_PACKAGE = f"linux-image-{KERNEL_VERSION}"
KERNEL_PACKAGE_VERSION = "6.12.107-1"
BINARIES = {"wrapper": "zrpc-node-wrapper", "broker": "zrpc-gcp-quote-broker", "guard": "zrpc-gcp-guard", "disk_id": "zrpc-gcp-disk-id", "cookie": "zrpc-gcp-cookie", "zebra": "zebrad"}
EARLY_INIT_ROLE = "early_init"
# These are signed Debian archives, extracted as inert data. Their package
# scripts, NVMe-oF units, udev rules, CLI plugins, UUID daemon, and the
# uuid-runtime/adduser/passwd dependency closure are never installed.
DISK_TOOL_PACKAGES = {
    "nvme_cli_deb": {"name": "nvme-cli", "version": "2.13-2", "architecture": "amd64", "filename": "pool/main/n/nvme-cli/nvme-cli_2.13-2_amd64.deb", "size": 801800, "sha256": "cd78752dd935ba71c676fc6cb1fd0b3d671c447bff33677caf4a20b2f32921d4"},
    "libnvme_deb": {"name": "libnvme1t64", "version": "1.13-2", "architecture": "amd64", "filename": "pool/main/libn/libnvme/libnvme1t64_1.13-2_amd64.deb", "size": 81324, "sha256": "1de883115b82a991b7b1b456177c4d4ab122d6ecc1db106d649cf0203cf04745"},
    "libkeyutils_deb": {"name": "libkeyutils1", "version": "1.6.3-6", "architecture": "amd64", "filename": "pool/main/k/keyutils/libkeyutils1_1.6.3-6_amd64.deb", "size": 9456, "sha256": "0b11ad17be0300b63ad4eeb4c6450fed24d34b7b740f23e5363dcb29ee6d5eba"},
}
DISK_TOOL_ELFS = {
    "usr/sbin/nvme": ("nvme_cli_deb", "usr/sbin/nvme", 1477760, "2ecb01494cd51dc4793f14ce30bdd18133f0caad48316e7d7c8093c687957140"),
    "usr/lib/x86_64-linux-gnu/libnvme.so.1": ("libnvme_deb", "libnvme.so.1", 209096, "49eb38e4e8952b4f38946562d35419354209116082bce9172bd969faa3293c85"),
    "usr/lib/x86_64-linux-gnu/libnvme-mi.so.1": ("libnvme_deb", "libnvme-mi.so.1", 35392, "c9066ca1ab54637064ccd4f0b2c8dce13563ac3591d53f3417e2e1db935feac0"),
    "usr/lib/x86_64-linux-gnu/libkeyutils.so.1": ("libkeyutils_deb", "libkeyutils.so.1", 22448, "e5d5a7450d08eff7d4bbcaac75ef2b94d3447c81a1b2ddf3ab85d2de4709a9a8"),
}
PINNED_DISK_FILES = {
    "etc/fstab": "9ea5dfdcd0381e01357a1fabaf36a7b612151c9f2e6e49b627718453d4267169",
    "usr/lib/udev/rules.d/65-gce-disk-naming.rules": "b06b83104359437859d4f497973eede0da1d8b3958afc4aab073d9f94e9d7b19",
    "usr/lib/systemd/system/zrpc-gcp-disk-trigger.service": "60da51b2fb02e6591a42bdce024594c3f891a314d5622ab88237049ae3ac9737",
}
ROLES = set(BINARIES) | set(DISK_TOOL_PACKAGES) | {EARLY_INIT_ROLE, "secure_boot_certificate", "package_manifest", "snapshot_inrelease", "packages_index", "boot_policy"}
# Builder-only handoff. A later operator build must supply this private key
# from a memory-backed mount. Staging never checks that mount, copies the key,
# or treats this reference as evidence of a signed image.
EXTERNAL_SECURE_BOOT_KEY = "/run/zrpc-build-signing/secure-boot.key"
INITRD_PACKAGES = {"systemd", "udev", "systemd-cryptsetup", "dmsetup", "kmod", "mount"}
ROOT_REMOVE_FILES = (
    "/usr/sbin/unix_chkpwd", "/usr/bin/umount", "/usr/bin/su",
    "/usr/sbin/losetup", "/usr/sbin/swapon", "/usr/sbin/swapoff",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
)
INITRD_REMOVE_FILES = (
    "/usr/lib/systemd/system/rescue.service",
    "/usr/lib/systemd/system/rescue.target",
    "/usr/lib/systemd/system/emergency.service",
    "/usr/lib/systemd/system/emergency.target",
    "/usr/lib/systemd/system/debug-shell.service",
    "/usr/lib/systemd/system/getty.target",
    "/usr/lib/systemd/system/getty@.service",
    "/etc/systemd/system/getty.target.wants/getty@tty1.service",
    "/usr/lib/systemd/system/autovt@.service",
    "/usr/lib/systemd/system/serial-getty@.service",
    "/usr/lib/systemd/system/console-getty.service",
    "/usr/lib/systemd/system/container-getty@.service",
    "/usr/lib/systemd/system/multi-user.target.wants/getty.target",
    "/usr/lib/systemd/system/runlevel1.target",
    "/usr/lib/systemd/system/systemd-sysext.service",
    "/usr/lib/systemd/system/systemd-sysext.socket",
    "/usr/lib/systemd/system/systemd-sysext@.service",
    "/usr/lib/systemd/system/sockets.target.wants/systemd-sysext.socket",
    "/usr/lib/systemd/system/systemd-confext.service",
    "/usr/lib/systemd/system/systemd-udev-load-credentials.service",
    "/usr/lib/systemd/system/systemd-pstore.service",
    "/usr/lib/systemd/system/systemd-network-generator.service",
    "/etc/systemd/system/sysinit.target.wants/systemd-sysext.service",
    "/etc/systemd/system/sockets.target.wants/systemd-sysext.socket",
    "/etc/systemd/system/sysinit.target.wants/systemd-confext.service",
    "/etc/systemd/system/sysinit.target.wants/systemd-udev-load-credentials.service",
    "/etc/systemd/system/sysinit.target.wants/systemd-pstore.service",
    "/etc/systemd/system/sysinit.target.wants/systemd-network-generator.service",
    "/usr/lib/systemd/systemd-sulogin-shell",
    "/boot/loader",
    "/var/log/journal",
    "/var/mail",
    "/etc/ssh",
    "/usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf",
    "/usr/sbin/unix_chkpwd", "/usr/bin/umount",
    "/usr/sbin/losetup", "/usr/sbin/swapon", "/usr/sbin/swapoff",
    "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/sh",
    "/usr/bin/perl", "/usr/bin/perl5.40.1",
    "/usr/sbin/sulogin", "/usr/bin/login", "/usr/bin/su",
)
# The parent never mounts anything. This runs only after unshare has created
# both namespaces, and checks their identities before invoking mount(8).
# The temporary mount disappears with the child namespace even if cleanup
# fails; a successful probe also requires an explicit unmount.
MOUNT_PROBE_SCRIPT = r'''
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parent_user, parent_mount, mount_tool, umount_tool = sys.argv[1:]
if (os.readlink("/proc/self/ns/user") == parent_user
        or os.readlink("/proc/self/ns/mnt") == parent_mount):
    raise SystemExit(1)

with tempfile.TemporaryDirectory(prefix="zrpc-builder-mount-probe-") as target:
    mounted = subprocess.run(
        [mount_tool, "-t", "tmpfs", "-o", "nodev,nosuid,noexec", "tmpfs", target],
        capture_output=True, check=False,
    )
    if mounted.returncode:
        raise SystemExit(1)
    try:
        # Do not trust a zero exit from mount(8) without observing the mount.
        found = any(
            line.split(" - ", 1)[1].split()[0] == "tmpfs"
            and line.split(" - ", 1)[0].split()[4] == target
            for line in Path("/proc/self/mountinfo").read_text().splitlines()
            if " - " in line
        )
    finally:
        unmounted = subprocess.run(
            [umount_tool, "--", target], capture_output=True, check=False,
        )
    if not found or unmounted.returncode:
        raise SystemExit(1)

print("zrpc-isolated-tmpfs-ok")
'''
REPART_SEED_NAME_PREFIX = "https://github.com/tamnys/ZECret-service/gcp-guest-seed/v1/"
# A unit's ImportCredential= can still read /run/credstore with the manager's
# external credential imports disabled by the fixed kernel command line.
# In the pinned kernel, pstore_register() rejects every backend except the
# selected name; no shipped backend is named "none".
FIXED_KERNEL_CMDLINE = "ro systemd.gpt_auto=0 rd.systemd.gpt_auto=0 rd.modules_load=dm-verity systemd.import_credentials=no systemd.unit=zrpc.target systemd.crash_shell=0 systemd.crash_action=poweroff systemd.dump_core=0 systemd.mask=debug-shell.service systemd.mask=systemd-hibernate.service systemd.mask=systemd-hybrid-sleep.service systemd.mask=systemd-suspend-then-hibernate.service pstore.backend=none panic=-1 oops=panic module.sig_enforce=1 lockdown=confidentiality"
MASKS = ("ssh.service", "sshd.service", "ssh.socket", "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service", "container-getty@.service", "debug-shell.service", "rescue.service", "rescue.target", "emergency.service", "emergency.target", "systemd-hibernate.service", "systemd-suspend.service", "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service", "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service", "systemd-sysext.socket", "systemd-sysext@.service", "systemd-confext.service", "systemd-udev-load-credentials.service", "systemd-network-generator.service", "systemd-sysupdate.service", "systemd-sysupdate.timer", "systemd-firstboot.service", "systemd-sysusers.service", "systemd-user-sessions.service", "cloud-init.service", "cloud-final.service", "google-guest-agent.service", "google-osconfig-agent.service", "apt-daily.timer", "apt-daily-upgrade.timer")
FORBIDDEN_PACKAGES = {"openssh-server", "cloud-init", "google-guest-agent", "google-osconfig-agent", "docker.io", "containerd", "systemd-container", "sudo", "polkitd", "nvme-cli", "libnvme1t64", "libkeyutils1", "uuid-runtime", "adduser", "passwd"}

def install_boot_overrides(rootfs):
    """Install the same immutable unit policy in production and root probes."""
    masks = rootfs / "etc/systemd/system"
    masks.mkdir(parents=True, exist_ok=True)
    for name in MASKS:
        (masks / name).symlink_to("/dev/null")
    (masks / "default.target").symlink_to("/usr/lib/systemd/system/zrpc.target")
    (masks / "multi-user.target.wants").mkdir()
    for name in ("systemd-networkd.service", "systemd-resolved.service"):
        (masks / "multi-user.target.wants" / name).symlink_to("/usr/lib/systemd/system/" + name)
    (rootfs / "etc/resolv.conf").symlink_to("/run/systemd/resolve/stub-resolv.conf")

def validate_boot_profile(profile=PROFILE, staged_copy=False):
    """Reject source drift that would omit the direct UKI or unbind the root."""
    # mkosi discovers settings and executable hooks by filename. The staged
    # directory is created fresh from these reviewed source entries only.
    expected_entries = {"mkosi.conf", "mkosi.images", "repart", "rootfs"}
    if not staged_copy:
        expected_entries |= {"input-identities.json", "package-closure.lock.json"}
    if {path.name for path in profile.iterdir()} != expected_entries or any(path.is_symlink() for path in profile.iterdir()):
        raise ValueError("unexpected mkosi source override or redirected input")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with (profile / "mkosi.conf").open() as stream:
        parser.read_file(stream)
    expected_settings = {
        "Distribution": {"Distribution": "debian", "Release": "trixie", "Architecture": "x86-64", "RepositoryKeyCheck": "yes", "RepositoryKeyFetch": "no"},
        "Output": {"Format": "disk", "Output": "zrpc-gcp", "ManifestFormat": "json", "RepartDirectories": "repart", "SectorSize": "512"},
        "Config": {"Dependencies": "initrd"},
        "Content": {"Bootable": "yes", "Bootloader": "uki", "BiosBootloader": "none", "ShimBootloader": "none", "UnifiedKernelImages": "yes", "KernelModulesInitrd": "yes", "KernelModulesInitrdInclude": "^drivers/md/dm-verity[.]ko[.]xz$", "KernelModulesInitrdExclude": ".*", "Autologin": "no", "Ssh": "no", "KernelCommandLine": FIXED_KERNEL_CMDLINE, "ExtraTrees": "rootfs", "RemoveFiles": ",".join(ROOT_REMOVE_FILES)},
        "Validation": {"SecureBoot": "yes", "SecureBootAutoEnroll": "no", "SignExpectedPcr": "no", "Checksum": "yes"},
        "Build": {"WithNetwork": "no", "CacheOnly": "always", "Incremental": "no"},
    }
    if {section: dict(parser.items(section)) for section in parser.sections()} != expected_settings:
        raise ValueError("direct signed-UKI image recipe differs")
    images = profile / "mkosi.images"
    initrd = images / "initrd"
    if not images.is_dir() or images.is_symlink() or {path.name for path in images.iterdir()} != {"initrd"} or not initrd.is_dir() or initrd.is_symlink() or {path.name for path in initrd.iterdir()} != {"mkosi.conf"}:
        raise ValueError("unexpected initrd subimage input")
    initrd_config = initrd / "mkosi.conf"
    if not initrd_config.is_file() or initrd_config.is_symlink():
        raise ValueError("initrd subimage missing or redirected")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with initrd_config.open() as stream:
        parser.read_file(stream)
    expected_initrd = {
        "Output": {"Format": "cpio", "Output": "initrd", "ManifestFormat": "json", "CompressOutput": "zstd"},
        "Content": {"Bootable": "no", "MakeInitrd": "yes", "Autologin": "no", "Ssh": "no", "CleanPackageMetadata": "yes", "WithDocs": "no", "RemoveFiles": ",".join(INITRD_REMOVE_FILES)},
    }
    if {section: dict(parser.items(section)) for section in parser.sections()} != expected_initrd:
        raise ValueError("systemd initrd subimage recipe differs")
    if any((profile / "rootfs" / path).exists() or (profile / "rootfs" / path).is_symlink() for path in ("boot", "lib/modules", "usr/lib/modules")):
        raise ValueError("ExtraTrees must not supply a kernel or module tree")
    sysusers = profile / "rootfs/usr/lib/sysusers.d/zrpc.conf"
    if (sysusers.is_symlink() or not sysusers.is_file()
            or digest(sysusers) != PROJECT_SYSUSERS_SHA256):
        raise ValueError("project sysusers source differs from reviewed accounts")
    for name, (size, expected_sha256, source_mode, _) in ACCOUNT_OUTPUTS.items():
        path = profile / "rootfs/etc" / name
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_size != size
                or stat.S_IMODE(path.stat().st_mode) != source_mode
                or digest(path) != expected_sha256):
            raise ValueError("reviewed guest account source differs: " + name)
    for relative, expected_sha256 in PINNED_DISK_FILES.items():
        path = profile / "rootfs" / relative
        if (path.is_symlink() or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) != 0o644
                or digest(path) != expected_sha256):
            raise ValueError("measured public-disk boot input differs: " + relative)
    repart = profile / "repart"
    expected = {"10-root.conf", "20-root-verity.conf", "30-esp.conf"}
    if {path.name for path in repart.iterdir()} != expected:
        raise ValueError("unexpected repart definition")
    definitions = {
        "10-root.conf": ("[Partition]", "Type=root-x86-64", "Format=ext4", "CopyFiles=/", "Minimize=guess", "ReadOnly=yes", "Verity=data", "VerityMatchKey=root"),
        "20-root-verity.conf": ("[Partition]", "Type=root-x86-64-verity", "Verity=hash", "VerityMatchKey=root", "Minimize=best"),
        "30-esp.conf": ("[Partition]", "Type=esp", "Format=vfat", "CopyFiles=/efi:/", "Minimize=guess"),
    }
    for name, expected_lines in definitions.items():
        path = repart / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("repart definition missing or redirected")
        lines = tuple(line.strip() for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith(("#", ";")))
        if lines != expected_lines:
            raise ValueError("direct UKI or root verity repart definition differs")

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result

def reject_nonfinite_constant(value):
    raise ValueError(f"nonstandard JSON constant: {value}")

def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)

def staged_inventory(directory_fd, expected=None):
    """Inventory the directory by file descriptor without following symlinks.

    The candidate manifest itself is excluded because its digest must be
    recorded outside this tree. An expected inventory rejects added build
    inputs before opening or descending into them.
    """
    entries = {}

    def visit(parent_fd, prefix):
        with os.scandir(parent_fd) as children:
            for child in children:
                relative = f"{prefix}/{child.name}" if prefix else child.name
                if relative == "candidate-manifest.json":
                    continue
                if expected is not None and relative not in expected:
                    raise ValueError("unexpected staged input or build output")
                before = os.stat(child.name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode):
                    entry = {"type": "symlink", "target": os.readlink(child.name, dir_fd=parent_fd)}
                    after = os.stat(child.name, dir_fd=parent_fd, follow_symlinks=False)
                    if (before.st_dev, before.st_ino, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_ctime_ns):
                        raise ValueError("staged symlink changed during inspection")
                elif stat.S_ISDIR(before.st_mode):
                    fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
                    try:
                        opened = os.fstat(fd)
                        if (before.st_dev, before.st_ino, before.st_mode) != (opened.st_dev, opened.st_ino, opened.st_mode):
                            raise ValueError("staged directory changed during inspection")
                        entry = {"type": "directory", "mode": stat.S_IMODE(opened.st_mode)}
                        if expected is not None and expected[relative] != entry:
                            raise ValueError("staged input differs from pinned manifest")
                        entries[relative] = entry
                        visit(fd, relative)
                        after = os.fstat(fd)
                        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns, after.st_ctime_ns):
                            raise ValueError("staged directory changed during inspection")
                    finally:
                        os.close(fd)
                    continue
                elif stat.S_ISREG(before.st_mode):
                    fd = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
                    with os.fdopen(fd, "rb") as stream:
                        opened = os.fstat(stream.fileno())
                        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino, before.st_mode, before.st_size) != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size):
                            raise ValueError("staged file changed during inspection")
                        entry = {"type": "file", "sha256": hashlib.file_digest(stream, "sha256").hexdigest(), "mode": stat.S_IMODE(opened.st_mode)}
                        after = os.fstat(stream.fileno())
                        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                            raise ValueError("staged file changed during inspection")
                else:
                    raise ValueError("unsupported staged input file type")
                if expected is not None and expected[relative] != entry:
                    raise ValueError("staged input differs from pinned manifest")
                entries[relative] = entry

    visit(directory_fd, "")
    if expected is not None and entries.keys() != expected.keys():
        raise ValueError("staged input missing from pinned manifest")
    return dict(sorted(entries.items()))

def open_stage_directory(directory):
    if not directory.is_absolute() or directory.is_symlink() or not directory.resolve(strict=True).is_relative_to(ROOT.resolve()):
        raise ValueError("stage must be a non-symlink directory on the workspace volume")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("stage root is not a directory")
    return fd

def verify_stage(directory, expected_manifest_sha256, expected_manifest_bytes):
    """Check pinned staged inputs; this does not establish a built image."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) or type(expected_manifest_bytes) is not int or expected_manifest_bytes <= 0:
        raise ValueError("recorded candidate manifest identity required")
    root_fd = open_stage_directory(directory)
    try:
        manifest_fd = os.open("candidate-manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
        with os.fdopen(manifest_fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_manifest_bytes:
                raise ValueError("candidate manifest is not the recorded regular file")
            manifest_bytes = stream.read(expected_manifest_bytes)
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("candidate manifest changed during inspection")
        if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
            raise ValueError("candidate manifest differs from recorded digest")
        manifest = json.loads(
            manifest_bytes,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite_constant,
        )
        manifest_fields = {
            "schema_version", "status", "input_lock_sha256", "repart_seed",
            "repart_seed_derivation", "debian_snapshot", "entries",
            "remaining_gates", "image_built", "private_mode_approved",
        }
        if (
            not isinstance(manifest, dict)
            or set(manifest) != manifest_fields
            or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["status"] != "staged-unbuilt-unapproved"
            or manifest["image_built"] is not False
            or manifest["private_mode_approved"] is not False
        ):
            raise ValueError("candidate manifest cannot authorize a built image or private mode")
        expected = manifest["entries"]
        if not isinstance(expected, dict) or not expected or not re.fullmatch(r"[0-9a-f]{64}", manifest["input_lock_sha256"]):
            raise ValueError("candidate manifest inventory or lock identity invalid")
        for relative in expected:
            if not isinstance(relative, str):
                raise ValueError("candidate manifest contains an invalid input path")
            path = Path(relative)
            if path.is_absolute() or relative != path.as_posix() or not path.parts or any(part in (".", "..") for part in path.parts) or relative == "candidate-manifest.json":
                raise ValueError("candidate manifest contains an invalid input path")
        staged_inventory(root_fd, expected)
        lock_fd = os.open("inputs.lock.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
        with os.fdopen(lock_fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("staged input lock differs from candidate manifest")
            lock_bytes = stream.read()
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or hashlib.sha256(lock_bytes).hexdigest() != manifest["input_lock_sha256"]:
                raise ValueError("staged input lock differs from candidate manifest")
        seed = repart_seed(lock_bytes)
        if manifest["repart_seed"] != str(seed) or manifest["repart_seed_derivation"] != {"algorithm": "UUIDv5", "namespace": str(uuid.NAMESPACE_URL), "name": REPART_SEED_NAME_PREFIX + manifest["input_lock_sha256"]}:
            raise ValueError("staged repart seed differs from candidate manifest")
    finally:
        os.close(root_fd)
    return {"status": "staged-inputs-match-pinned-manifest", "manifest_sha256": expected_manifest_sha256, "manifest_bytes": expected_manifest_bytes, "image_built": False, "private_mode_approved": False}

def repart_seed(lock_bytes):
    """Use the standard UUIDv5 name construction for reproducible GPT IDs."""
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    return uuid.uuid5(uuid.NAMESPACE_URL, REPART_SEED_NAME_PREFIX + lock_sha256)

def preflight():
    blockers = []
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        blockers.append("managed x86_64 Linux builder required")
    tools = {name: shutil.which(name) for name in ("mkosi", "systemd-repart", "ukify", "gpgv", "unshare", "mount", "umount", "sbsign", "veritysetup")}
    blockers.extend(f"missing build tool: {name}" for name, path in tools.items() if not path)
    if tools["unshare"]:
        result = subprocess.run([tools["unshare"], "--user", "--map-root-user", "true"], capture_output=True, check=False)
        if result.returncode:
            blockers.append("user namespace creation denied by builder isolation")
        # mkosi's APT sandbox deliberately allows network access. A future
        # build runner must isolate the *whole* build, not just build scripts.
        # A successful command alone is insufficient if the tool does not
        # actually move the process into a different network namespace.
        try:
            parent_net = Path("/proc/self/ns/net").readlink().as_posix()
        except OSError:
            blockers.append("builder network namespace identity unavailable")
        else:
            result = subprocess.run(
                [tools["unshare"], "--user", "--map-root-user", "--net", sys.executable,
                 "-c", 'import os; print(os.readlink("/proc/self/ns/net"))'],
                capture_output=True, text=True, check=False,
            )
            child_net = result.stdout.strip()
            if result.returncode or not re.fullmatch(r"net:\[[0-9]+\]", child_net) or child_net == parent_net:
                blockers.append("outer build network namespace isolation unavailable")
        if tools["mount"] and tools["umount"]:
            try:
                parent_user = Path("/proc/self/ns/user").readlink().as_posix()
                parent_mount = Path("/proc/self/ns/mnt").readlink().as_posix()
            except OSError:
                blockers.append("builder user/mount namespace identity unavailable")
            else:
                result = subprocess.run(
                    [tools["unshare"], "--user", "--map-root-user", "--mount",
                     "--fork", "--propagation", "private", sys.executable,
                     "-c", MOUNT_PROBE_SCRIPT, parent_user, parent_mount,
                     tools["mount"], tools["umount"]],
                    capture_output=True, text=True, check=False,
                )
                if result.returncode or result.stdout.strip() != "zrpc-isolated-tmpfs-ok":
                    blockers.append("isolated tmpfs mount/unmount unavailable")
    return {"schema_version": 1, "status": "blocked" if blockers else "capabilities-present-input-review-required", "architecture": platform.machine(), "tools": tools, "blockers": blockers, "image_built": False, "private_mode_approved": False}

def verify_disk_tool_archives(paths, snapshot):
    """Bind three inert extraction inputs to the same signed Debian index."""
    epoch, (index_hash, _), index_bytes = debian_snapshot.authenticated_index_bytes(
        paths["snapshot_inrelease"], paths["packages_index"],
        snapshot["inrelease_sha256"],
    )
    if epoch != snapshot["source_date_epoch"] or index_hash != snapshot["index_sha256"]:
        raise ValueError("public-disk tool index differs from signed guest snapshot")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    for role, entry in DISK_TOOL_PACKAGES.items():
        record = records.get((entry["name"], entry["version"], entry["architecture"]))
        if (record is None or any(str(entry[field]) != record.get(index_field)
                for field, index_field in (("filename", "Filename"), ("size", "Size"),
                                           ("sha256", "SHA256")))):
            raise ValueError("public-disk tool differs from signed Debian index: " + role)
        path = paths[role]
        if (path.is_symlink() or path.stat().st_size != entry["size"]
                or digest(path) != entry["sha256"]):
            raise ValueError("public-disk tool archive differs: " + role)

def disk_tool_member(archive_bytes, member_path, expected_size, expected_sha256):
    """Select one exact ELF member, never package scripts or other files."""
    payload = verify_builder_closure.deb_data_tar(archive_bytes)
    found = None
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as contents:
        for member in contents:
            if member.name in (member_path, "./" + member_path):
                if found is not None or not member.isfile() or member.size != expected_size:
                    raise ValueError("public-disk tool ELF is ambiguous or changed")
                with contents.extractfile(member) as stream:
                    found = stream.read(expected_size + 1)
    if (found is None or len(found) != expected_size
            or hashlib.sha256(found).hexdigest() != expected_sha256
            or found[:6] != b"\x7fELF\x02\x01" or found[18:20] != b"\x3e\x00"):
        raise ValueError("public-disk tool ELF differs from reviewed signed archive")
    return found

def mount_package_identity(manifest, packages):
    """Bind mount(8) to the signed, locked Debian package before chmod."""
    entries = [entry for entry in manifest
               if entry["name"] == "mount" and entry["architecture"] == "amd64"]
    if len(entries) != 1:
        raise ValueError("one locked amd64 mount package required")
    entry = entries[0]
    path = packages[(entry["name"], entry["version"], entry["architecture"])]
    archive_bytes = path.read_bytes()
    if len(archive_bytes) != entry["size"] or hashlib.sha256(archive_bytes).hexdigest() != entry["sha256"]:
        raise ValueError("signed mount package archive changed")
    payload = verify_builder_closure.deb_data_tar(archive_bytes)
    mount = None
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as contents:
        for member in contents:
            if member.name in ("usr/bin/mount", "./usr/bin/mount"):
                if (mount is not None or not member.isfile()
                        or (member.uid, member.gid) != (0, 0)
                        or member.size <= 0 or member.mode & 0o022):
                    raise ValueError("signed mount package ELF metadata differs")
                with contents.extractfile(member) as stream:
                    mount = stream.read(member.size + 1)
                if len(mount) != member.size:
                    raise ValueError("signed mount package ELF size differs")
    if (mount is None or mount[:6] != b"\x7fELF\x02\x01"
            or mount[18:20] != b"\x3e\x00"):
        raise ValueError("signed mount package has no x86_64 ELF")
    return len(mount), hashlib.sha256(mount).hexdigest()

def stage_disk_tool(rootfs, artifacts):
    """Copy only four reviewed ELF members into the authenticated root tree."""
    archives = {}
    for role, entry in DISK_TOOL_PACKAGES.items():
        archive = artifacts / role
        data = archive.read_bytes()
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("staged public-disk archive changed: " + role)
        archives[role] = data
    for relative, (role, member, size, sha256) in DISK_TOOL_ELFS.items():
        if member.startswith("lib"):
            value = verify_builder_closure.package_elf(archives[role], member)
            if (len(value) != size or hashlib.sha256(value).hexdigest() != sha256):
                raise ValueError("public-disk shared library differs from reviewed archive")
        else:
            value = disk_tool_member(archives[role], member, size, sha256)
        path = rootfs / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(value)
        path.chmod(0o555 if member == "usr/sbin/nvme" else 0o444)

def validate_lock(lock, source):
    if set(lock) != {"schema_version", "mkosi_source_commit", "source_date_epoch", "kernel_version", "snapshot", "artifacts", "runtime"} or lock["schema_version"] != 6 or lock["mkosi_source_commit"] != SOURCE_COMMIT:
        raise ValueError("unsupported or incomplete input lock")
    if type(lock["source_date_epoch"]) is not int or lock["source_date_epoch"] <= 0:
        raise ValueError("source date must derive from authenticated inputs")
    if lock["kernel_version"] != KERNEL_VERSION:
        raise ValueError("kernel ABI differs from reviewed Debian package")
    if not re.fullmatch(r"https://snapshot\.debian\.org/archive/debian/[0-9]{8}T[0-9]{6}Z/", lock["snapshot"]):
        raise ValueError("immutable Debian snapshot required")
    artifacts = lock["artifacts"]
    if set(artifacts) != ROLES:
        raise ValueError("exact complete input role set required")
    paths = {}
    for role, entry in artifacts.items():
        if set(entry) != {"path", "sha256"} or not re.fullmatch("[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("artifact identity missing")
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("input escapes the input directory")
        path = source / relative
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(source.resolve()) or digest(path) != entry["sha256"]:
            raise ValueError("input digest or path mismatch")
        if role in BINARIES or role == EARLY_INIT_ROLE:
            with path.open("rb") as stream:
                header = stream.read(64)
            if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
                raise ValueError("guest binaries must be x86_64 ELF")
        paths[role] = path
    manifest_bytes = paths["package_manifest"].read_bytes()
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("complete Debian package manifest required")
    names = set()
    for package in manifest:
        if set(package) != {"name", "version", "architecture", "filename", "size", "sha256", "path"} or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package["name"]) or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~-]*", package["version"]) or not re.fullmatch("[0-9a-f]{64}", package["sha256"]) or package["name"] in names:
            raise ValueError("invalid package identity")
        names.add(package["name"])
    kernel_packages = [package for package in manifest if package["name"].startswith("linux-image-")]
    if len(kernel_packages) != 1 or (kernel_packages[0]["name"], kernel_packages[0]["version"], kernel_packages[0]["architecture"]) != (KERNEL_PACKAGE, KERNEL_PACKAGE_VERSION, "amd64"):
        raise ValueError("exact signed Debian cloud kernel package required")
    # networkd/resolved, stable /dev/disk links, the direct UKI/verity path,
    # x-systemd.makefs for the public ext4 data disk, and mkosi's depmod step
    # need these binaries.
    if names & FORBIDDEN_PACKAGES or not ({"systemd-boot-efi", "systemd-resolved", "e2fsprogs", "libc6", "libjson-c5", "libssl3t64"} | INITRD_PACKAGES) <= names:
        raise ValueError("guest package surface does not match appliance policy")
    # Signed archive membership authenticates individual packages, but does
    # not authorize a caller to select a different executable/dependency set.
    # This source-reviewed candidate closure remains unbuilt and unapproved.
    if PACKAGE_CLOSURE_LOCK.is_symlink() or not PACKAGE_CLOSURE_LOCK.is_file():
        raise ValueError("package manifest differs from source-reviewed candidate closure")
    closure_bytes = PACKAGE_CLOSURE_LOCK.read_bytes()
    if hashlib.sha256(closure_bytes).hexdigest() != PACKAGE_CLOSURE_SHA256 or manifest_bytes != closure_bytes:
        raise ValueError("package manifest differs from source-reviewed candidate closure")
    runtime = lock["runtime"]
    if set(runtime) != {"listen_port", "max_connections", "max_quotes", "quote_spacing_ms", "node_startup_timeout_secs", "node_poll_interval_ms"} or any(type(value) is not int or value <= 0 for value in runtime.values()) or runtime["listen_port"] > 65535:
        raise ValueError("explicit measured runtime limits required")
    snapshot, packages = debian_snapshot.verify_snapshot(lock, paths, source, manifest)
    verify_disk_tool_archives(paths, snapshot)
    return paths, manifest, snapshot, packages

def stage(lock_path, source, destination):
    # Snapshot the exact lock used for validation and staged build inputs.
    # Rereading a mutable path after validation could change the repart seed or
    # the copied policy without changing the package closure used below.
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes, object_pairs_hook=unique_object)
    paths, package_manifest, snapshot, packages = validate_lock(lock, source)
    mount_size, mount_sha256 = mount_package_identity(package_manifest, packages)
    source_fd = open_stage_directory(PROFILE)
    try:
        source_entries = staged_inventory(source_fd)
    finally:
        os.close(source_fd)
    validate_boot_profile()
    copied_entries = {
        path: entry for path, entry in source_entries.items()
        if path not in {"input-identities.json", "package-closure.lock.json"}
    }
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    seed = repart_seed(lock_bytes)
    destination = destination.resolve()
    if not destination.is_relative_to(ROOT.resolve()) or destination.exists():
        raise ValueError("fresh output directory on the managed workspace volume required")
    destination.mkdir(parents=True, mode=0o700)
    shutil.copytree(PROFILE / "rootfs", destination / "rootfs")
    shutil.copytree(PROFILE / "repart", destination / "repart")
    shutil.copytree(PROFILE / "mkosi.images", destination / "mkosi.images")
    shutil.copy2(PROFILE / "mkosi.conf", destination / "mkosi.conf")
    copied_fd = open_stage_directory(destination)
    try:
        staged_inventory(copied_fd, copied_entries)
    finally:
        os.close(copied_fd)
    # Also parse the copied mkosi and repart recipe before generated settings
    # or binaries are added; the inventory comparison covers copied rootfs.
    validate_boot_profile(destination, staged_copy=True)
    # The public, all-locked shadow bytes are owner-readable in the stage so
    # its manifest and outer immutable inventory can hash them unprivileged.
    # The source-bound finalizer seals the installed copy to mode 000.
    (destination / "rootfs/etc/shadow").chmod(ACCOUNT_OUTPUTS["shadow"][3])
    shutil.copyfile(Path(__file__).with_name("seal-shadow.py"), destination / "seal-shadow.py")
    (destination / "seal-shadow.py").chmod(0o555)
    mount_template = Path(__file__).with_name("sanitize-mount.py").read_text()
    for marker, value in (("__STAGED_MOUNT_SHA256__", mount_sha256),
                          ("__STAGED_MOUNT_SIZE__", str(mount_size))):
        if mount_template.count(marker) != 1:
            raise ValueError("mount finalizer template differs")
        mount_template = mount_template.replace(marker, value)
    for script in (destination / "sanitize-mount.py",
                   destination / "mkosi.images/initrd/sanitize-mount.py"):
        script.write_text(mount_template)
        script.chmod(0o555)
    root_audit_template = Path(__file__).with_name("audit-rootfs.py").read_text()
    marker = "__STAGED_MOUNT_SHA256__"
    if root_audit_template.count(marker) != 1:
        raise ValueError("rootfs mount audit template differs")
    root_audit = destination / "audit-rootfs.py"
    root_audit.write_text(root_audit_template.replace(marker, mount_sha256))
    root_audit.chmod(0o555)
    artifacts = destination / "artifacts"
    artifacts.mkdir()
    for role, path in paths.items():
        target = artifacts / role
        shutil.copyfile(path, target)
        if digest(target) != lock["artifacts"][role]["sha256"]:
            raise ValueError("artifact changed during staging")
    initrd_tree = destination / "mkosi.images/initrd/rootfs"
    initrd_tree.mkdir()
    init_path = initrd_tree / "init"
    shutil.copyfile(artifacts / EARLY_INIT_ROLE, init_path)
    init_path.chmod(0o555)
    if digest(init_path) != lock["artifacts"][EARLY_INIT_ROLE]["sha256"]:
        raise ValueError("early init changed during staging")
    audit_template = Path(__file__).with_name("audit-initrd.py").read_text()
    marker = "__STAGED_INIT_SHA256__"
    if audit_template.count(marker) != 1:
        raise ValueError("early init audit template differs")
    audit_template = audit_template.replace(marker, lock["artifacts"][EARLY_INIT_ROLE]["sha256"])
    marker = "__STAGED_MOUNT_SHA256__"
    if audit_template.count(marker) != 1:
        raise ValueError("initrd mount audit template differs")
    initrd_audit = destination / "mkosi.images/initrd/audit-initrd.py"
    initrd_audit.write_text(audit_template.replace(marker, mount_sha256))
    initrd_audit.chmod(0o555)
    package_directory = destination / "packages"
    package_directory.mkdir()
    # mkosi otherwise reuses the invoking user's shared APT cache and lists.
    # This candidate-specific directory is still not an offline-build proof:
    # the eventual runner must verify an outer network namespace before build.
    (destination / "package-cache").mkdir()
    for package in package_manifest:
        source_archive = packages[(package["name"], package["version"], package["architecture"])]
        target = package_directory / (package["sha256"] + ".deb")
        shutil.copyfile(source_archive, target)
        if digest(target) != package["sha256"]:
            raise ValueError("Debian package changed during staging")
    rootfs = destination / "rootfs"
    binaries = rootfs / "usr/lib/zrpc"
    binaries.mkdir(parents=True)
    for role, name in BINARIES.items():
        shutil.copyfile(artifacts / role, binaries / name)
        (binaries / name).chmod(0o555)
    stage_disk_tool(rootfs, artifacts)
    (rootfs / "etc/zrpc").mkdir(parents=True)
    # Zebra otherwise enables a HOME/XDG peer cache outside the public node tree.
    (rootfs / "etc/zrpc/zebra.toml").write_text('[network]\nnetwork = "Testnet"\nlisten_addr = "127.0.0.1:18233"\ncache_dir = false\n[state]\ncache_dir = "/var/lib/zebra"\n[rpc]\nlisten_addr = "127.0.0.1:18232"\ncookie_dir = "/run/zrpc-node"\nenable_cookie_auth = true\n[tracing]\nfilter = "off"\n')
    unit_dir = rootfs / "usr/lib/systemd/system"
    runtime = lock["runtime"]
    with (unit_dir / "zrpc-wrapper.service").open("a") as stream:
        stream.write(f'ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec wrapper --platform gcp-tdx --listen 0.0.0.0:{runtime["listen_port"]} --node 127.0.0.1:18232 --max-connections {runtime["max_connections"]} --max-quotes {runtime["max_quotes"]} --quote-spacing-ms {runtime["quote_spacing_ms"]}\n')
    with (unit_dir / "zrpc-cookie.service").open("a") as stream:
        stream.write(f'ExecStart=/usr/lib/zrpc/zrpc-gcp-guard --exec cookie --startup-timeout-secs {runtime["node_startup_timeout_secs"]} --poll-interval-ms {runtime["node_poll_interval_ms"]}\nTimeoutStartSec={runtime["node_startup_timeout_secs"]}s\n')
    install_boot_overrides(rootfs)
    with (destination / "mkosi.conf").open("a") as stream:
        pinned_packages = ",".join(sorted(f'{package["name"]}={package["version"]}' for package in package_manifest))
        stream.write(f'\n[Distribution]\nMirror={lock["snapshot"]}\n[Content]\nPackages={pinned_packages}\nPackageDirectories=packages\nInitrds=output/initrd.cpio.zst\nFinalizeScripts=seal-shadow.py,sanitize-mount.py,audit-rootfs.py\nSourceDateEpoch={lock["source_date_epoch"]}\n[Validation]\nSecureBootCertificate=artifacts/secure_boot_certificate\nSecureBootKey={EXTERNAL_SECURE_BOOT_KEY}\n[Output]\nOutputDirectory=output\nSeed={seed}\n[Build]\nBuildSources=\nWorkspaceDirectory=work\nPackageCacheDirectory=package-cache\nEnvironment=SYSTEMD_REPART_MKFS_OPTIONS_EXT4=-Ehash_seed={seed}\n')
    with (destination / "mkosi.images/initrd/mkosi.conf").open("a") as stream:
        versions = {package["name"]: package["version"] for package in package_manifest}
        initrd_packages = ",".join(f"{name}={versions[name]}" for name in sorted(INITRD_PACKAGES))
        stream.write(f"\nPackages={initrd_packages}\nExtraTrees=rootfs\nFinalizeScripts=sanitize-mount.py,audit-initrd.py\n")
    (destination / "inputs.lock.json").write_bytes(lock_bytes)
    root_fd = open_stage_directory(destination)
    try:
        entries = staged_inventory(root_fd)
    finally:
        os.close(root_fd)
    report = {"schema_version": 1, "status": "staged-unbuilt-unapproved", "input_lock_sha256": lock_sha256, "repart_seed": str(seed), "repart_seed_derivation": {"algorithm": "UUIDv5", "namespace": str(uuid.NAMESPACE_URL), "name": REPART_SEED_NAME_PREFIX + lock_sha256}, "debian_snapshot": snapshot, "entries": entries, "remaining_gates": ["verified outer no-network builder namespace and complete installed package closure comparison after build", "operator-owned signing key supplied at the builder-only memory-backed reference and checked against the staged certificate", "verify installed kernel and appended dm-verity module closure came from exact Debian cloud package", "exact mkosi and tools-tree verification", "Zebra release age and provenance review", "inspect actual appended initrd /init and x86_64 early-init runtime closure", "test verity root boot with rescue paths disabled", "guest rootfs and initramfs surface audit", "prove exact signed UKI boot policy excludes unreviewed addons and profiles", "boot companion exclusion audit", "extract final UKI .cmdline and compare exact fixed flags plus repart roothash", "UKI signing and verity reconstruction", "reproducible image build", "synthetic boot and namespace tests", "real TDX acceptance"], "image_built": False, "private_mode_approved": False}
    manifest_path = destination / "candidate-manifest.json"
    manifest_path.write_text(json.dumps(report, indent=2) + "\n")
    # Return these for recording outside the mutable stage. They cannot be
    # included in the manifest itself without a self-reference.
    report["manifest_sha256"] = digest(manifest_path)
    report["manifest_bytes"] = manifest_path.stat().st_size
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    inputs = sub.add_parser("inspect-inputs")
    staging = sub.add_parser("stage")
    verification = sub.add_parser("verify-stage")
    for command in (inputs, staging):
        command.add_argument("--lock", type=Path, required=True)
        command.add_argument("--inputs", type=Path, required=True)
    staging.add_argument("--output", type=Path, required=True)
    verification.add_argument("--output", type=Path, required=True)
    verification.add_argument("--expected-manifest-sha256", required=True)
    verification.add_argument("--expected-manifest-bytes", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "preflight":
            report = preflight()
        elif args.command == "inspect-inputs":
            _, _, snapshot, _ = validate_lock(read_json(args.lock), args.inputs)
            report = {"status": "offline-debian-signature-and-hashes-matched-toolchain-review-pending", "debian_snapshot": snapshot, "image_built": False, "private_mode_approved": False}
        elif args.command == "verify-stage":
            report = verify_stage(args.output, args.expected_manifest_sha256, args.expected_manifest_bytes)
        else:
            report = stage(args.lock, args.inputs, args.output)
        print(json.dumps(report, indent=2))
        return 1 if report["status"] == "blocked" else 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, configparser.Error) as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "image_built": False, "private_mode_approved": False}))
        return 1

if __name__ == "__main__":
    sys.exit(main())
