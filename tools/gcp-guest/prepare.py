#!/usr/bin/env python3
"""Offline candidate staging, never image publication or release approval.

Run inside the managed Linux container. No package installer, cloud client,
credential discovery, image builder, signing operation or scheduler is invoked.
"""
import argparse
import configparser
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import uuid

import debian_snapshot

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "deploy/gcp/guest"
PACKAGE_CLOSURE_LOCK = PROFILE / "package-closure.lock.json"
PACKAGE_CLOSURE_SHA256 = "a6994a27c6bcfbed584751ed6eb10cb393c21808c58b628b3ff1584a570b0ca5"
SOURCE_COMMIT = "54c625c380ef5500f17460981a3c67b109b6a847"
KERNEL_VERSION = "6.12.107+deb13-cloud-amd64"
KERNEL_PACKAGE = f"linux-image-{KERNEL_VERSION}"
KERNEL_PACKAGE_VERSION = "6.12.107-1"
BINARIES = {"wrapper": "zrpc-node-wrapper", "broker": "zrpc-gcp-quote-broker", "guard": "zrpc-gcp-guard", "cookie": "zrpc-gcp-cookie", "zebra": "zebrad"}
ROLES = set(BINARIES) | {"secure_boot_certificate", "package_manifest", "snapshot_inrelease", "packages_index", "boot_policy"}
INITRD_PACKAGES = {"systemd", "udev", "systemd-cryptsetup", "dmsetup", "kmod"}
INITRD_REMOVE_FILES = (
    "/usr/lib/systemd/system/rescue.service",
    "/usr/lib/systemd/system/rescue.target",
    "/usr/lib/systemd/system/emergency.service",
    "/usr/lib/systemd/system/emergency.target",
    "/usr/lib/systemd/system/debug-shell.service",
    "/usr/lib/systemd/system/getty.target",
    "/usr/lib/systemd/system/getty@.service",
    "/usr/lib/systemd/system/serial-getty@.service",
    "/usr/lib/systemd/system/console-getty.service",
    "/usr/lib/systemd/system/container-getty@.service",
    "/usr/lib/systemd/system/multi-user.target.wants/getty.target",
    "/usr/lib/systemd/system/runlevel1.target",
    "/usr/lib/systemd/systemd-sulogin-shell",
    "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/sh",
    "/usr/sbin/sulogin", "/usr/bin/login", "/usr/bin/su",
)
REPART_SEED_NAME_PREFIX = "https://github.com/tamnys/ZECret-service/gcp-guest-seed/v1/"
MASKS = ("ssh.service", "sshd.service", "ssh.socket", "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service", "container-getty@.service", "debug-shell.service", "rescue.service", "rescue.target", "emergency.service", "emergency.target", "systemd-hibernate.service", "systemd-suspend.service", "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service", "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service", "systemd-confext.service", "systemd-sysupdate.service", "systemd-sysupdate.timer", "systemd-firstboot.service", "systemd-sysusers.service", "systemd-user-sessions.service", "cloud-init.service", "cloud-final.service", "google-guest-agent.service", "google-osconfig-agent.service", "apt-daily.timer", "apt-daily-upgrade.timer")
FORBIDDEN_PACKAGES = {"openssh-server", "cloud-init", "google-guest-agent", "google-osconfig-agent", "docker.io", "containerd", "systemd-container", "sudo", "polkitd"}

def validate_boot_profile(profile=PROFILE):
    """Reject source drift that would omit the direct UKI or unbind the root."""
    # mkosi discovers settings and executable hooks by filename. The staged
    # directory is created fresh from these reviewed source entries only.
    if {path.name for path in profile.iterdir()} != {"input-identities.json", "package-closure.lock.json", "mkosi.conf", "mkosi.images", "repart", "rootfs"} or any(path.is_symlink() for path in profile.iterdir()):
        raise ValueError("unexpected mkosi source override or redirected input")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with (profile / "mkosi.conf").open() as stream:
        parser.read_file(stream)
    expected_settings = {
        "Distribution": {"Distribution": "debian", "Release": "trixie", "Architecture": "x86-64", "RepositoryKeyCheck": "yes", "RepositoryKeyFetch": "no"},
        "Output": {"Format": "disk", "Output": "zrpc-gcp", "ManifestFormat": "json", "RepartDirectories": "repart"},
        "Config": {"Dependencies": "initrd"},
        "Content": {"Bootable": "yes", "Bootloader": "uki", "BiosBootloader": "none", "ShimBootloader": "none", "UnifiedKernelImages": "yes", "KernelModulesInitrd": "yes", "KernelModulesInitrdInclude": "^drivers/md/dm-verity[.]ko[.]xz$", "KernelModulesInitrdExclude": ".*", "Autologin": "no", "Ssh": "no", "KernelCommandLine": "ro systemd.gpt_auto=0 rd.systemd.gpt_auto=0 rd.modules_load=dm-verity systemd.unit=zrpc.target systemd.crash_shell=0 systemd.crash_action=poweroff systemd.dump_core=0 systemd.mask=debug-shell.service systemd.mask=systemd-hibernate.service systemd.mask=systemd-hybrid-sleep.service systemd.mask=systemd-suspend-then-hibernate.service panic=-1 oops=panic module.sig_enforce=1 lockdown=confidentiality", "ExtraTrees": "rootfs"},
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
    repart = profile / "repart"
    expected = {"10-root.conf", "20-root-verity.conf", "30-esp.conf"}
    if {path.name for path in repart.iterdir()} != expected:
        raise ValueError("unexpected repart definition")
    definitions = {
        "10-root.conf": ("[Partition]", "Type=root-x86-64", "Format=ext4", "CopyFiles=/", "Minimize=best", "ReadOnly=yes", "Verity=data", "VerityMatchKey=root"),
        "20-root-verity.conf": ("[Partition]", "Type=root-x86-64-verity", "Verity=hash", "VerityMatchKey=root"),
        "30-esp.conf": ("[Partition]", "Type=esp", "Format=vfat", "CopyFiles=/efi:/"),
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

def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)

def repart_seed(lock_bytes):
    """Use the standard UUIDv5 name construction for reproducible GPT IDs."""
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    return uuid.uuid5(uuid.NAMESPACE_URL, REPART_SEED_NAME_PREFIX + lock_sha256)

def preflight():
    blockers = []
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        blockers.append("managed x86_64 Linux builder required")
    tools = {name: shutil.which(name) for name in ("mkosi", "systemd-repart", "ukify", "gpgv", "unshare", "sbsign", "veritysetup")}
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
    return {"schema_version": 1, "status": "blocked" if blockers else "capabilities-present-input-review-required", "architecture": platform.machine(), "tools": tools, "blockers": blockers, "image_built": False, "private_mode_approved": False}

def validate_lock(lock, source):
    if set(lock) != {"schema_version", "mkosi_source_commit", "source_date_epoch", "kernel_version", "snapshot", "artifacts", "runtime"} or lock["schema_version"] != 5 or lock["mkosi_source_commit"] != SOURCE_COMMIT:
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
        if role in BINARIES:
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
    if names & FORBIDDEN_PACKAGES or not ({"systemd-boot-efi", "systemd-resolved", "e2fsprogs"} | INITRD_PACKAGES) <= names:
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
    return paths, manifest, snapshot, packages

def stage(lock_path, source, destination):
    # Snapshot the exact lock used for validation and staged build inputs.
    # Rereading a mutable path after validation could change the repart seed or
    # the copied policy without changing the package closure used below.
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes, object_pairs_hook=unique_object)
    paths, package_manifest, snapshot, packages = validate_lock(lock, source)
    validate_boot_profile()
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
    shutil.copyfile(Path(__file__).with_name("audit-rootfs.py"), destination / "audit-rootfs.py")
    (destination / "audit-rootfs.py").chmod(0o555)
    initrd_audit = destination / "mkosi.images/initrd/audit-initrd.py"
    shutil.copyfile(Path(__file__).with_name("audit-initrd.py"), initrd_audit)
    initrd_audit.chmod(0o555)
    artifacts = destination / "artifacts"
    artifacts.mkdir()
    for role, path in paths.items():
        target = artifacts / role
        shutil.copyfile(path, target)
        if digest(target) != lock["artifacts"][role]["sha256"]:
            raise ValueError("artifact changed during staging")
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
    (rootfs / "etc/zrpc").mkdir(parents=True)
    (rootfs / "etc/zrpc/zebra.toml").write_text('[network]\nnetwork = "Testnet"\nlisten_addr = "127.0.0.1:18233"\n[state]\ncache_dir = "/var/lib/zebra"\n[rpc]\nlisten_addr = "127.0.0.1:18232"\ncookie_dir = "/run/zrpc-node"\nenable_cookie_auth = true\n[tracing]\nfilter = "off"\n')
    unit_dir = rootfs / "usr/lib/systemd/system"
    runtime = lock["runtime"]
    with (unit_dir / "zrpc-wrapper.service").open("a") as stream:
        stream.write(f'ExecStart=/usr/lib/zrpc/zrpc-node-wrapper --platform gcp-tdx --listen 0.0.0.0:{runtime["listen_port"]} --node 127.0.0.1:18232 --max-connections {runtime["max_connections"]} --max-quotes {runtime["max_quotes"]} --quote-spacing-ms {runtime["quote_spacing_ms"]}\n')
    with (unit_dir / "zrpc-cookie.service").open("a") as stream:
        stream.write(f'ExecStart=/usr/lib/zrpc/zrpc-gcp-cookie --startup-timeout-secs {runtime["node_startup_timeout_secs"]} --poll-interval-ms {runtime["node_poll_interval_ms"]}\nTimeoutStartSec={runtime["node_startup_timeout_secs"]}s\n')
    masks = rootfs / "etc/systemd/system"
    masks.mkdir(parents=True, exist_ok=True)
    for name in MASKS:
        (masks / name).symlink_to("/dev/null")
    (masks / "default.target").symlink_to("/usr/lib/systemd/system/zrpc.target")
    (masks / "multi-user.target.wants").mkdir()
    for name in ("systemd-networkd.service", "systemd-resolved.service"):
        (masks / "multi-user.target.wants" / name).symlink_to("/usr/lib/systemd/system/" + name)
    (rootfs / "etc/resolv.conf").symlink_to("/run/systemd/resolve/stub-resolv.conf")
    with (destination / "mkosi.conf").open("a") as stream:
        pinned_packages = ",".join(sorted(f'{package["name"]}={package["version"]}' for package in package_manifest))
        stream.write(f'\n[Distribution]\nMirror={lock["snapshot"]}\n[Content]\nPackages={pinned_packages}\nPackageDirectories=packages\nInitrds=output/initrd.cpio.zst\nFinalizeScripts=audit-rootfs.py\nSourceDateEpoch={lock["source_date_epoch"]}\n[Validation]\nSecureBootCertificate=artifacts/secure_boot_certificate\n[Output]\nOutputDirectory=output\nSeed={seed}\n[Build]\nWorkspaceDirectory=work\nPackageCacheDirectory=package-cache\n')
    with (destination / "mkosi.images/initrd/mkosi.conf").open("a") as stream:
        versions = {package["name"]: package["version"] for package in package_manifest}
        initrd_packages = ",".join(f"{name}={versions[name]}" for name in sorted(INITRD_PACKAGES))
        stream.write(f"\nPackages={initrd_packages}\nFinalizeScripts=audit-initrd.py\n")
    (destination / "inputs.lock.json").write_bytes(lock_bytes)
    entries = {}
    for path in sorted(destination.rglob("*")):
        if path.is_symlink():
            entry = {"type": "symlink", "target": str(path.readlink())}
        elif path.is_file():
            entry = {"type": "file", "sha256": digest(path), "mode": path.stat().st_mode & 0o777}
        else:
            entry = {"type": "directory", "mode": path.stat().st_mode & 0o777}
        entries[str(path.relative_to(destination))] = entry
    report = {"schema_version": 1, "status": "staged-unbuilt-unapproved", "input_lock_sha256": lock_sha256, "repart_seed": str(seed), "repart_seed_derivation": {"algorithm": "UUIDv5", "namespace": str(uuid.NAMESPACE_URL), "name": REPART_SEED_NAME_PREFIX + lock_sha256}, "debian_snapshot": snapshot, "entries": entries, "remaining_gates": ["verified outer no-network builder namespace and complete installed package closure comparison after build", "verify installed kernel and appended dm-verity module closure came from exact Debian cloud package", "exact mkosi and tools-tree verification", "Zebra release age and provenance review", "inspect actual initrd contents and test verity root boot with rescue paths disabled", "guest rootfs and initramfs surface audit", "boot companion exclusion audit", "extract final UKI .cmdline and compare exact fixed flags plus repart roothash", "UKI signing and verity reconstruction", "reproducible image build", "synthetic boot and namespace tests", "real TDX acceptance"], "image_built": False, "private_mode_approved": False}
    (destination / "candidate-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    inputs = sub.add_parser("inspect-inputs")
    staging = sub.add_parser("stage")
    for command in (inputs, staging):
        command.add_argument("--lock", type=Path, required=True)
        command.add_argument("--inputs", type=Path, required=True)
    staging.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "preflight":
            report = preflight()
        elif args.command == "inspect-inputs":
            _, _, snapshot, _ = validate_lock(read_json(args.lock), args.inputs)
            report = {"status": "offline-debian-signature-and-hashes-matched-toolchain-review-pending", "debian_snapshot": snapshot, "image_built": False, "private_mode_approved": False}
        else:
            report = stage(args.lock, args.inputs, args.output)
        print(json.dumps(report, indent=2))
        return 1 if report["status"] == "blocked" else 0
    except (OSError, ValueError, KeyError, TypeError, configparser.Error) as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "image_built": False, "private_mode_approved": False}))
        return 1

if __name__ == "__main__":
    sys.exit(main())
