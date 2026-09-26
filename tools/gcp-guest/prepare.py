#!/usr/bin/env python3
"""Offline candidate staging, never image publication or release approval.

Run inside the managed Linux container. No package installer, cloud client,
credential discovery, image builder, signing operation or scheduler is invoked.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

import debian_snapshot

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "deploy/gcp/guest"
SOURCE_COMMIT = "54c625c380ef5500f17460981a3c67b109b6a847"
BINARIES = {"wrapper": "zrpc-node-wrapper", "broker": "zrpc-gcp-quote-broker", "guard": "zrpc-gcp-guard", "cookie": "zrpc-gcp-cookie", "zebra": "zebrad"}
ROLES = set(BINARIES) | {"base_tree", "kernel", "initrd", "secure_boot_certificate", "package_manifest", "snapshot_inrelease", "packages_index", "boot_policy"}
MASKS = ("ssh.service", "sshd.service", "ssh.socket", "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service", "container-getty@.service", "debug-shell.service", "rescue.service", "rescue.target", "emergency.service", "emergency.target", "systemd-hibernate.service", "systemd-suspend.service", "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service", "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service", "systemd-confext.service", "systemd-sysupdate.service", "systemd-sysupdate.timer", "systemd-firstboot.service", "systemd-user-sessions.service", "cloud-init.service", "cloud-final.service", "google-guest-agent.service", "google-osconfig-agent.service", "apt-daily.timer", "apt-daily-upgrade.timer")
FORBIDDEN_PACKAGES = {"openssh-server", "cloud-init", "google-guest-agent", "google-osconfig-agent", "docker.io", "containerd", "systemd-container", "sudo", "polkitd"}

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
    return {"schema_version": 1, "status": "blocked" if blockers else "capabilities-present-input-review-required", "architecture": platform.machine(), "tools": tools, "blockers": blockers, "image_built": False, "private_mode_approved": False}

def validate_lock(lock, source):
    if set(lock) != {"schema_version", "mkosi_source_commit", "source_date_epoch", "kernel_version", "snapshot", "artifacts", "runtime"} or lock["schema_version"] != 2 or lock["mkosi_source_commit"] != SOURCE_COMMIT:
        raise ValueError("unsupported or incomplete input lock")
    if type(lock["source_date_epoch"]) is not int or lock["source_date_epoch"] <= 0:
        raise ValueError("source date must derive from authenticated inputs")
    if not re.fullmatch(r"[A-Za-z0-9.+_-]+", lock["kernel_version"]):
        raise ValueError("unsafe kernel version")
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
    manifest = read_json(paths["package_manifest"])
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("complete Debian package manifest required")
    names = set()
    for package in manifest:
        if set(package) != {"name", "version", "architecture", "filename", "size", "sha256", "path"} or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package["name"]) or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~-]*", package["version"]) or not re.fullmatch("[0-9a-f]{64}", package["sha256"]) or package["name"] in names:
            raise ValueError("invalid package identity")
        names.add(package["name"])
    if names & FORBIDDEN_PACKAGES or not {"systemd", "systemd-boot-efi", "systemd-cryptsetup"} <= names:
        raise ValueError("guest package surface does not match appliance policy")
    runtime = lock["runtime"]
    if set(runtime) != {"listen_port", "max_connections", "max_quotes", "quote_spacing_ms", "node_startup_timeout_secs", "node_poll_interval_ms"} or any(type(value) is not int or value <= 0 for value in runtime.values()) or runtime["listen_port"] > 65535:
        raise ValueError("explicit measured runtime limits required")
    snapshot, packages = debian_snapshot.verify_snapshot(lock, paths, source, manifest)
    return paths, manifest, snapshot, packages

def stage(lock_path, source, destination):
    lock = read_json(lock_path)
    paths, package_manifest, snapshot, packages = validate_lock(lock, source)
    destination = destination.resolve()
    if not destination.is_relative_to(ROOT.resolve()) or destination.exists():
        raise ValueError("fresh output directory on the managed workspace volume required")
    destination.mkdir(parents=True, mode=0o700)
    shutil.copytree(PROFILE / "rootfs", destination / "rootfs")
    shutil.copytree(PROFILE / "repart", destination / "repart")
    shutil.copy2(PROFILE / "mkosi.conf", destination / "mkosi.conf")
    shutil.copyfile(Path(__file__).with_name("audit-rootfs.py"), destination / "audit-rootfs.py")
    (destination / "audit-rootfs.py").chmod(0o555)
    artifacts = destination / "artifacts"
    artifacts.mkdir()
    for role, path in paths.items():
        target = artifacts / (role + (".tar" if role == "base_tree" else ""))
        shutil.copyfile(path, target)
        if digest(target) != lock["artifacts"][role]["sha256"]:
            raise ValueError("artifact changed during staging")
    package_directory = destination / "packages"
    package_directory.mkdir()
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
    modules = rootfs / "usr/lib/modules" / lock["kernel_version"]
    modules.mkdir(parents=True)
    shutil.copyfile(artifacts / "kernel", modules / "vmlinuz")
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
        stream.write(f'\n[Distribution]\nMirror={lock["snapshot"]}\n[Content]\nPackages={pinned_packages}\nPackageDirectories=packages\nBaseTrees=artifacts/base_tree.tar\nInitrds=artifacts/initrd\nFinalizeScripts=audit-rootfs.py\nSourceDateEpoch={lock["source_date_epoch"]}\n[Validation]\nSecureBootCertificate=artifacts/secure_boot_certificate\n[Output]\nOutputDirectory=output\n[Build]\nWorkspaceDirectory=work\n')
    shutil.copyfile(lock_path, destination / "inputs.lock.json")
    entries = {}
    for path in sorted(destination.rglob("*")):
        if path.is_symlink():
            entry = {"type": "symlink", "target": str(path.readlink())}
        elif path.is_file():
            entry = {"type": "file", "sha256": digest(path), "mode": path.stat().st_mode & 0o777}
        else:
            entry = {"type": "directory", "mode": path.stat().st_mode & 0o777}
        entries[str(path.relative_to(destination))] = entry
    report = {"schema_version": 1, "status": "staged-unbuilt-unapproved", "input_lock_sha256": digest(destination / "inputs.lock.json"), "debian_snapshot": snapshot, "entries": entries, "remaining_gates": ["complete installed package closure comparison after build", "exact mkosi and tools-tree verification", "Zebra release age and provenance review", "guest rootfs and initramfs surface audit", "boot companion exclusion audit", "UKI signing and verity reconstruction", "reproducible image build", "synthetic boot and namespace tests", "real TDX acceptance"], "image_built": False, "private_mode_approved": False}
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
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "image_built": False, "private_mode_approved": False}))
        return 1

if __name__ == "__main__":
    sys.exit(main())
