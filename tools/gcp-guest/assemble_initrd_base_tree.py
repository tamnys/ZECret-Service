#!/usr/bin/env python3
"""Assemble a narrowly selected, source-bound initrd BaseTrees input archive.

Only data members of the signed Debian guest closure are read. This candidate
does not include /init, generated initrd files, a complete runtime/unit graph,
or a bootable image. It never runs package control scripts or grants approval.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import stat
import sys
import tarfile

import assemble_guest_base_tree as root_tree
import fetch_guest_closure as guest
import preflight_guest_base_tree as preflight
import stage_builder_toolchain as builder


STATUS = "diagnostic-signed-initrd-basetree-input-unbuilt"
ARCHIVE = "guest-initrd-inputs.tar"
MANIFEST = "guest-initrd-inputs-manifest.json"

# Reviewed with readelf against the exact cached Debian archive bytes. This is
# the DT_NEEDED/interpreter closure for the named entrypoints, not proof of
# dlopen, unit activation, udev rules, or the separately pinned Rust /init.
ELF_ENTRYPOINTS = (
    "usr/bin/kmod",
    "usr/bin/systemctl",
    "usr/bin/udevadm",
    "usr/lib/systemd/system-generators/systemd-fstab-generator",
    "usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "usr/lib/systemd/systemd",
    "usr/lib/systemd/systemd-modules-load",
    "usr/lib/systemd/systemd-veritysetup",
    "usr/sbin/dmsetup",
)
ELF_RUNTIME = (
    "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "usr/lib/x86_64-linux-gnu/libacl.so.1",
    "usr/lib/x86_64-linux-gnu/libacl.so.1.1.2302",
    "usr/lib/x86_64-linux-gnu/libapparmor.so.1",
    "usr/lib/x86_64-linux-gnu/libapparmor.so.1.24.2",
    "usr/lib/x86_64-linux-gnu/libaudit.so.1",
    "usr/lib/x86_64-linux-gnu/libaudit.so.1.0.0",
    "usr/lib/x86_64-linux-gnu/libblkid.so.1",
    "usr/lib/x86_64-linux-gnu/libblkid.so.1.1.0",
    "usr/lib/x86_64-linux-gnu/libc.so.6",
    "usr/lib/x86_64-linux-gnu/libcap-ng.so.0",
    "usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0",
    "usr/lib/x86_64-linux-gnu/libcap.so.2",
    "usr/lib/x86_64-linux-gnu/libcap.so.2.75",
    "usr/lib/x86_64-linux-gnu/libcrypt.so.1",
    "usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0",
    "usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    "usr/lib/x86_64-linux-gnu/libcryptsetup.so.12",
    "usr/lib/x86_64-linux-gnu/libcryptsetup.so.12.10.0",
    "usr/lib/x86_64-linux-gnu/libdevmapper.so.1.02.1",
    "usr/lib/x86_64-linux-gnu/libjson-c.so.5",
    "usr/lib/x86_64-linux-gnu/libjson-c.so.5.4.0",
    "usr/lib/x86_64-linux-gnu/libm.so.6",
    "usr/lib/x86_64-linux-gnu/libmount.so.1",
    "usr/lib/x86_64-linux-gnu/libmount.so.1.1.0",
    "usr/lib/x86_64-linux-gnu/libpam.so.0",
    "usr/lib/x86_64-linux-gnu/libpam.so.0.85.1",
    "usr/lib/x86_64-linux-gnu/libpcre2-8.so.0",
    "usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0",
    "usr/lib/x86_64-linux-gnu/libseccomp.so.2",
    "usr/lib/x86_64-linux-gnu/libseccomp.so.2.6.0",
    "usr/lib/x86_64-linux-gnu/libselinux.so.1",
    "usr/lib/x86_64-linux-gnu/libudev.so.1",
    "usr/lib/x86_64-linux-gnu/libudev.so.1.7.10",
    "usr/lib/x86_64-linux-gnu/libuuid.so.1",
    "usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0",
    "usr/lib/x86_64-linux-gnu/libz.so.1",
    "usr/lib/x86_64-linux-gnu/libz.so.1.3.1",
    "usr/lib/x86_64-linux-gnu/libzstd.so.1",
    "usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7",
    "usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-257.so",
    "usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-257.so",
)
BOOT_FILES = (
    "etc/os-release",
    "lib64",
    "usr/lib/os-release",
    # The verity generator names GPT partitions through /dev/disk/by-partuuid.
    # This signed udev rule creates those links; runtime behavior still needs
    # a boot test and is not established by selecting its package bytes.
    "usr/lib/udev/rules.d/60-persistent-storage.rules",
    "usr/lib64/ld-linux-x86-64.so.2",
    "usr/lib/systemd/systemd-sysroot-fstab-check",
    "usr/lib/systemd/systemd-udevd",
)
UNITS = tuple("usr/lib/systemd/system/" + name for name in (
    "basic.target",
    "initrd-cleanup.service",
    "initrd-fs.target",
    "initrd-parse-etc.service",
    "initrd-root-device.target",
    "initrd-root-fs.target",
    "initrd-switch-root.service",
    "initrd-switch-root.target",
    "initrd-udevadm-cleanup-db.service",
    "initrd-usr-fs.target",
    "initrd.target",
    "local-fs-pre.target",
    "local-fs.target",
    "paths.target",
    "slices.target",
    "sockets.target",
    "swap.target",
    "sysinit.target",
    "systemd-modules-load.service",
    "systemd-udev-trigger.service",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    "systemd-udevd.service",
    "timers.target",
    "veritysetup-pre.target",
    "veritysetup.target",
))
MOUNT_DIRECTORIES = ("dev", "proc", "run", "sys", "tmp", "etc/systemd/system")
SELECTED_FILES = tuple(sorted(set(ELF_ENTRYPOINTS + ELF_RUNTIME + BOOT_FILES + UNITS)))


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def link_target(path, target):
    if target.startswith("/"):
        raise ValueError(f"absolute initrd link is unsupported: {path}")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if resolved in {"", ".", ".."} or resolved.startswith("../"):
        raise ValueError(f"initrd link leaves archive root: {path}")
    return resolved


def selected_source_plan(authenticated, *, selected_files=SELECTED_FILES,
                         mount_directories=MOUNT_DIRECTORIES,
                         elf_entrypoints=ELF_ENTRYPOINTS):
    payloads, source_entries = root_tree.source_plan(authenticated)
    source = {row["path"]: row for row in source_entries}
    selected = {".", *selected_files, *mount_directories}
    for path in tuple(selected):
        if path not in source:
            raise ValueError(f"required initrd package data absent: {path}")
        for index, _ in enumerate(path.split("/")[:-1], start=1):
            selected.add("/".join(path.split("/")[:index]))
    for path in selected:
        row = source.get(path)
        if row is None or (path not in selected_files and row["kind"] != "directory"):
            raise ValueError(f"initrd parent is not a package directory: {path}")
        if row["kind"] in {"symlink", "hardlink"}:
            target = (link_target(path, row["target"]) if row["kind"] == "symlink"
                      else row["target"])
            if target not in selected:
                raise ValueError(f"initrd selected link target absent: {path}")
        if row["kind"] == "file" and path in selected_files and row["output_mode"] & 0o111:
            if path not in {*elf_entrypoints, *ELF_RUNTIME}:
                raise ValueError(f"unreviewed executable in initrd input: {path}")
    for path in elf_entrypoints:
        row = source.get(path)
        if row is None or row["kind"] != "file" or not row["output_mode"] & 0o111:
            raise ValueError(f"required ELF initrd entrypoint absent: {path}")
    expected_elf = {path for path in selected if source[path]["kind"] == "file"
                    and (path in {*elf_entrypoints, *ELF_RUNTIME}
                         or source[path]["output_mode"] & 0o111)}
    for identity, _ in authenticated:
        package = identity["name"]
        pending = {path for path in expected_elf if source[path]["packages"] == [package]}
        if not pending:
            continue
        with tarfile.open(fileobj=io.BytesIO(payloads[package]), mode="r:xz") as contents:
            for member in contents:
                path = builder.member_path(member, allow_hardlink=True)
                if path not in pending:
                    continue
                stream = contents.extractfile(member)
                if stream is None or stream.read(4) != b"\x7fELF":
                    raise ValueError(f"selected initrd executable is not ELF: {path}")
                pending.remove(path)
        if pending:
            raise ValueError("selected initrd ELF source member absent")
    entries = [source[path] for path in sorted(selected)]
    return payloads, entries


def write_archive(destination, authenticated, payloads, entries):
    by_path = {row["path"]: row for row in entries}
    written = set()
    directories = sorted((row for row in entries if row["kind"] == "directory"),
                         key=lambda row: (row["path"].count("/"), row["path"]))
    with tarfile.open(fileobj=destination, mode="w|", format=tarfile.PAX_FORMAT) as output:
        for row in directories:
            output.addfile(root_tree.tar_header(row))
            written.add(row["path"])
        for identity, _ in authenticated:
            package = identity["name"]
            with tarfile.open(fileobj=io.BytesIO(payloads[package]), mode="r:xz") as source:
                hardlinks = []
                for member in source:
                    path = builder.member_path(member, allow_hardlink=True)
                    if path not in by_path or member.type == tarfile.DIRTYPE:
                        continue
                    row = by_path[path]
                    if row["packages"] != [package] or row["source_mode"] != member.mode:
                        raise ValueError("selected initrd package member differs")
                    if member.type == tarfile.LNKTYPE:
                        hardlinks.append(row)
                        continue
                    if member.type == tarfile.SYMTYPE:
                        if row["kind"] != "symlink" or row["target"] != member.linkname:
                            raise ValueError("selected initrd symlink differs")
                        output.addfile(root_tree.tar_header(row))
                    elif member.type == tarfile.REGTYPE:
                        if row["kind"] != "file":
                            raise ValueError("selected initrd regular file differs")
                        stream = source.extractfile(member)
                        if stream is None:
                            raise ValueError("selected initrd file unreadable")
                        reader = root_tree.HashingReader(stream)
                        output.addfile(root_tree.tar_header(row), reader)
                        if reader.size != row["size"] or reader.digest.hexdigest() != row["sha256"]:
                            raise ValueError("selected initrd file content differs")
                    else:
                        raise ValueError("selected initrd member has unsupported type")
                    if path in written:
                        raise ValueError(f"selected initrd member written twice: {path}")
                    written.add(path)
                for row in hardlinks:
                    if row["kind"] != "hardlink" or row["target"] not in written:
                        raise ValueError("selected initrd hardlink target absent")
                    output.addfile(root_tree.tar_header(row))
                    if row["path"] in written:
                        raise ValueError("selected initrd hardlink written twice")
                    written.add(row["path"])
    if written != set(by_path):
        raise ValueError("selected initrd archive is incomplete")


def source_manifest(authenticated, entries, archive_sha256, archive_size):
    used = {package for row in entries if row["kind"] != "directory"
            for package in row["packages"]}
    return {
        "schema_version": 1, "status": STATUS,
        "guest_package_closure_sha256": guest.prepare.PACKAGE_CLOSURE_SHA256,
        "signed_inrelease_sha256": guest.INRELEASE_SHA256,
        "signed_packages_index_sha256": guest.PACKAGES_SHA256,
        "selected_packages": [{key: identity[key] for key in
                               ("name", "version", "architecture", "size", "sha256")}
                              for identity, _ in authenticated if identity["name"] in used],
        "archive_name": ARCHIVE, "archive_sha256": archive_sha256,
        "archive_size": archive_size, "entries": entries,
        "elf_entrypoints": list(ELF_ENTRYPOINTS),
        "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
        "package_control_scripts_executed": False,
        "early_init_included": False, "runtime_closure_verified": False,
        "initrd_built": False, "boot_verified": False,
        "private_mode_approved": False,
    }


def assemble(metadata, archives, artifact, workspace):
    authenticated = preflight.authenticated_archives(Path(metadata), Path(archives))
    payloads, entries = selected_source_plan(authenticated)
    artifact = Path(artifact)
    parent = builder.output_parent(Path(workspace), artifact)
    try:
        os.mkdir(artifact.name, mode=0o700, dir_fd=parent)
        directory = os.open(artifact.name, builder.DIRECTORY_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        descriptor = os.open(ARCHIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as output:
            write_archive(output, authenticated, payloads, entries)
            output.flush()
            os.fsync(output.fileno())
        descriptor = os.open(ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            archive_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        manifest = source_manifest(authenticated, entries, archive_sha256, info.st_size)
        encoded = canonical_bytes(manifest)
        descriptor = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"status": STATUS, "archive_sha256": archive_sha256,
            "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "entry_count": len(entries), "selected_package_count": len(manifest["selected_packages"]),
            "package_control_scripts_executed": False, "runtime_closure_verified": False,
            "initrd_built": False, "boot_verified": False,
            "private_mode_approved": False}


class DigestSink:
    def __init__(self):
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data):
        self.digest.update(data)
        self.size += len(data)
        return len(data)


def artifact_identity(info):
    """Fields that must remain fixed while signed-source bytes are checked."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check_artifact_metadata(info, *, directory, label):
    expected_mode = 0o700 if directory else 0o600
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(info.st_mode) or stat.S_IMODE(info.st_mode) != expected_mode
            or info.st_uid != os.geteuid() or (not directory and info.st_nlink != 1)):
        raise ValueError(f"{label} ownership, type, links, or mode differs")


def require_stable(descriptor, before, label):
    if artifact_identity(os.fstat(descriptor)) != artifact_identity(before):
        raise ValueError(f"{label} changed during verification")


def verify(metadata, archives, artifact):
    authenticated = preflight.authenticated_archives(Path(metadata), Path(archives))
    payloads, entries = selected_source_plan(authenticated)
    artifact = Path(artifact)
    directory = guest.open_directory(artifact, "initrd BaseTrees input")
    try:
        directory_info = os.fstat(directory)
        check_artifact_metadata(directory_info, directory=True,
                                label="initrd BaseTrees input directory")
        if set(os.listdir(directory)) != {ARCHIVE, MANIFEST}:
            raise ValueError("initrd BaseTrees input contains unreviewed files")
        sink = DigestSink()
        write_archive(sink, authenticated, payloads, entries)
        descriptor = os.open(ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            check_artifact_metadata(info, directory=False,
                                    label="initrd BaseTrees archive")
            if info.st_size != sink.size:
                raise ValueError("initrd BaseTrees archive size differs")
            observed_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            require_stable(stream.fileno(), info, "initrd BaseTrees archive")
            if observed_sha256 != sink.digest.hexdigest():
                raise ValueError("initrd BaseTrees archive differs from signed package data")
        expected = canonical_bytes(source_manifest(authenticated, entries,
                                                   observed_sha256, info.st_size))
        descriptor = os.open(MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            manifest_info = os.fstat(stream.fileno())
            check_artifact_metadata(manifest_info, directory=False,
                                    label="initrd BaseTrees manifest")
            observed = stream.read(len(expected) + 1)
            require_stable(stream.fileno(), manifest_info, "initrd BaseTrees manifest")
            if observed != expected:
                raise ValueError("initrd BaseTrees manifest differs from signed source plan")
        require_stable(directory, directory_info, "initrd BaseTrees input directory")
        if artifact_identity(os.stat(artifact, follow_symlinks=False)) != artifact_identity(directory_info):
            raise ValueError("initrd BaseTrees input directory changed during verification")
    finally:
        os.close(directory)
    return {"status": STATUS, "archive_sha256": observed_sha256,
            "manifest_sha256": hashlib.sha256(expected).hexdigest(),
            "entry_count": len(entries), "package_control_scripts_executed": False,
            "runtime_closure_verified": False, "initrd_built": False,
            "boot_verified": False, "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble", "verify"))
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "assemble":
            workspace = args.workspace or Path(os.environ["CODEX_WORKSPACE_DIR"])
            report = assemble(args.metadata, args.archives, args.artifact, workspace)
        else:
            report = verify(args.metadata, args.archives, args.artifact)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "initrd_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
