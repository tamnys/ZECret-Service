#!/usr/bin/env python3
"""Generate or verify a diagnostic guest account database from signed inputs.

This runs the signed Debian systemd-sysusers binary, never package maintainer
scripts. It does not authenticate the host's dynamic linker/library closure,
install a root filesystem, build an image, or approve private mode.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile

import fetch_guest_closure as guest
import stage_builder_toolchain as builder
import verify_builder_closure as closure


AUDIT_SPEC = importlib.util.spec_from_file_location(
    "audit_rootfs", Path(__file__).with_name("audit-rootfs.py"))
audit_rootfs = importlib.util.module_from_spec(AUDIT_SPEC)
AUDIT_SPEC.loader.exec_module(audit_rootfs)

PROJECT_SYSUSERS = (Path(__file__).resolve().parents[2] /
                    "deploy/gcp/guest/rootfs/usr/lib/sysusers.d/zrpc.conf")
REQUIRED = {
    "base-passwd": {
        "usr/share/base-passwd/passwd.master",
        "usr/share/base-passwd/group.master",
    },
    "dbus-system-bus-common": {"usr/lib/sysusers.d/dbus.conf"},
    "systemd": {
        "usr/bin/systemd-sysusers",
        "usr/lib/sysusers.d/basic.conf",
        "usr/lib/sysusers.d/systemd-journal.conf",
        "usr/lib/sysusers.d/systemd-network.conf",
    },
    "systemd-resolved": {"usr/lib/sysusers.d/systemd-resolve.conf"},
    "udev": {"usr/lib/sysusers.d/debian-udev.conf"},
    "libsystemd-shared": {
        "usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-257.so",
    },
}
SYSUSERS_DIRS = ("etc/sysusers.d/", "run/sysusers.d/",
                 "usr/local/lib/sysusers.d/", "usr/lib/sysusers.d/")
OUTPUT_FILES = ("passwd", "group", "shadow")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def authenticated_inputs(metadata, archives):
    """Read only exact required files, but inspect every locked package."""
    identities = guest.authenticated_packages(Path(metadata))
    directory = guest.open_directory(Path(archives), "guest archive")
    selected = {}
    source = []
    try:
        for identity in identities:
            package = identity["name"]
            archive = builder.locked_archive(
                {key: identity[key] for key in closure.PACKAGE_FIELDS}, directory)
            payload = closure.deb_data_tar(archive)
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as contents:
                for member in contents:
                    path = builder.member_path(member, allow_hardlink=True)
                    if path is None:
                        continue
                    requested = path in REQUIRED.get(package, ())
                    sysusers_input = path.startswith(SYSUSERS_DIRS)
                    if sysusers_input and not requested:
                        raise ValueError("unreviewed package sysusers input: " + path)
                    if not requested:
                        continue
                    if (member.type != tarfile.REGTYPE or member.uid != 0
                            or member.gid != 0 or member.mode & 0o022
                            or (path == "usr/bin/systemd-sysusers"
                                and not member.mode & 0o111)):
                        raise ValueError("unsafe account input: " + path)
                    key = (package, path)
                    if key in selected:
                        raise ValueError("duplicate account input: " + path)
                    stream = contents.extractfile(member)
                    if stream is None:
                        raise ValueError("unreadable account input: " + path)
                    data = stream.read()
                    if len(data) != member.size:
                        raise ValueError("truncated account input: " + path)
                    selected[key] = data
                    source.append({"package": package, "archive_sha256": identity["sha256"],
                                   "path": path, "size": len(data), "sha256": sha256(data),
                                   "mode": member.mode})
    finally:
        os.close(directory)
    wanted = {(package, path) for package, paths in REQUIRED.items() for path in paths}
    if selected.keys() != wanted:
        raise ValueError("signed account inputs missing: " +
                         ", ".join(sorted(f"{package}:{path}" for package, path
                                          in wanted - selected.keys())))
    if PROJECT_SYSUSERS.is_symlink() or not PROJECT_SYSUSERS.is_file():
        raise ValueError("project sysusers input missing or redirected")
    project_mode = stat.S_IMODE(PROJECT_SYSUSERS.stat().st_mode)
    if project_mode & 0o022:
        raise ValueError("project sysusers input is mutable")
    project = PROJECT_SYSUSERS.read_bytes()
    selected[("project", "usr/lib/sysusers.d/zrpc.conf")] = project
    source.append({"package": "project", "path": "usr/lib/sysusers.d/zrpc.conf",
                   "size": len(project), "sha256": sha256(project), "mode": project_mode})
    return selected, sorted(source, key=lambda row: (row["package"], row["path"]))


def write_input(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    path.chmod(mode)


def master_ids(data, fields, id_fields):
    """Check fixed identities in base-passwd master; sysusers creates files."""
    identities = {}
    for line in data.decode("utf-8").splitlines():
        parts = line.split(":")
        if (len(parts) != fields or not parts[0] or parts[0] in identities
                or parts[1] != "*" or any(not parts[index].isdecimal()
                                           for index in id_fields)):
            raise ValueError("signed base-passwd master malformed")
        identities[parts[0]] = tuple(int(parts[index]) for index in id_fields)
    if not identities or "root" not in identities:
        raise ValueError("signed base-passwd root identity missing")
    return identities


def check_master_ids(root, selected):
    users = master_ids(selected[("base-passwd", "usr/share/base-passwd/passwd.master")],
                       7, (2, 3))
    groups = master_ids(selected[("base-passwd", "usr/share/base-passwd/group.master")],
                        4, (2,))
    passwd = audit_rootfs.account_file(root, "passwd", 7)
    group = audit_rootfs.account_file(root, "group", 4)
    for name, identity in users.items():
        if name not in passwd or tuple(int(passwd[name][index]) for index in (2, 3)) != identity:
            raise ValueError("generated account differs from signed base-passwd master")
    for name, identity in groups.items():
        if name not in group or (int(group[name][2]),) != identity:
            raise ValueError("generated group differs from signed base-passwd master")


def run_once(directory, selected, binary, library):
    root = directory / "root"
    sysusers_dir = root / "usr/lib/sysusers.d"
    sysusers_dir.mkdir(parents=True)
    (root / "etc").mkdir()
    for (package, path), data in selected.items():
        if path.startswith("usr/lib/sysusers.d/"):
            write_input(root / path, data, 0o644)
    environment = {
        "LANG": "C", "PATH": "/usr/bin:/bin", "SYSTEMD_LOG_LEVEL": "warning",
        "SOURCE_DATE_EPOCH": str(guest.SIGNED_RELEASE_EPOCH),
        "LD_LIBRARY_PATH": str(library.parent),
    }
    result = subprocess.run([str(binary), f"--root={root}"], env=environment,
                            capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"signed systemd-sysusers failed: exit {result.returncode}")
    shadow = root / "etc/shadow"
    if shadow.is_symlink() or not shadow.is_file():
        raise ValueError("signed systemd-sysusers omitted shadow")
    # systemd creates shadow with mode 000. Read it as the local owner for the
    # diagnostic comparison; the published account artifact remains 0400.
    shadow.chmod(0o400)
    audit_rootfs.audit_accounts(root)
    check_master_ids(root, selected)
    return {name: (root / "etc" / name).read_bytes() for name in OUTPUT_FILES}


def build(metadata, archives, workspace, output):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Linux x86_64 userspace required")
    workspace = Path(workspace)
    output = Path(output)
    if (workspace.is_symlink() or not workspace.is_dir() or output.parent != workspace
            or output.exists() or output.is_symlink()):
        raise ValueError("fresh direct child of explicit workspace required")
    selected, sources = authenticated_inputs(metadata, archives)
    with tempfile.TemporaryDirectory(prefix="zrpc-accounts-", dir=workspace) as temporary:
        scratch = Path(temporary)
        binary = scratch / "tool/usr/bin/systemd-sysusers"
        library = (scratch / "tool/usr/lib/x86_64-linux-gnu/systemd/"
                   "libsystemd-shared-257.so")
        write_input(binary, selected[("systemd", "usr/bin/systemd-sysusers")], 0o500)
        write_input(library, selected[("libsystemd-shared", "usr/lib/x86_64-linux-gnu/"
                                       "systemd/libsystemd-shared-257.so")], 0o400)
        first = run_once(scratch / "first", selected, binary, library)
        second = run_once(scratch / "second", selected, binary, library)
        if first != second:
            raise ValueError("systemd-sysusers account bytes are nondeterministic")
        artifact = scratch / "artifact"
        (artifact / "etc").mkdir(parents=True)
        for name, data in first.items():
            write_input(artifact / "etc" / name, data,
                        0o400 if name == "shadow" else 0o444)
        receipt = {
            "schema_version": 1,
            "status": "diagnostic-reproducible-guest-accounts-unbuilt",
            "guest_package_closure_sha256": guest.prepare.PACKAGE_CLOSURE_SHA256,
            "signed_inrelease_sha256": guest.INRELEASE_SHA256,
            "signed_packages_index_sha256": guest.PACKAGES_SHA256,
            "source_date_epoch": guest.SIGNED_RELEASE_EPOCH,
            "inputs": sources,
            "outputs": [{"path": "etc/" + name, "size": len(first[name]),
                         "sha256": sha256(first[name]),
                         "mode": 0o400 if name == "shadow" else 0o444}
                        for name in OUTPUT_FILES],
            "independent_generation_runs_matched": True,
            "package_scripts_executed": False,
            "host_dynamic_runtime_authenticated": False,
            "image_built": False,
            "private_mode_approved": False,
        }
        write_input(artifact / "receipt.json",
                    (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                    0o444)
        (artifact / "etc").chmod(0o700)
        artifact.chmod(0o700)
        artifact.rename(output)
    return receipt


def compare_artifact(actual, expected):
    """Compare exact files, directory inventory, modes, and receipt by fd."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = os.open(actual, directory_flags)
    try:
        if stat.S_IMODE(os.fstat(root).st_mode) != 0o700:
            raise ValueError("account artifact root mode differs")
        if set(os.listdir(root)) != {"etc", "receipt.json"}:
            raise ValueError("account artifact root entries differ")
        etc = os.open("etc", directory_flags, dir_fd=root)
        try:
            if (stat.S_IMODE(os.fstat(etc).st_mode) != 0o700
                    or set(os.listdir(etc)) != set(OUTPUT_FILES)):
                raise ValueError("account artifact etc entries or mode differ")
            for name in OUTPUT_FILES:
                compare_file(etc, name, expected / "etc" / name,
                             0o400 if name == "shadow" else 0o444)
        finally:
            os.close(etc)
        compare_file(root, "receipt.json", expected / "receipt.json", 0o444)
        if set(os.listdir(root)) != {"etc", "receipt.json"}:
            raise ValueError("account artifact changed during verification")
    finally:
        os.close(root)


def compare_file(directory, name, expected, mode):
    desired = expected.read_bytes()
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode:
            raise ValueError("account artifact file type or mode differs: " + name)
        observed = os.read(descriptor, len(desired) + 1)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if observed != desired or identity(before) != identity(after):
            raise ValueError("account artifact bytes differ: " + name)
    finally:
        os.close(descriptor)


def verify(metadata, archives, workspace, output):
    workspace = Path(workspace)
    output = Path(output)
    if (workspace.is_symlink() or not workspace.is_dir()
            or output.parent != workspace or output.is_symlink()
            or not output.is_dir()):
        raise ValueError("existing direct-child account artifact required")
    with tempfile.TemporaryDirectory(prefix="zrpc-account-verify-", dir=workspace) as temporary:
        fresh_workspace = Path(temporary)
        fresh = fresh_workspace / "expected"
        receipt = build(metadata, archives, fresh_workspace, fresh)
        compare_artifact(output, fresh)
    return {**receipt, "status": "diagnostic-verified-guest-account-artifact-unbuilt"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("metadata", "archives", "workspace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--verify", action="store_true",
                        help="reauthenticate inputs and compare an existing artifact")
    args = parser.parse_args()
    try:
        operation = verify if args.verify else build
        receipt = operation(args.metadata, args.archives, args.workspace, args.output)
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps({"status": receipt["status"],
                      "source_date_epoch": receipt["source_date_epoch"],
                      "input_count": len(receipt["inputs"]),
                      "outputs": receipt["outputs"],
                      "independent_generation_runs_matched": True,
                      "image_built": False, "private_mode_approved": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
