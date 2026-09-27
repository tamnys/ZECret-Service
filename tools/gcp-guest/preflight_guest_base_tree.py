#!/usr/bin/env python3
"""Inventory signed Debian payload metadata before considering mkosi BaseTrees.

This reads package archives as data. It does not configure packages, execute
maintainer scripts, build an image, or establish a bootable or approved guest.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

import fetch_guest_closure as guest
import prepare
import stage_builder_toolchain as builder
import stage_guest_payload


STATUS = "diagnostic-base-tree-input-gaps-unreviewed"
SYSUSERS = prepare.PROFILE / "rootfs/usr/lib/sysusers.d/zrpc.conf"
ROOT_INPUTS = (
    ("usr/lib/os-release", "file", False),
    ("usr/lib/systemd/systemd", "file", True),
    ("usr/lib/systemd/boot/efi/linuxx64.efi.stub", "file", False),
    (f"boot/vmlinuz-{prepare.KERNEL_VERSION}", "file", False),
    (f"usr/lib/modules/{prepare.KERNEL_VERSION}", "directory", False),
    (f"usr/lib/modules/{prepare.KERNEL_VERSION}/kernel/drivers/md/dm-verity.ko.xz", "file", False),
)
INITRD_INPUTS = (
    ("usr/lib/os-release", "file", False),
    ("usr/lib/systemd/systemd", "file", True),
    ("usr/lib/systemd/systemd-veritysetup", "file", True),
    ("usr/lib/systemd/system-generators/systemd-veritysetup-generator", "file", True),
    ("usr/bin/udevadm", "file", True),
    ("usr/bin/kmod", "file", True),
    ("usr/sbin/dmsetup", "file", True),
    ("usr/lib/systemd/system/initrd.target", "file", False),
    ("usr/lib/systemd/system/initrd-root-fs.target", "file", False),
)
ACCOUNT_INPUTS = ("etc/passwd", "etc/group", "etc/shadow")
KINDS = {tarfile.DIRTYPE: "directory", tarfile.REGTYPE: "file",
         tarfile.SYMTYPE: "symlink", tarfile.LNKTYPE: "hardlink"}


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def authenticated_archives(metadata, archives):
    identities = guest.authenticated_packages(Path(metadata))
    directory = guest.open_directory(Path(archives), "guest archive")
    try:
        return [(identity, builder.locked_archive(
            {key: identity[key] for key in builder.closure.PACKAGE_FIELDS},
            directory,
        )) for identity in identities]
    finally:
        os.close(directory)


def payload_inventory(archives):
    """Return exact tar metadata and the collision-checked effective payload."""
    packages = [(identity["name"], archive) for identity, archive in archives]
    payloads, effective = builder.payload_entries(packages, allow_hardlinks=True)
    root = []
    initrd = []
    for identity, _ in archives:
        name = identity["name"]
        with tarfile.open(fileobj=io.BytesIO(payloads[name]), mode="r:xz") as contents:
            for member in contents:
                path = builder.member_path(member, allow_hardlink=True)
                if type(member.uid) is not int or member.uid < 0 or type(member.gid) is not int or member.gid < 0:
                    raise ValueError(f"invalid Debian payload owner: {name}:{member.name}")
                if path is None:
                    path = "."
                kind = KINDS[member.type]
                row = {"package": name, "path": path, "type": kind,
                       "uid": member.uid, "gid": member.gid,
                       "uname": member.uname, "gname": member.gname,
                       "mode": member.mode}
                if kind == "symlink":
                    row["target"] = builder.checked_link_target(path, member.linkname)
                elif kind == "hardlink":
                    row["target"] = builder.checked_hardlink_target(member.linkname)
                if kind in {"file", "hardlink"}:
                    row["size"] = effective[path]["size"]
                    row["sha256"] = effective[path]["sha256"]
                root.append(row)
                if name in prepare.INITRD_PACKAGES:
                    initrd.append(row)
    if not prepare.INITRD_PACKAGES <= {identity["name"] for identity, _ in archives}:
        raise ValueError("required initrd package seed missing from signed guest closure")
    root.sort(key=lambda row: (row["path"], row["package"]))
    initrd.sort(key=lambda row: (row["path"], row["package"]))
    return root, initrd, effective


def required_inputs(rows, required):
    by_path = {row["path"]: row for row in rows if row["type"] != "directory"}
    by_path.update({row["path"]: row for row in rows if row["type"] == "directory" and row["path"] not in by_path})
    checks = []
    for path, kind, executable in required:
        row = by_path.get(path)
        if row is None:
            result = "missing_from_package_data"
        elif row["type"] != kind:
            result = "wrong_type"
        elif (row["uid"], row["gid"]) != (0, 0):
            result = "non_root_owner"
        elif row["mode"] & 0o022 or (executable and not row["mode"] & 0o111):
            result = "unsafe_or_nonexecutable_mode"
        else:
            result = "present_in_package_data"
        checks.append({"path": path, "expected_type": kind,
                       "expected_executable": executable, "result": result})
    return checks


def staged_inventory(root, effective):
    """Inspect data-only staged files without following any directory symlink."""
    directory = guest.open_directory(Path(root), "staged guest payload")
    rows = []
    try:
        root_stat = os.fstat(directory)
        rows.append({"path": ".", "type": "directory", "uid": root_stat.st_uid,
                     "gid": root_stat.st_gid, "mode": stat.S_IMODE(root_stat.st_mode)})
        for path, expected in sorted(effective.items()):
            with builder.parent_fd(directory, path) as parent:
                name = path.rsplit("/", 1)[-1]
                actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
                kind = ("directory" if stat.S_ISDIR(actual.st_mode) else
                        "file" if stat.S_ISREG(actual.st_mode) else
                        "symlink" if stat.S_ISLNK(actual.st_mode) else "special")
                if kind != expected["kind"] or (kind != "symlink" and
                        stat.S_IMODE(actual.st_mode) != expected["staged_mode"]):
                    raise ValueError(f"staged payload type or mode differs: {path}")
                row = {"path": path, "type": kind, "uid": actual.st_uid,
                       "gid": actual.st_gid, "mode": stat.S_IMODE(actual.st_mode)}
                if kind == "symlink":
                    row["target"] = os.readlink(name, dir_fd=parent)
                    if row["target"] != expected["target"]:
                        raise ValueError(f"staged payload symlink differs: {path}")
                elif kind == "file":
                    row["size"] = actual.st_size
                    if row["size"] != expected["size"]:
                        raise ValueError(f"staged payload size differs: {path}")
                rows.append(row)
        manifest = os.stat(stage_guest_payload.MANIFEST, dir_fd=directory,
                           follow_symlinks=False)
        if not stat.S_ISREG(manifest.st_mode) or stat.S_IMODE(manifest.st_mode) != 0o600:
            raise ValueError("staged payload inventory file differs")
        rows.append({"path": stage_guest_payload.MANIFEST, "type": "file",
                     "uid": manifest.st_uid, "gid": manifest.st_gid,
                     "mode": stat.S_IMODE(manifest.st_mode), "size": manifest.st_size})
        observed = {"."}
        retained_root = Path(f"/proc/self/fd/{directory}")
        for parent, directories, files in os.walk(retained_root, followlinks=False):
            for name in directories + files:
                observed.add((Path(parent) / name).relative_to(retained_root).as_posix())
        if observed != {".", stage_guest_payload.MANIFEST, *effective}:
            raise ValueError("staged payload has missing or unreviewed paths")
    finally:
        os.close(directory)
    return rows


def preflight(metadata, archives, staged_root):
    authenticated = authenticated_archives(metadata, archives)
    root, initrd, effective = payload_inventory(authenticated)
    staged = staged_inventory(staged_root, effective)
    staged_by_path = {row["path"]: row for row in staged}
    owner_mismatches = sum(
        (row["uid"], row["gid"]) !=
        (staged_by_path[row["path"]]["uid"], staged_by_path[row["path"]]["gid"])
        for row in root
    )
    mode_changes = sum(row["mode"] != staged_by_path[row["path"]]["mode"] for row in root)
    root_checks = required_inputs(root, ROOT_INPUTS)
    initrd_checks = required_inputs(initrd, INITRD_INPUTS)
    account_checks = required_inputs(root, tuple((path, "file", False) for path in ACCOUNT_INPUTS))
    if SYSUSERS.is_symlink() or not SYSUSERS.is_file():
        raise ValueError("committed account-generation input missing or redirected")
    sysusers_hash = hashlib.sha256(SYSUSERS.read_bytes()).hexdigest()
    gaps = [
        {"code": "stager_does_not_preserve_archive_ownership", "mismatching_archive_entries": owner_mismatches},
        {"code": "stager_changes_archive_modes", "changed_archive_entries": mode_changes},
        {"code": "package_configuration_and_triggers_not_applied"},
        {"code": "generated_account_files_not_verified"},
        {"code": "initrd_seed_tree_not_staged"},
        {"code": "separate_early_init_and_runtime_binaries_not_verified"},
        {"code": "initrd_runtime_dependency_closure_not_verified"},
        {"code": "image_build_and_boot_not_performed"},
    ]
    for label, checks in (("root", root_checks), ("initrd_seed", initrd_checks), ("account", account_checks)):
        gaps.extend({"code": "required_package_input_gap", "image": label,
                     "path": check["path"], "result": check["result"]}
                    for check in checks if check["result"] != "present_in_package_data")
    return {
        "schema_version": 1, "status": STATUS,
        "guest_package_closure_sha256": prepare.PACKAGE_CLOSURE_SHA256,
        "signed_inrelease_sha256": guest.INRELEASE_SHA256,
        "signed_packages_index_sha256": guest.PACKAGES_SHA256,
        "initrd_seed_package_names": sorted(prepare.INITRD_PACKAGES),
        "packages": [{"name": identity["name"], "version": identity["version"],
                      "architecture": identity["architecture"], "sha256": identity["sha256"]}
                     for identity, _ in authenticated],
        "root_archive_entries": root, "initrd_seed_archive_entries": initrd,
        "staged_root_entries": staged,
        "root_archive_inventory_sha256": hashlib.sha256(canonical_bytes(root)).hexdigest(),
        "initrd_seed_archive_inventory_sha256": hashlib.sha256(canonical_bytes(initrd)).hexdigest(),
        "staged_root_inventory_sha256": hashlib.sha256(canonical_bytes(staged)).hexdigest(),
        "root_required_inputs": root_checks, "initrd_seed_required_inputs": initrd_checks,
        "account_file_inputs": account_checks,
        "account_sysusers_config_sha256": sysusers_hash,
        "gaps": gaps,
        "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
        "staged_payload_content_rechecked": False,
        "initrd_seed_tree_staged": False,
        "package_scripts_executed": False, "image_built": False,
        "boot_verified": False, "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--staged-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = preflight(args.metadata, args.archives, args.staged_root)
        encoded = canonical_bytes(report) + b"\n"
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps({
        "status": report["status"],
        "report_sha256": hashlib.sha256(encoded).hexdigest(),
        "package_count": len(report["packages"]),
        "root_archive_entry_count": len(report["root_archive_entries"]),
        "initrd_seed_archive_entry_count": len(report["initrd_seed_archive_entries"]),
        "staged_root_entry_count": len(report["staged_root_entries"]),
        "root_archive_inventory_sha256": report["root_archive_inventory_sha256"],
        "initrd_seed_archive_inventory_sha256": report["initrd_seed_archive_inventory_sha256"],
        "staged_root_inventory_sha256": report["staged_root_inventory_sha256"],
        "gaps": report["gaps"],
        "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
        "staged_payload_content_rechecked": False,
        "initrd_seed_tree_staged": False,
        "package_scripts_executed": False, "image_built": False,
        "boot_verified": False, "private_mode_approved": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
