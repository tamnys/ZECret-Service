#!/usr/bin/env python3
"""Compare a mkosi profile's output directory with signed Debian BaseTrees data.

This records observed differences without accepting first-seen output or
asserting that mkosi created the directory.
No generated path or changed byte has an approved policy yet. The comparison
does not build a disk, establish a complete application root, or approve boot.
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

import assemble_guest_base_tree as base_tree
import preflight_guest_base_tree as preflight
import fetch_guest_closure as guest
import prepare_guest_basetree_profile as profile


STATUS = "diagnostic-authenticated-input-tree-exact-unapproved"
DELTA_STATUS = "diagnostic-unreviewed-profile-output-delta"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
SOURCE_MTIME_NS = 0  # assemble_guest_base_tree.tar_header sets mtime=0.
ACCOUNT_DIRECTORIES = {"etc", "usr", "usr/lib", "usr/lib/sysusers.d"}
ACCOUNT_FILES = {"etc/" + name for name in profile.accounts.OUTPUT_FILES} | {
    "usr/lib/sysusers.d/" + profile.ACCOUNT_FILE}


def stable_stat(value):
    """Fields that must not change while this process reads an entry."""
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)


def reject_xattrs(descriptor, path):
    # Linux capabilities and ACLs are xattrs. The signed BaseTrees assembler
    # rejects PAX metadata, so none can be silently authorized by this scan.
    if os.listxattr(descriptor):
        raise ValueError(f"produced root has unreviewed extended attributes: {path}")


def observed_entry(parent_fd, name, path, root_device):
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if before.st_dev != root_device:
        raise ValueError(f"produced root contains another filesystem: {path}")
    result = {"path": path, "uid": before.st_uid, "gid": before.st_gid,
              "mode": stat.S_IMODE(before.st_mode),
              "mtime_ns": before.st_mtime_ns,
              "inode": (before.st_dev, before.st_ino)}
    if stat.S_ISDIR(before.st_mode):
        fd = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            if stable_stat(os.fstat(fd)) != stable_stat(before):
                raise ValueError(f"produced root directory changed during open: {path}")
            reject_xattrs(fd, path)
            result["kind"] = "directory"
            children = scan_directory(fd, path, root_device)
            if stable_stat(os.fstat(fd)) != stable_stat(before):
                raise ValueError(f"produced root directory changed during scan: {path}")
        finally:
            os.close(fd)
        return result, children
    if stat.S_ISREG(before.st_mode):
        fd = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
        try:
            if stable_stat(os.fstat(fd)) != stable_stat(before):
                raise ValueError(f"produced root file changed during open: {path}")
            reject_xattrs(fd, path)
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(fd, 1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
            if size != before.st_size or stable_stat(os.fstat(fd)) != stable_stat(before):
                raise ValueError(f"produced root file changed during scan: {path}")
        finally:
            os.close(fd)
        result.update(kind="file", size=size, sha256=digest.hexdigest(),
                      nlink=before.st_nlink)
        return result, {}
    if stat.S_ISLNK(before.st_mode):
        if os.listxattr(f"/proc/self/fd/{parent_fd}/{name}", follow_symlinks=False):
            raise ValueError(f"produced root has unreviewed extended attributes: {path}")
        result.update(kind="symlink", target=os.readlink(name, dir_fd=parent_fd))
        if stable_stat(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != stable_stat(before):
            raise ValueError(f"produced root link changed during scan: {path}")
        return result, {}
    raise ValueError(f"produced root contains unsupported file type: {path}")


def scan_directory(fd, prefix, root_device):
    rows = {}
    with os.scandir(fd) as listing:
        names = sorted(entry.name for entry in listing)
    for name in names:
        if name in {"", ".", ".."} or "/" in name:
            raise ValueError("produced root has noncanonical entry name")
        path = name if prefix == "." else f"{prefix}/{name}"
        row, children = observed_entry(fd, name, path, root_device)
        if path in rows or any(child in rows for child in children):
            raise ValueError("produced root has duplicate path")
        rows[path] = row
        rows.update(children)
    return rows


def scan_root(root):
    root = Path(root)
    fd = guest.open_directory(root, "produced mkosi root")
    try:
        before = os.fstat(fd)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("produced mkosi root is not a directory")
        reject_xattrs(fd, ".")
        rows = {".": {"path": ".", "kind": "directory",
                      "uid": before.st_uid, "gid": before.st_gid,
                      "mode": stat.S_IMODE(before.st_mode),
                      "mtime_ns": before.st_mtime_ns,
                      "inode": (before.st_dev, before.st_ino)}}
        rows.update(scan_directory(fd, ".", before.st_dev))
        if stable_stat(os.fstat(fd)) != stable_stat(before):
            raise ValueError("produced mkosi root changed during scan")
        aliases = {}
        for row in rows.values():
            if row["kind"] == "file":
                aliases[row["inode"]] = aliases.get(row["inode"], 0) + 1
        for row in rows.values():
            if row["kind"] == "file" and row["nlink"] != aliases[row["inode"]]:
                raise ValueError(f"produced root file has an outside hardlink: {row['path']}")
        return rows
    finally:
        os.close(fd)


def expected_input_rows(base_entries, account_tree):
    """Apply only the exact signed-source ExtraTrees paths in the mkosi profile."""
    expected = {row["path"]: dict(row) for row in base_entries}
    if len(expected) != len(base_entries) or "." not in expected:
        raise ValueError("signed guest BaseTrees inventory is malformed")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(account_tree), mode="r:") as archive:
        for member in archive:
            path = member.name.rstrip("/")
            if path in seen or path not in ACCOUNT_DIRECTORIES | ACCOUNT_FILES:
                raise ValueError("account ExtraTrees contains unreviewed path")
            seen.add(path)
            if (member.uid != 0 or member.gid != 0 or member.mtime != 0
                    or member.pax_headers or member.uname or member.gname):
                raise ValueError("account ExtraTrees metadata differs")
            if path in ACCOUNT_DIRECTORIES:
                if not member.isdir() or member.mode != 0o755:
                    raise ValueError("account ExtraTrees directory differs")
                previous = expected.get(path)
                if previous is not None and previous["kind"] != "directory":
                    raise ValueError("account ExtraTrees replaces non-directory parent")
                expected[path] = {"path": path, "kind": "directory", "uid": 0,
                                  "gid": 0, "output_mode": 0o755}
            else:
                mode = (profile.INSTALLED_ACCOUNT_MODES[path.removeprefix("etc/")]
                        if path.startswith("etc/") else 0o644)
                if not member.isfile() or member.mode != mode:
                    raise ValueError("account ExtraTrees file differs")
                previous = expected.get(path)
                if previous is not None and previous["kind"] != "file":
                    raise ValueError("account ExtraTrees replaces link or directory")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("account ExtraTrees file is unreadable")
                data = stream.read()
                if len(data) != member.size:
                    raise ValueError("account ExtraTrees file size differs")
                expected[path] = {"path": path, "kind": "file", "uid": 0,
                                  "gid": 0, "output_mode": mode,
                                  "size": len(data),
                                  "sha256": hashlib.sha256(data).hexdigest()}
    if seen != ACCOUNT_DIRECTORIES | ACCOUNT_FILES:
        raise ValueError("account ExtraTrees inventory is incomplete")
    return list(expected.values())


def differences(expected_rows, observed):
    expected = {row["path"]: row for row in expected_rows}
    if len(expected) != len(expected_rows) or "." not in expected:
        raise ValueError("signed guest BaseTrees inventory is malformed")
    changes = []
    for path in sorted(expected.keys() | observed.keys()):
        source = expected.get(path)
        actual = observed.get(path)
        if source is None:
            changes.append({"path": path, "difference": "added"})
            continue
        if actual is None:
            changes.append({"path": path, "difference": "missing"})
            continue
        kind = "file" if source["kind"] == "hardlink" else source["kind"]
        if kind != actual["kind"]:
            changes.append({"path": path, "difference": "kind"})
            continue
        if (source["uid"], source["gid"]) != (actual["uid"], actual["gid"]):
            changes.append({"path": path, "difference": "owner"})
        if kind != "symlink" and source["output_mode"] != actual["mode"]:
            changes.append({"path": path, "difference": "mode"})
        if actual["mtime_ns"] != SOURCE_MTIME_NS:
            changes.append({"path": path, "difference": "mtime"})
        if kind == "symlink" and source["target"] != actual["target"]:
            changes.append({"path": path, "difference": "link-target"})
        if kind == "file" and (source["size"], source["sha256"]) != (actual["size"], actual["sha256"]):
            changes.append({"path": path, "difference": "content"})
        if source["kind"] == "hardlink":
            target = observed.get(source["target"])
            if target is None or target["kind"] != "file" or actual["inode"] != target["inode"]:
                changes.append({"path": path, "difference": "hardlink"})
    return changes


def audit(metadata, archives, artifact, account_artifact, profile_path, workspace):
    source = base_tree.verify(metadata, archives, artifact)
    if (source.get("status") != base_tree.STATUS
            or source.get("signed_snapshot_rechecked") is not True
            or source.get("archive_bytes_checked") is not True
            or any(source.get(field) is not False for field in
                   ("package_scripts_executed", "image_built", "boot_verified",
                    "private_mode_approved"))):
        raise ValueError("signed guest BaseTrees changed diagnostic state")
    profile_path = profile.checked_profile_path(profile_path, workspace)
    pinned_profile = profile.verify_profile(metadata, archives, artifact,
                                            account_artifact, profile_path, workspace)
    if (pinned_profile.get("status") != profile.STATUS
            or pinned_profile.get("base_tree_sha256") != source["archive_sha256"]
            or pinned_profile.get("account_files_preseeded_from_signed_source") is not True
            or any(pinned_profile.get(field) is not False for field in
                   ("package_install_configured", "package_scripts_executed",
                    "root_directory_built", "disk_image_built", "boot_verified",
                    "private_mode_approved"))):
        raise ValueError("mkosi BaseTrees profile changed diagnostic state")
    authenticated = preflight.authenticated_archives(Path(metadata), Path(archives))
    _, entries = base_tree.source_plan(authenticated)
    if len(entries) != source["entry_count"]:
        raise ValueError("signed guest BaseTrees entry count changed")
    account_tree = profile.account_tree_bytes(
        profile.project_sysusers_bytes(),
        profile.verified_account_files(metadata, archives, account_artifact,
                                       workspace))
    expected = expected_input_rows(entries, account_tree)
    output = profile_path.parent / (profile_path.name + "-output") / profile.OUTPUT_NAME
    if output.parent.is_symlink():
        raise ValueError("mkosi output directory is redirected")
    observed = scan_root(output)
    changes = differences(expected, observed)
    if profile.verify_profile(metadata, archives, artifact, account_artifact,
                              profile_path, workspace) != pinned_profile:
        raise ValueError("mkosi BaseTrees profile changed during root scan")
    if base_tree.verify(metadata, archives, artifact) != source:
        raise ValueError("signed guest BaseTrees changed during root scan")
    return {
        "schema_version": 2, "status": STATUS if not changes else DELTA_STATUS,
        "signed_base_tree_sha256": source["archive_sha256"],
        "signed_base_tree_manifest_sha256": source["manifest_sha256"],
        "signed_account_tree_sha256": hashlib.sha256(account_tree).hexdigest(),
        "mkosi_profile_manifest_sha256": pinned_profile["profile_manifest_sha256"],
        "signed_base_entry_count": len(entries),
        "authenticated_input_entry_count": len(expected),
        "produced_entry_count": len(observed),
        "differences": changes, "authenticated_inputs_exact": not changes,
        "mkosi_execution_verified": False,
        "generated_effects_approved": False,
        "post_mkosi_tree_audited": False, "disk_image_built": False,
        "boot_verified": False, "private_mode_approved": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--account-artifact", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.metadata, args.archives, args.artifact,
                       args.account_artifact, args.profile, args.workspace)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        report = {"schema_version": 2, "status": "blocked", "reason": str(error),
                  "authenticated_inputs_exact": False,
                  "mkosi_execution_verified": False,
                  "generated_effects_approved": False,
                  "post_mkosi_tree_audited": False, "disk_image_built": False,
                  "boot_verified": False, "private_mode_approved": False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in {STATUS, DELTA_STATUS} else 1


if __name__ == "__main__":
    sys.exit(main())
