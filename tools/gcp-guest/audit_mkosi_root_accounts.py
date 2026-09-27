#!/usr/bin/env python3
"""Compare mkosi's diagnostic root accounts with signed-source expectations.

This checks only three account files in an already produced directory. It does
not audit the rest of the tree, a disk image, boot behavior, or private mode.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import build_guest_accounts as accounts
import prepare_guest_basetree_profile as profile_builder


STATUS = "diagnostic-produced-root-accounts-matched-unapproved"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


def stable_identity(observed):
    return (observed.st_dev, observed.st_ino, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns)


def checked_bytes(directory, name, size, mode, uid, gid, label):
    descriptor = os.open(name, FILE_FLAGS, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size != size
                or stat.S_IMODE(before.st_mode) != mode
                or (uid is not None and before.st_uid != uid)
                or (gid is not None and before.st_gid != gid)):
            raise ValueError(
                f"{label} metadata differs: {name}; "
                f"expected size={size} mode={mode:#o} uid={uid} gid={gid}; "
                f"observed regular={stat.S_ISREG(before.st_mode)} "
                f"size={before.st_size} mode={stat.S_IMODE(before.st_mode):#o} "
                f"uid={before.st_uid} gid={before.st_gid}")
        observed = bytearray()
        while len(observed) <= size:
            chunk = os.read(descriptor, min(65536, size + 1 - len(observed)))
            if not chunk:
                break
            observed.extend(chunk)
        after = os.fstat(descriptor)
        if len(observed) != size or stable_identity(before) != stable_identity(after):
            raise ValueError(f"{label} changed during inspection: {name}")
        return bytes(observed)
    finally:
        os.close(descriptor)


def compare_files(root_path, artifact_path, receipt):
    rows = receipt["outputs"]
    expected_names = set(accounts.OUTPUT_FILES)
    if (len(rows) != len(expected_names)
            or {row["path"] for row in rows} != {"etc/" + name for name in expected_names}):
        raise ValueError("signed-source account output inventory differs")
    expected_root = os.open(artifact_path, DIRECTORY_FLAGS)
    try:
        expected_etc = os.open("etc", DIRECTORY_FLAGS, dir_fd=expected_root)
        try:
            root = os.open(root_path, DIRECTORY_FLAGS)
            try:
                actual_etc = os.open("etc", DIRECTORY_FLAGS, dir_fd=root)
                try:
                    for row in rows:
                        name = row["path"].removeprefix("etc/")
                        expected = checked_bytes(
                            expected_etc, name, row["size"], row["mode"],
                            None, None, "signed-source account artifact")
                        if hashlib.sha256(expected).hexdigest() != row["sha256"]:
                            raise ValueError("signed-source account artifact bytes differ: " + name)
                        observed = checked_bytes(
                            actual_etc, name, row["size"], row["sysusers_generated_mode"],
                            row["expected_root_uid"], row["expected_root_gid"],
                            "produced root account")
                        if observed != expected:
                            raise ValueError("produced root account bytes differ: " + name)
                finally:
                    os.close(actual_etc)
            finally:
                os.close(root)
        finally:
            os.close(expected_etc)
    finally:
        os.close(expected_root)


def audit(metadata, archives, base_tree, profile, workspace, account_artifact):
    profile = profile_builder.checked_profile_path(profile, workspace)
    profile_report = profile_builder.verify_profile(
        metadata, archives, base_tree, profile, workspace)
    if (profile_report["status"] != profile_builder.STATUS
            or profile_report["package_install_configured"] is not False
            or profile_report["package_scripts_executed"] is not False
            or profile_report["root_directory_built"] is not False):
        raise ValueError("mkosi diagnostic profile changed acceptance status")
    receipt = accounts.verify(metadata, archives, workspace, account_artifact)
    if (receipt["status"] != "diagnostic-verified-guest-account-artifact-unbuilt"
            or receipt["independent_generation_runs_matched"] is not True
            or receipt["package_scripts_executed"] is not False
            or receipt["installed_rootfs_accounts_compared"] is not False
            or receipt["image_built"] is not False
            or receipt["private_mode_approved"] is not False):
        raise ValueError("signed-source account artifact changed acceptance status")
    output = profile.parent / (profile.name + "-output") / profile_builder.OUTPUT_NAME
    compare_files(output, account_artifact, receipt)
    return {
        "status": STATUS,
        "base_tree_sha256": profile_report["base_tree_sha256"],
        "account_output_sha256": {row["path"]: row["sha256"] for row in receipt["outputs"]},
        "signed_snapshot_rechecked": True,
        "account_artifact_regenerated_and_verified": True,
        "produced_root_account_bytes_modes_owners_compared": True,
        "package_install_configured": False,
        "package_scripts_executed": False,
        "post_mkosi_tree_audited": False,
        "disk_image_built": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("metadata", "archives", "base_tree", "profile", "workspace",
                 "account_artifact"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.metadata, args.archives, args.base_tree, args.profile,
                       args.workspace, args.account_artifact)
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "disk_image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
