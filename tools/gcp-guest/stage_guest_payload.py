#!/usr/bin/env python3
"""Stage signed guest .deb payloads as inert data in a fresh tree.

The signed Debian index and exact archive hashes are checked offline before
preflight. Package scripts are never unpacked or run. The result is a payload
inventory, not an installed root filesystem, boot image, or approved release.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

import fetch_guest_closure as guest
import stage_builder_toolchain as builder
import verify_builder_closure as builder_closure


MANIFEST = ".zrpc-guest-payload.json"
STATUS = "diagnostic-signed-guest-payloads-staged-data-only"


def signed_packages(metadata, archives):
    # This invokes the staged gpgv and accepts only the source-reviewed guest
    # closure and the exact binary package records in the authenticated index.
    identities = guest.authenticated_packages(Path(metadata))
    archives_fd = guest.open_directory(Path(archives), "guest archive")
    try:
        packages = []
        for identity in identities:
            # The builder reader uses descriptor-relative O_NOFOLLOW and checks
            # the exact size, hash, ar magic, and file identity across the read.
            archive_identity = {key: identity[key]
                                for key in builder_closure.PACKAGE_FIELDS}
            packages.append((identity["name"],
                             builder.locked_archive(archive_identity, archives_fd)))
    finally:
        os.close(archives_fd)
    return packages


def canonical_hardlink_target(target):
    """Interpret a tar hardlink name from the archive root for audit only."""
    if not target or not target.isascii() or target.startswith("/"):
        return None
    path = target[2:] if target.startswith("./") else target
    if any(part in {"", ".", ".."} for part in path.split("/")):
        return None
    return path


def audit_unsupported_members(metadata, archives):
    """List every hardlink/special member without extracting any payload."""
    packages = signed_packages(metadata, archives)
    unsupported = []
    for package, archive in packages:
        payload = builder_closure.deb_data_tar(archive)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as contents:
            members = list(contents)
        regular = set()
        for member in members:
            if member.type == tarfile.REGTYPE:
                try:
                    regular.add(builder.member_path(member))
                except ValueError:
                    # The staging preflight will reject malformed regular
                    # members; they cannot count as safe hardlink targets.
                    pass
        for member in members:
            if member.type in {tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.SYMTYPE}:
                continue
            target = (canonical_hardlink_target(member.linkname)
                      if member.type == tarfile.LNKTYPE else None)
            unsupported.append({
                "package": package,
                "path": member.name,
                "tar_type_hex": member.type.hex(),
                "kind": "hardlink" if member.type == tarfile.LNKTYPE else "special",
                "target": member.linkname if member.type == tarfile.LNKTYPE else None,
                "canonical_target_path": target,
                "target_is_regular_in_package": target in regular if target is not None else False,
            })
    return {
        "status": ("diagnostic-unsupported-guest-payload-members-found"
                   if unsupported else "diagnostic-no-unsupported-guest-payload-members"),
        "package_count": len(packages), "unsupported_count": len(unsupported),
        "unsupported_members": unsupported,
        "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
        "payload_tree_staged": False, "installed_closure_checked": False,
        "package_scripts_executed": False, "runtime_execution_verified": False,
        "image_built": False, "private_mode_approved": False,
    }


def stage(metadata, archives, output, workspace):
    packages = signed_packages(metadata, archives)

    # The common preflight rejects traversals, hardlinks, special files,
    # escaping symlinks, file collisions, and symlink/missing parents before
    # the output directory exists. It also hashes every regular payload file.
    payloads, entries = builder.payload_entries(packages)
    if MANIFEST in entries:
        raise ValueError("guest payload collides with inventory")

    output = Path(output)
    parent = builder.output_parent(Path(workspace), output)
    try:
        collision = builder.casefold_collision(entries)
        if collision is not None and not builder.case_sensitive_directory(parent):
            raise ValueError("guest payload requires a case-sensitive workspace: "
                             + " and ".join(collision))
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        root = os.open(output.name, builder.DIRECTORY_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        directories = sorted((path for path, record in entries.items()
                              if record["kind"] == "directory"),
                             key=lambda path: (path.count("/"), path))
        for path in directories:
            with builder.parent_fd(root, path) as directory:
                os.mkdir(path.rsplit("/", 1)[-1], mode=0o700, dir_fd=directory)

        written = set()
        for package, _ in packages:
            with tarfile.open(fileobj=io.BytesIO(payloads[package]), mode="r:xz") as contents:
                for member in contents:
                    path = builder.member_path(member)
                    if path is None or member.type == tarfile.DIRTYPE:
                        continue
                    record = entries[path]
                    if record["packages"] != [package] or member.mode != record["source_mode"]:
                        raise ValueError("guest payload changed during staging")
                    with builder.parent_fd(root, path) as directory:
                        name = path.rsplit("/", 1)[-1]
                        if member.type == tarfile.SYMTYPE:
                            if member.linkname != record["target"]:
                                raise ValueError("guest symlink changed during staging")
                            os.symlink(member.linkname, name, dir_fd=directory)
                        else:
                            stream = contents.extractfile(member)
                            if stream is None:
                                raise ValueError("unreadable guest payload file")
                            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                                 dir_fd=directory)
                            with os.fdopen(descriptor, "wb") as destination:
                                digest = hashlib.sha256()
                                size = 0
                                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                    destination.write(chunk)
                                    digest.update(chunk)
                                    size += len(chunk)
                                if size != record["size"] or digest.hexdigest() != record["sha256"]:
                                    raise ValueError("guest payload changed during staging")
                                os.fchmod(destination.fileno(), record["staged_mode"])
                    written.add(path)
        if written != {path for path, record in entries.items()
                       if record["kind"] != "directory"}:
            raise ValueError("guest payload member missing during staging")
        for path in reversed(directories):
            with builder.parent_fd(root, path) as directory:
                os.chmod(path.rsplit("/", 1)[-1], entries[path]["staged_mode"],
                         dir_fd=directory, follow_symlinks=False)

        manifest = {
            "schema_version": 1, "status": STATUS,
            "guest_package_closure_sha256": guest.prepare.PACKAGE_CLOSURE_SHA256,
            "signed_inrelease_sha256": guest.INRELEASE_SHA256,
            "signed_packages_index_sha256": guest.PACKAGES_SHA256,
            "package_count": len(packages),
            "entries": [entries[path] for path in sorted(entries)],
            "signed_snapshot_rechecked": True,
            "archive_bytes_checked": True,
            "payload_tree_staged": True,
            "installed_closure_checked": False,
            "package_scripts_executed": False,
            "runtime_execution_verified": False,
            "image_built": False,
            "private_mode_approved": False,
        }
        manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(manifest_bytes)
        current = os.stat(output, follow_symlinks=False)
        staged = os.fstat(root)
        if (current.st_dev, current.st_ino) != (staged.st_dev, staged.st_ino):
            raise ValueError("guest output changed during staging")
    finally:
        os.close(root)
    return {"status": STATUS,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "package_count": len(packages), "entry_count": len(entries),
            "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
            "payload_tree_staged": True, "installed_closure_checked": False,
            "package_scripts_executed": False, "runtime_execution_verified": False,
            "image_built": False, "private_mode_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = stage(args.metadata, args.archives, args.output, args.workspace)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "payload_tree_staged": False,
                          "installed_closure_checked": False,
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
