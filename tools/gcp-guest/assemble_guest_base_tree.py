#!/usr/bin/env python3
"""Assemble a source-bound, script-free Debian root BaseTrees tar candidate.

This is package data, not an installed, bootable, measured, or approved guest.
The rootfs audit forbids SUID/SGID regular files, so that exact mode transform
is recorded for every affected file. No package control member is executed.
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
import preflight_guest_base_tree as preflight
import stage_builder_toolchain as builder
import verify_builder_closure as closure


STATUS = "diagnostic-signed-guest-root-basetree-candidate-unbuilt"
ARCHIVE = "guest-root.tar"
MANIFEST = "guest-root-manifest.json"
ROOT_MODE = 0o755
MAX_LINUX_ID = 0xfffffffe  # Linux's all-ones uid/gid is the invalid sentinel.


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def checked_owner(member, package):
    if (type(member.uid) is not int or type(member.gid) is not int
            or not 0 <= member.uid <= MAX_LINUX_ID
            or not 0 <= member.gid <= MAX_LINUX_ID):
        raise ValueError(f"invalid numeric guest payload owner: {package}:{member.name}")
    if member.pax_headers:
        # Extended attributes, capabilities and tar interpretation overrides
        # need an explicit policy; silently dropping them changes the root.
        raise ValueError(f"unsupported guest payload PAX metadata: {package}:{member.name}")
    return member.uid, member.gid


def source_plan(authenticated):
    """Return an exact output inventory only after complete collision preflight."""
    names = [identity["name"] for identity, _ in authenticated]
    if names != sorted(set(names)):
        raise ValueError("guest package identities are not unique and sorted")
    payloads, effective = builder.payload_entries(
        [(identity["name"], data) for identity, data in authenticated],
        allow_hardlinks=True,
    )
    owners = {}
    roots = []
    regular_owners = {}
    hardlinks = []
    for identity, _ in authenticated:
        package = identity["name"]
        with tarfile.open(fileobj=io.BytesIO(payloads[package]), mode="r:xz") as contents:
            for member in contents:
                path = builder.member_path(member, allow_hardlink=True)
                owner = checked_owner(member, package)
                if path is None:
                    roots.append((owner, member.mode))
                    continue
                prior = owners.get(path)
                if prior is not None and prior != owner:
                    raise ValueError(f"conflicting numeric guest payload owner: {path}")
                owners[path] = owner
                if member.type == tarfile.REGTYPE:
                    regular_owners[(package, path)] = owner
                elif member.type == tarfile.LNKTYPE:
                    hardlinks.append((package, path,
                                      builder.checked_hardlink_target(member.linkname), owner))
    if roots and any(owner != (0, 0) or mode != ROOT_MODE for owner, mode in roots):
        raise ValueError("guest archive root directory metadata differs")
    for package, path, target, owner in hardlinks:
        if regular_owners.get((package, target)) != owner:
            raise ValueError(f"guest hardlink owner differs from target: {path}")
    entries = [{"path": ".", "kind": "directory", "uid": 0, "gid": 0,
                "source_mode": ROOT_MODE, "output_mode": ROOT_MODE,
                "packages": []}]
    for path, source in sorted(effective.items()):
        kind = "hardlink" if "hardlink_target" in source else source["kind"]
        source_mode = source["source_mode"]
        output_mode = (source_mode & ~0o6000
                       if kind in {"file", "hardlink"} else source_mode)
        uid, gid = owners[path]
        row = {"path": path, "kind": kind, "uid": uid, "gid": gid,
               "source_mode": source_mode, "output_mode": output_mode,
               "packages": source["packages"]}
        if output_mode != source_mode:
            row["mode_transform"] = "clear_regular_setuid_setgid"
        if kind in {"file", "hardlink"}:
            row.update(size=source["size"], sha256=source["sha256"])
        if kind == "symlink":
            row["target"] = source["target"]
        if kind == "hardlink":
            row["target"] = source["hardlink_target"]
        entries.append(row)
    return payloads, entries


def tar_header(row):
    path = row["path"]
    name = "./" if path == "." else "./" + path
    kind = row["kind"]
    if kind == "directory" and path != ".":
        name += "/"
    header = tarfile.TarInfo(name)
    header.type = {"directory": tarfile.DIRTYPE, "file": tarfile.REGTYPE,
                   "symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE}[kind]
    header.uid = row["uid"]
    header.gid = row["gid"]
    header.uname = ""
    header.gname = ""
    header.mode = row["output_mode"]
    header.mtime = 0
    if kind == "file":
        header.size = row["size"]
    elif kind == "symlink":
        header.linkname = row["target"]
    elif kind == "hardlink":
        header.linkname = "./" + row["target"]
    return header


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, count):
        data = self.stream.read(count)
        self.digest.update(data)
        self.size += len(data)
        return data


def write_archive(destination, authenticated, payloads, entries):
    by_path = {row["path"]: row for row in entries}
    written = set()
    directories = sorted((row for row in entries if row["kind"] == "directory"),
                         key=lambda row: (row["path"].count("/"), row["path"]))
    with tarfile.open(fileobj=destination, mode="w:", format=tarfile.PAX_FORMAT) as output:
        for row in directories:
            output.addfile(tar_header(row))
            written.add(row["path"])
        for identity, _ in authenticated:
            package = identity["name"]
            with tarfile.open(fileobj=io.BytesIO(payloads[package]), mode="r:xz") as source:
                pending = []
                for member in source:
                    path = builder.member_path(member, allow_hardlink=True)
                    if path is None or member.type == tarfile.DIRTYPE:
                        continue
                    row = by_path[path]
                    if row["packages"] != [package] or row["source_mode"] != member.mode:
                        raise ValueError("guest payload changed during archive assembly")
                    if member.type == tarfile.LNKTYPE:
                        pending.append(row)
                        continue
                    if member.type == tarfile.SYMTYPE:
                        if row["kind"] != "symlink" or row["target"] != member.linkname:
                            raise ValueError("guest symlink changed during archive assembly")
                        output.addfile(tar_header(row))
                    else:
                        if row["kind"] != "file":
                            raise ValueError("guest regular file changed during archive assembly")
                        stream = source.extractfile(member)
                        if stream is None:
                            raise ValueError("unreadable guest payload file")
                        reader = HashingReader(stream)
                        output.addfile(tar_header(row), reader)
                        if reader.size != row["size"] or reader.digest.hexdigest() != row["sha256"]:
                            raise ValueError("guest payload file changed during archive assembly")
                    if path in written:
                        raise ValueError(f"guest payload path written twice: {path}")
                    written.add(path)
                for row in pending:
                    if row["kind"] != "hardlink":
                        raise ValueError("guest hardlink changed during archive assembly")
                    if row["target"] not in written:
                        raise ValueError("guest hardlink target not written first")
                    output.addfile(tar_header(row))
                    if row["path"] in written:
                        raise ValueError(f"guest payload path written twice: {row['path']}")
                    written.add(row["path"])
    if written != set(by_path):
        raise ValueError("guest payload member missing from archive")


def source_manifest(authenticated, entries, archive_hash, archive_size):
    return {
        "schema_version": 1, "status": STATUS,
        "guest_package_closure_sha256": guest.prepare.PACKAGE_CLOSURE_SHA256,
        "signed_inrelease_sha256": guest.INRELEASE_SHA256,
        "signed_packages_index_sha256": guest.PACKAGES_SHA256,
        "packages": [{key: identity[key] for key in
                      ("name", "version", "architecture", "size", "sha256")}
                     for identity, _ in authenticated],
        "archive_name": ARCHIVE, "archive_sha256": archive_hash,
        "archive_size": archive_size, "entries": entries,
        "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
        "package_scripts_executed": False, "installed_closure_checked": False,
        "image_built": False, "boot_verified": False,
        "private_mode_approved": False,
    }


def require_hardlinks(inodes, hardlinks):
    for path, target in hardlinks:
        if inodes.get(path) != inodes.get(target) or target not in inodes:
            raise ValueError(f"extracted guest BaseTrees hardlink differs: {path}")


def assemble(metadata, archives, output, workspace):
    authenticated = preflight.authenticated_archives(Path(metadata), Path(archives))
    payloads, entries = source_plan(authenticated)
    output = Path(output)
    parent = builder.output_parent(Path(workspace), output)
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        root = os.open(output.name, builder.DIRECTORY_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        descriptor = os.open(ARCHIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        with os.fdopen(descriptor, "wb") as destination:
            write_archive(destination, authenticated, payloads, entries)
            destination.flush()
            os.fsync(destination.fileno())
        descriptor = os.open(ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=root)
        with os.fdopen(descriptor, "rb") as archive:
            observed = os.fstat(archive.fileno())
            archive_hash = hashlib.file_digest(archive, "sha256").hexdigest()
        manifest = source_manifest(authenticated, entries, archive_hash, observed.st_size)
        encoded = canonical_bytes(manifest)
        descriptor = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
        os.fsync(root)
    finally:
        os.close(root)
    return {"status": STATUS, "archive_sha256": archive_hash,
            "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "entry_count": len(entries), "package_count": len(authenticated),
            "transformed_regular_mode_count": sum("mode_transform" in row for row in entries),
            "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
            "package_scripts_executed": False, "image_built": False,
            "boot_verified": False, "private_mode_approved": False}


def verify(metadata, archives, artifact):
    authenticated = preflight.authenticated_archives(Path(metadata), Path(archives))
    _, entries = source_plan(authenticated)
    by_path = {row["path"]: row for row in entries}
    artifact = Path(artifact)
    directory = guest.open_directory(artifact, "guest BaseTrees candidate")
    try:
        fd = os.open(MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("guest BaseTrees manifest is not a regular file")
            maximum = len(canonical_bytes(source_manifest(
                authenticated, entries, "0" * 64, 0))) + 20
            manifest_bytes = stream.read(maximum + 1)
            if len(manifest_bytes) > maximum or stream.read(1):
                raise ValueError("guest BaseTrees manifest exceeds source-derived size")
        manifest = json.loads(manifest_bytes, object_pairs_hook=guest.prepare.unique_object)
        if canonical_bytes(manifest) != manifest_bytes:
            raise ValueError("guest BaseTrees manifest is not canonical JSON")
        fd = os.open(ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            archive_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(archive_stat.st_mode):
                raise ValueError("guest BaseTrees archive is not a regular file")
            observed_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            expected_manifest = source_manifest(authenticated, entries,
                                                observed_hash, archive_stat.st_size)
            if manifest_bytes != canonical_bytes(expected_manifest):
                raise ValueError("guest BaseTrees manifest differs from signed source plan or archive")
            stream.seek(0)
            observed = {}
            with tarfile.open(fileobj=stream, mode="r:") as tar:
                for member in tar:
                    path = builder.member_path(member, allow_hardlink=True)
                    if path is None:
                        path = "."
                    if path in observed:
                        raise ValueError(f"duplicate guest BaseTrees member: {path}")
                    row = by_path.get(path)
                    if row is None:
                        raise ValueError(f"unreviewed guest BaseTrees member: {path}")
                    expected = tar_header(row)
                    if (member.type != expected.type or member.uid != expected.uid
                            or member.gid != expected.gid or member.mode != expected.mode
                            or member.mtime != 0 or member.uname or member.gname
                            or member.linkname != expected.linkname or member.size != expected.size
                            or any(key not in {"path", "linkpath", "uid", "gid", "size"}
                                   for key in member.pax_headers)
                            or any(str(value) != str({"path": expected.name,
                                "linkpath": expected.linkname, "uid": expected.uid,
                                "gid": expected.gid, "size": expected.size}[key])
                                   for key, value in member.pax_headers.items())):
                        raise ValueError(f"guest BaseTrees metadata differs: {path}")
                    if row["kind"] == "file":
                        data = tar.extractfile(member)
                        if data is None:
                            raise ValueError(f"unreadable guest BaseTrees content: {path}")
                        digest = hashlib.sha256()
                        for chunk in iter(lambda: data.read(1024 * 1024), b""):
                            digest.update(chunk)
                        if digest.hexdigest() != row["sha256"]:
                            raise ValueError(f"guest BaseTrees content differs: {path}")
                    observed[path] = True
            if set(observed) != {row["path"] for row in entries}:
                raise ValueError("guest BaseTrees entries missing")
        if {item.name for item in artifact.iterdir()} != {ARCHIVE, MANIFEST}:
            raise ValueError("guest BaseTrees artifact contains unreviewed files")
    finally:
        os.close(directory)
    return {"status": STATUS, "entry_count": len(entries),
            "archive_sha256": manifest["archive_sha256"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
            "package_scripts_executed": False, "image_built": False,
            "boot_verified": False, "private_mode_approved": False}


def verify_extracted(metadata, archives, artifact, extracted):
    """Check an isolated GNU-tar extraction against authenticated archive data."""
    report = verify(metadata, archives, artifact)
    authenticated = preflight.authenticated_archives(Path(metadata), Path(archives))
    _, entries = source_plan(authenticated)
    extracted = Path(extracted)
    directory = guest.open_directory(extracted, "extracted guest BaseTrees root")
    try:
        observed = {"."}
        retained = Path(f"/proc/self/fd/{directory}")
        for parent, directories, files in os.walk(retained, followlinks=False):
            for name in directories + files:
                observed.add((Path(parent) / name).relative_to(retained).as_posix())
        if observed != {row["path"] for row in entries}:
            raise ValueError("extracted guest BaseTrees paths differ")
        inodes = {}
        hardlinks = []
        for row in entries:
            path = row["path"]
            if path == ".":
                actual = os.fstat(directory)
            else:
                with builder.parent_fd(directory, path) as parent:
                    actual = os.stat(path.rsplit("/", 1)[-1], dir_fd=parent,
                                     follow_symlinks=False)
            expected_kind = row["kind"]
            if (actual.st_uid != row["uid"] or actual.st_gid != row["gid"]
                    or not (stat.S_ISDIR(actual.st_mode) if expected_kind == "directory" else
                            stat.S_ISLNK(actual.st_mode) if expected_kind == "symlink" else
                            stat.S_ISREG(actual.st_mode))
                    or (expected_kind != "symlink" and
                        stat.S_IMODE(actual.st_mode) != row["output_mode"])):
                raise ValueError(f"extracted guest BaseTrees metadata differs: {path}")
            if expected_kind == "symlink":
                with builder.parent_fd(directory, path) as parent:
                    if os.readlink(path.rsplit("/", 1)[-1], dir_fd=parent) != row["target"]:
                        raise ValueError(f"extracted guest BaseTrees link differs: {path}")
            elif expected_kind in {"file", "hardlink"}:
                if actual.st_size != row["size"]:
                    raise ValueError(f"extracted guest BaseTrees file size differs: {path}")
                with builder.parent_fd(directory, path) as parent:
                    fd = os.open(path.rsplit("/", 1)[-1], os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_CLOEXEC, dir_fd=parent)
                    with os.fdopen(fd, "rb") as stream:
                        if hashlib.file_digest(stream, "sha256").hexdigest() != row["sha256"]:
                            raise ValueError(f"extracted guest BaseTrees content differs: {path}")
                inodes[path] = (actual.st_dev, actual.st_ino)
                if expected_kind == "hardlink":
                    hardlinks.append((path, row["target"]))
        require_hardlinks(inodes, hardlinks)
    finally:
        os.close(directory)
    report["extracted_numeric_owners_checked"] = True
    report["extracted_contents_checked"] = True
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble", "verify", "verify-extracted"))
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--extracted", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "assemble":
            workspace = args.workspace or Path(os.environ["CODEX_WORKSPACE_DIR"])
            report = assemble(args.metadata, args.archives, args.artifact, workspace)
        elif args.command == "verify":
            report = verify(args.metadata, args.archives, args.artifact)
        elif args.extracted is None:
            raise ValueError("--extracted is required for verify-extracted")
        else:
            report = verify_extracted(args.metadata, args.archives,
                                      args.artifact, args.extracted)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
