#!/usr/bin/env python3
"""Stage the reviewed builder .deb payloads as data, without installing them.

This checks the source-pinned closure lock and every local archive hash. Signed
snapshot membership is a separate prerequisite, established by
verify_builder_closure.py; this command does not run package maintainer scripts,
authenticate a runnable toolchain, build an image, or approve private mode.
"""

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tarfile

import debian_snapshot
import verify_builder_closure as closure
import verify_builder_packages as direct


MANIFEST = ".zrpc-builder-toolchain.json"
STATUS = "diagnostic-builder-payloads-staged-unbuilt"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def locked_archive(entry, directory_fd):
    """Read one exact .deb from a no-follow directory descriptor."""
    if (not isinstance(entry, dict) or set(entry) != closure.PACKAGE_FIELDS
            or not isinstance(entry["name"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", entry["name"])
            or type(entry["size"]) is not int or entry["size"] <= 0
            or not isinstance(entry["sha256"], str)
            or not debian_snapshot.HEX_SHA256.fullmatch(entry["sha256"])):
        raise ValueError("invalid reviewed builder archive identity")
    descriptor = os.open(entry["sha256"] + ".deb", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != entry["size"]:
            raise ValueError("builder archive size differs from reviewed lock")
        data = stream.read(entry["size"] + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    if (len(data) != entry["size"] or not data.startswith(b"!<arch>\n")
            or hashlib.sha256(data).hexdigest() != entry["sha256"]
            or identity(before) != identity(after)):
        raise ValueError("builder archive differs from reviewed lock")
    return data


def member_path(member):
    """Accept only canonical package paths used by the exact signed closure."""
    if member.name in {".", "./"} and member.type == tarfile.DIRTYPE:
        return None
    if not member.name.startswith("./"):
        raise ValueError("non-canonical builder payload path")
    path = member.name[2:].removesuffix("/")
    if (not path or path == MANIFEST or not path.isascii()
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or (member.name != "./" + path + ("/" if member.isdir() and member.name.endswith("/") else ""))):
        raise ValueError("unsafe builder payload path")
    if member.type not in {tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.SYMTYPE}:
        raise ValueError("builder payload contains a hardlink or special file")
    if (type(member.mode) is not int or member.mode < 0 or member.mode > 0o7777
            or member.size < 0 or (member.type != tarfile.REGTYPE and member.size != 0)):
        raise ValueError("invalid builder payload metadata")
    return path


def checked_link_target(path, target):
    if (not target or not target.isascii()
            or any(ord(character) < 32 or ord(character) == 127 for character in target)
            or target.startswith("//")):
        raise ValueError("unsafe builder payload symlink")
    components = [] if target.startswith("/") else path.split("/")[:-1]
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not components:
                raise ValueError("builder payload symlink escapes staged root")
            components.pop()
        else:
            components.append(part)
    return target


def payload_entries(packages):
    """Preflight every package and collision before creating an output tree."""
    entries = {}
    payloads = {}
    for package, archive in packages:
        payload = closure.deb_data_tar(archive)
        payloads[package] = payload
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as contents:
            for member in contents:
                path = member_path(member)
                if path is None:
                    continue
                kind = ("directory" if member.type == tarfile.DIRTYPE else
                        "file" if member.type == tarfile.REGTYPE else "symlink")
                record = {"path": path, "kind": kind, "source_mode": member.mode,
                          "staged_mode": (member.mode & 0o1777 if kind == "directory" else
                                          member.mode & 0o777 if kind == "file" else None),
                          "packages": [package]}
                if kind == "file":
                    stream = contents.extractfile(member)
                    if stream is None:
                        raise ValueError("unreadable builder payload file")
                    digest = hashlib.sha256()
                    size = 0
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(chunk)
                        digest.update(chunk)
                    if size != member.size:
                        raise ValueError("truncated builder payload file")
                    record.update(size=size, sha256=digest.hexdigest())
                elif kind == "symlink":
                    record["target"] = checked_link_target(path, member.linkname)
                prior = entries.get(path)
                if prior is not None:
                    if (kind != "directory" or prior["kind"] != "directory"
                            or prior["source_mode"] != member.mode):
                        raise ValueError("builder payload path collision")
                    prior["packages"].append(package)
                else:
                    entries[path] = record
    for path in entries:
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = entries.get("/".join(parts[:index]))
            if parent is None or parent["kind"] != "directory":
                raise ValueError("builder payload member has missing or symlink parent")
    return payloads, entries


@contextmanager
def parent_fd(root_fd, path):
    descriptor = os.dup(root_fd)
    try:
        for part in path.split("/")[:-1]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def output_parent(workspace, output):
    if (not output.is_absolute() or ".." in output.parts
            or not workspace.is_absolute() or workspace.is_symlink()):
        raise ValueError("builder output must be inside the managed workspace")
    workspace = workspace.resolve(strict=True)
    try:
        relative = output.relative_to(workspace)
    except ValueError as error:
        raise ValueError("builder output must be inside the managed workspace") from error
    if len(relative.parts) < 1:
        raise ValueError("builder output must be a new subdirectory")
    descriptor = os.open(workspace, DIRECTORY_FLAGS)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def casefold_collision(entries):
    observed = {}
    for path in entries:
        # Package paths above are restricted to ASCII, so lowercase is the
        # exact case fold relevant to this closure's observed PAM man pages.
        prior = observed.setdefault(path.lower(), path)
        if prior != path:
            return prior, path
    return None


def case_sensitive_directory(directory_fd):
    """Probe the output filesystem before staging distinct-cased paths."""
    prefix = ".zrpc-builder-case-" + secrets.token_hex(16)
    first = prefix + "a"
    second = prefix + "A"
    created = []
    try:
        for name in (first, second):
            try:
                descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                     dir_fd=directory_fd)
            except FileExistsError:
                if created:
                    return False
                raise
            os.close(descriptor)
            created.append(name)
        return True
    finally:
        for name in reversed(created):
            os.unlink(name, dir_fd=directory_fd)


def stage(archives, output, *, workspace=None, lock_path=closure.LOCK,
          lock_size=closure.LOCK_BYTES, lock_sha256=closure.LOCK_SHA256):
    lock_bytes = debian_snapshot.bounded_regular_bytes(lock_path, lock_size,
                                                        "builder closure lock")
    if len(lock_bytes) != lock_size or hashlib.sha256(lock_bytes).hexdigest() != lock_sha256:
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=direct.unique_object)
    if (not isinstance(lock, dict) or lock.get("status") !=
            "apt-resolved-candidate-unbuilt-unapproved" or not isinstance(lock.get("packages"), list)
            or not lock["packages"]):
        raise ValueError("unsupported builder closure lock")
    names = [entry.get("name") for entry in lock["packages"]]
    if names != sorted(set(names)):
        raise ValueError("builder closure package order or identity differs from review")
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("builder archive directory missing or redirected")
    archives_fd = os.open(archives, DIRECTORY_FLAGS)
    try:
        packages = [(entry["name"], locked_archive(entry, archives_fd))
                    for entry in lock["packages"]]
    finally:
        os.close(archives_fd)
    payloads, entries = payload_entries(packages)
    workspace = workspace or Path(os.environ["CODEX_WORKSPACE_DIR"])
    output = Path(output)
    parent = output_parent(Path(workspace), output)
    try:
        collision = casefold_collision(entries)
        if collision is not None and not case_sensitive_directory(parent):
            raise ValueError("builder payload requires a case-sensitive workspace: "
                             + " and ".join(collision))
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        root = os.open(output.name, DIRECTORY_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        directories = sorted((path for path, value in entries.items()
                              if value["kind"] == "directory"),
                             key=lambda path: (path.count("/"), path))
        for path in directories:
            with parent_fd(root, path) as directory:
                os.mkdir(path.rsplit("/", 1)[-1], mode=0o700, dir_fd=directory)
        written = set()
        for package, _ in packages:
            with tarfile.open(fileobj=io.BytesIO(payloads[package]), mode="r:xz") as contents:
                for member in contents:
                    path = member_path(member)
                    if path is None or member.type == tarfile.DIRTYPE:
                        continue
                    record = entries[path]
                    if record["packages"] != [package] or member.mode != record["source_mode"]:
                        raise ValueError("builder payload changed during staging")
                    with parent_fd(root, path) as directory:
                        name = path.rsplit("/", 1)[-1]
                        if member.type == tarfile.SYMTYPE:
                            if member.linkname != record["target"]:
                                raise ValueError("builder payload symlink changed during staging")
                            os.symlink(member.linkname, name, dir_fd=directory)
                        else:
                            stream = contents.extractfile(member)
                            if stream is None:
                                raise ValueError("unreadable builder payload file")
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
                                    raise ValueError("builder payload file changed during staging")
                                os.fchmod(destination.fileno(), record["staged_mode"])
                    written.add(path)
        if written != {path for path, value in entries.items() if value["kind"] != "directory"}:
            raise ValueError("builder payload member missing during staging")
        for path in reversed(directories):
            with parent_fd(root, path) as directory:
                os.chmod(path.rsplit("/", 1)[-1], entries[path]["staged_mode"],
                         dir_fd=directory, follow_symlinks=False)
        inventory = [entries[path] for path in sorted(entries)]
        manifest = {"schema_version": 1, "status": STATUS,
                    "builder_closure_lock_sha256": lock_sha256,
                    "snapshot": lock["snapshot"], "package_count": len(packages),
                    "entries": inventory, "signed_snapshot_rechecked": False,
                    "package_scripts_executed": False, "runtime_execution_verified": False,
                    "complete_builder_toolchain": False, "image_built": False,
                    "private_mode_approved": False}
        manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(manifest_bytes)
        current = os.stat(output, follow_symlinks=False)
        staged = os.fstat(root)
        if (current.st_dev, current.st_ino) != (staged.st_dev, staged.st_ino):
            raise ValueError("builder output changed during staging")
    finally:
        os.close(root)
    return {"status": STATUS, "builder_closure_lock_sha256": lock_sha256,
            "package_count": len(packages), "entry_count": len(entries),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "signed_snapshot_rechecked": False, "package_scripts_executed": False,
            "runtime_execution_verified": False, "complete_builder_toolchain": False,
            "image_built": False, "private_mode_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(stage(args.archives, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False, "image_built": False,
                          "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
