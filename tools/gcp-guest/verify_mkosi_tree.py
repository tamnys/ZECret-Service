#!/usr/bin/env python3
"""Compare signed Debian mkosi source with one pinned upstream Git archive.

This is an offline source identity check. It does not authenticate an installed
toolchain, build an image, or approve private mode. The Git archive SHA-256 was
recorded after `git archive` of the exact commit and independent `git fsck`;
its tree ID is a reviewed identity, not a value inferred from a tar header.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import verify_mkosi_source as source


COMMIT = "54c625c380ef5500f17460981a3c67b109b6a847"
TREE = "f5d828707aa0b1bd0235c55e13f7d4b41dba409e"
GIT_ARCHIVE_SHA256 = "16a58d4aab33a8f28dc996dc4c816711686d1e58fa6af23131b8e84ff11917d0"
GIT_ARCHIVE_SIZE = 1536000
DEBIAN_ROOT = "mkosi-25.3"


def archive_entries(path, *, root=None, commit=None):
    """Inventory every archive entry without extracting or following links."""
    entries = {}
    with tarfile.open(path, "r:*") as archive:
        if commit is not None and archive.pax_headers.get("comment") != commit:
            raise ValueError("Git archive commit marker differs")
        for member in archive:
            name = member.name
            parts = name.split("/")
            if not name or name.startswith("/") or any(part in ("", ".", "..") for part in parts):
                raise ValueError("non-canonical or traversing archive path")
            if root is not None:
                if parts[0] != root:
                    raise ValueError("Debian archive root differs")
                parts = parts[1:]
                if not parts:
                    if not member.isdir():
                        raise ValueError("Debian archive root is not a directory")
                    continue
            elif parts[0] == DEBIAN_ROOT:
                # The reviewed Git archive has no enclosing release directory.
                raise ValueError("unexpected Git archive root")
            key = "/".join(parts)
            if key in entries:
                raise ValueError("duplicate archive path: " + key)
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("unreadable archive file: " + key)
                entry = ("file", member.mode, hashlib.file_digest(stream, "sha256").hexdigest())
            elif member.isdir():
                entry = ("directory", member.mode, None)
            elif member.issym():
                target = member.linkname
                if not target or target.startswith("/") or any(part in ("", ".", "..") for part in target.split("/")):
                    raise ValueError("traversing archive symlink: " + key)
                entry = ("symlink", member.mode, target)
            else:
                raise ValueError("special or hardlink archive entry: " + key)
            entries[key] = entry
    return entries


def compare(debian_orig, git_archive, *, git_digest=GIT_ARCHIVE_SHA256,
            git_size=GIT_ARCHIVE_SIZE, commit=COMMIT):
    if git_archive.is_symlink() or not git_archive.is_file():
        raise ValueError("Git archive is missing or redirected")
    if git_archive.stat().st_size != git_size or source.digest(git_archive) != git_digest:
        raise ValueError("Git archive differs from pinned exact-commit bytes")
    debian = archive_entries(debian_orig, root=DEBIAN_ROOT)
    upstream = archive_entries(git_archive, commit=commit)
    if not debian or not upstream:
        raise ValueError("empty source archive")
    if debian.keys() != upstream.keys():
        raise ValueError("Debian and Git archive paths differ")
    for path in sorted(debian):
        if debian[path] != upstream[path]:
            raise ValueError("Debian and Git archive metadata or content differs: " + path)
    return len(debian)


def verify(inrelease, sources_index, source_dir, git_archive,
           identities_path=source.IDENTITIES):
    identities = json.loads(identities_path.read_text(), object_pairs_hook=source.unique_object)
    if identities["mkosi_source"]["commit"] != COMMIT:
        raise ValueError("bundled mkosi Git commit differs from pinned identity")
    files = {name: source_dir / name for name in source.SOURCE_FILES}
    membership = source.verify(inrelease, sources_index, files, identities_path)
    if (membership.get("status") != "source-membership-verified-toolchain-unreviewed"
            or membership.get("image_built") is not False
            or membership.get("private_mode_approved") is not False):
        raise ValueError("Debian source membership was not established")
    count = compare(files["mkosi_25.3.orig.tar.gz"], git_archive)
    return {
        "status": "source-tree-matched-toolchain-unreviewed",
        "upstream_commit": COMMIT,
        "upstream_tree": TREE,
        "upstream_archive_sha256": GIT_ARCHIVE_SHA256,
        "debian_orig_sha256": source.digest(files["mkosi_25.3.orig.tar.gz"]),
        "matched_entries": count,
        "image_built": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--sources-index", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--git-archive", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.inrelease, args.sources_index, args.source_dir, args.git_archive)
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
