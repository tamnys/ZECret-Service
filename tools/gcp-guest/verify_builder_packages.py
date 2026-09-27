#!/usr/bin/env python3
"""Authenticate selected *direct* builder package archives, without installing them.

This does not inspect installed executable bytes, dynamic libraries, Python
dependencies, mkosi's Debian patches, or the complete builder dependency graph.
It cannot authorize an image build, deployment, or private queries.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

import debian_snapshot


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deploy/gcp/builder-direct-packages.lock.json"
IDENTITIES = ROOT / "deploy/gcp/guest/input-identities.json"
# These packages supply the principal mkosi, archive, partition, UKI, signing,
# verity, and import tools in the reviewed build path. Their transitive runtime
# dependencies and the remaining mkosi tools are deliberately out of scope.
DIRECT_PACKAGES = frozenset({
    "apt", "cryptsetup-bin", "dpkg", "gpgv", "gzip", "mkosi", "mount",
    "sbsigntool", "systemd-boot-efi", "systemd-boot-tools",
    "systemd-repart", "systemd-ukify", "tar", "util-linux", "zstd",
})
PACKAGE_FIELDS = {"name", "version", "architecture", "filename", "size", "sha256"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("required reviewed input missing or redirected")
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def verify(inrelease, packages_index, archive_dir, *, lock_path=LOCK,
           identities_path=IDENTITIES):
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ValueError("required reviewed input missing or redirected")
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes, object_pairs_hook=unique_object)
    identities = read_json(identities_path)
    snapshot = identities["downloaded_metadata"]["trixie_snapshot_candidate"]
    if (set(lock) != {"schema_version", "status", "snapshot", "packages"}
            or type(lock["schema_version"]) is not int or lock["schema_version"] != 1
            or lock["status"] != "candidate-unbuilt-unapproved"
            or lock["snapshot"] != snapshot["url"]
            or identities["mkosi_source"]["distribution_package_version"] != "25.3-7"):
        raise ValueError("builder package lock differs from reviewed source and snapshot")
    entries = lock["packages"]
    if not isinstance(entries, list) or len(entries) != len(DIRECT_PACKAGES):
        raise ValueError("direct builder package set incomplete")
    epoch, (index_hash, index_size), index_bytes = debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, snapshot["inrelease_sha256"],
    )
    if epoch != snapshot["signed_release_date_epoch"]:
        raise ValueError("signed Debian Release date differs from reviewed snapshot")
    if (index_hash != snapshot["main_binary_amd64_packages_xz_sha256"]
            or index_size != snapshot["main_binary_amd64_packages_xz_size"]
            or len(index_bytes) != index_size):
        raise ValueError("Debian package index differs from signed Release")
    snapshot_time = datetime.strptime(
        lock["snapshot"].rstrip("/").rsplit("/", 1)[-1], "%Y%m%dT%H%M%SZ"
    ).replace(tzinfo=timezone.utc)
    if epoch > int(snapshot_time.timestamp()):
        raise ValueError("signed Debian Release postdates selected snapshot")
    debian_snapshot.require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    if archive_dir.is_symlink() or not archive_dir.is_dir():
        raise ValueError("local builder archive directory missing or redirected")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    found = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != PACKAGE_FIELDS:
            raise ValueError("incomplete direct builder package identity")
        name = entry["name"]
        if name not in DIRECT_PACKAGES or name in found:
            raise ValueError("unexpected or duplicate direct builder package")
        found.add(name)
        if (not isinstance(entry["version"], str)
                or not isinstance(entry["architecture"], str)
                or not isinstance(entry["filename"], str)
                or not isinstance(entry["sha256"], str)):
            raise ValueError("invalid direct builder package identity")
        identity = (name, entry["version"], entry["architecture"])
        if entry["architecture"] not in {"amd64", "all"}:
            raise ValueError("wrong builder package architecture")
        record = records.get(identity)
        if record is None or any(str(entry[field]) != record.get(index_field) for field, index_field in (
                ("filename", "Filename"), ("size", "Size"), ("sha256", "SHA256"))):
            raise ValueError("direct builder package differs from signed index")
        filename = PurePosixPath(entry["filename"])
        if (filename.is_absolute() or not filename.parts or ".." in filename.parts or filename.parts[0] != "pool"
                or filename.suffix != ".deb" or type(entry["size"]) is not int
                or entry["size"] <= 0 or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ValueError("invalid direct builder archive metadata")
        archive = archive_dir / f'{entry["sha256"]}.deb'
        if archive.is_symlink():
            raise ValueError("local direct builder archive differs from signed index")
        try:
            descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise ValueError("local direct builder archive differs from signed index") from error
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != entry["size"]:
                raise ValueError("local direct builder archive differs from signed index")
            if stream.read(8) != b"!<arch>\n":
                raise ValueError("local direct builder archive is not a deb")
            stream.seek(0)
            if hashlib.file_digest(stream, "sha256").hexdigest() != entry["sha256"]:
                raise ValueError("local direct builder archive differs from signed index")
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("local direct builder archive changed during inspection")
    if found != DIRECT_PACKAGES:
        raise ValueError("direct builder package set incomplete")
    return {
        "schema_version": 1,
        "status": "direct-builder-archives-matched-signed-snapshot",
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "inrelease_sha256": snapshot["inrelease_sha256"],
        "packages_index_sha256": index_hash,
        "package_count": len(found),
        "complete_builder_toolchain": False,
        "image_built": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.inrelease, args.packages_index, args.archives), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False,
                          "image_built": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
