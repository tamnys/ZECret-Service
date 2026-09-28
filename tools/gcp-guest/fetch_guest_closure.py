#!/usr/bin/env python3
"""Stage and check the source-reviewed guest package closure.

The networked phase fetches exact source-pinned hashes without executing
packages. The offline phase checks the Debian signature, signed index
membership, and every cached archive, with no download path. Neither phase
installs packages, builds a guest image, or approves private mode.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import urllib.error

import debian_snapshot
import fetch_builder_closure as snapshot_fetch
import prepare


# These identities were read from the reviewed 2026-09-18 signed Debian
# snapshot. A different snapshot or guest package set requires source review.
SNAPSHOT = "https://snapshot.debian.org/archive/debian/20260918T000000Z/"
INRELEASE_SHA256 = "0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675"
PACKAGES_SHA256 = "7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498"
PACKAGES_SIZE = 9678380
SIGNED_RELEASE_EPOCH = 1789199741
MANIFEST_BYTES = 37074
FIELDS = {"name", "version", "architecture", "filename", "size", "sha256", "path"}
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def reviewed_manifest(path=prepare.PACKAGE_CLOSURE_LOCK,
                      expected_sha256=prepare.PACKAGE_CLOSURE_SHA256,
                      expected_bytes=MANIFEST_BYTES):
    data = debian_snapshot.bounded_regular_bytes(path, expected_bytes,
                                                  "guest package closure")
    if len(data) != expected_bytes or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("guest package closure differs from source-reviewed candidate")
    manifest = json.loads(data, object_pairs_hook=prepare.unique_object,
                          parse_constant=prepare.reject_nonfinite_constant)
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("guest package closure is empty")
    names = []
    for package in manifest:
        if (not isinstance(package, dict) or set(package) != FIELDS
                or not isinstance(package["name"], str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package["name"])
                or not isinstance(package["version"], str)
                or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~-]*", package["version"])
                or package["architecture"] not in {"amd64", "all"}
                or type(package["size"]) is not int or package["size"] <= 0
                or not isinstance(package["sha256"], str)
                or not debian_snapshot.HEX_SHA256.fullmatch(package["sha256"])
                or not isinstance(package["filename"], str)):
            raise ValueError("invalid reviewed guest package identity")
        filename = PurePosixPath(package["filename"])
        if (filename.is_absolute() or filename.as_posix() != package["filename"]
                or not filename.parts or filename.parts[0] != "pool"
                or ".." in filename.parts or filename.suffix != ".deb"
                or package["path"] != f'debs/{package["sha256"]}.deb'):
            raise ValueError("unsafe reviewed guest package path")
        names.append(package["name"])
    if names != sorted(set(names)):
        raise ValueError("guest package closure order or identity differs from review")
    return data, manifest


def open_directory(path, label):
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} directory missing or redirected")
    return os.open(path, DIRECTORY_FLAGS)


def reviewed_snapshot_time():
    snapshot_time = datetime.strptime(SNAPSHOT.rsplit("/", 2)[-2],
                                      "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    debian_snapshot.require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    return snapshot_time


def fetch_metadata(directory, *, open_url=None, manifest_path=prepare.PACKAGE_CLOSURE_LOCK,
                   manifest_sha256=prepare.PACKAGE_CLOSURE_SHA256,
                   manifest_bytes=MANIFEST_BYTES):
    reviewed_manifest(manifest_path, manifest_sha256, manifest_bytes)
    reviewed_snapshot_time()
    fd = open_directory(directory, "guest metadata")
    downloaded = reused = 0
    try:
        for name, suffix, expected_sha256, maximum in (
            ("InRelease", "dists/trixie/InRelease", INRELEASE_SHA256,
             debian_snapshot.MAX_INRELEASE_BYTES),
            ("Packages.xz", "dists/trixie/main/binary-amd64/Packages.xz",
             PACKAGES_SHA256, PACKAGES_SIZE),
        ):
            if snapshot_fetch.verified_metadata(fd, name, expected_sha256, maximum):
                reused += 1
                continue
            snapshot_fetch.download_metadata(
                fd, name, SNAPSHOT + suffix, expected_sha256, maximum,
                open_url=open_url,
            )
            if not snapshot_fetch.verified_metadata(fd, name, expected_sha256, maximum):
                raise ValueError("guest snapshot metadata missing after download")
            downloaded += 1
    finally:
        os.close(fd)
    return {"status": "diagnostic-guest-metadata-hashes-matched-signature-unchecked",
            "guest_package_closure_sha256": manifest_sha256,
            "downloaded_count": downloaded, "reused_count": reused,
            "signed_snapshot_rechecked": False, "package_scripts_executed": False,
            "image_built": False, "private_mode_approved": False}


def authenticated_packages(metadata, *, manifest_path=prepare.PACKAGE_CLOSURE_LOCK,
                           manifest_sha256=prepare.PACKAGE_CLOSURE_SHA256,
                           manifest_bytes=MANIFEST_BYTES):
    _, manifest = reviewed_manifest(manifest_path, manifest_sha256, manifest_bytes)
    snapshot_time = reviewed_snapshot_time()
    fd = open_directory(metadata, "guest metadata")
    try:
        # Resolve children through the retained descriptor so replacement of
        # the original directory path cannot switch the files being checked.
        held = Path(f"/proc/self/fd/{fd}")
        epoch, (index_hash, index_size), index_bytes = \
            debian_snapshot.authenticated_index_bytes(
                held / "InRelease", held / "Packages.xz", INRELEASE_SHA256,
            )
    finally:
        os.close(fd)
    if (epoch != SIGNED_RELEASE_EPOCH or epoch > int(snapshot_time.timestamp())
            or index_hash != PACKAGES_SHA256 or index_size != PACKAGES_SIZE):
        raise ValueError("signed guest snapshot differs from source-reviewed candidate")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    for package in (*manifest, *prepare.DISK_TOOL_PACKAGES.values()):
        record = records.get((package["name"], package["version"],
                              package["architecture"]))
        if record is None or any(str(package[field]) != record.get(index_field)
                                 for field, index_field in (("filename", "Filename"),
                                                            ("size", "Size"),
                                                            ("sha256", "SHA256"))):
            raise ValueError("guest package differs from signed Debian index")
    return manifest


def verify_index(metadata, *, manifest_path=prepare.PACKAGE_CLOSURE_LOCK,
                 manifest_sha256=prepare.PACKAGE_CLOSURE_SHA256,
                 manifest_bytes=MANIFEST_BYTES):
    packages = authenticated_packages(
        metadata, manifest_path=manifest_path, manifest_sha256=manifest_sha256,
        manifest_bytes=manifest_bytes,
    )
    return {"status": "diagnostic-guest-package-index-membership-only",
            "guest_package_closure_sha256": manifest_sha256,
            "signed_inrelease_sha256": INRELEASE_SHA256,
            "signed_packages_index_sha256": PACKAGES_SHA256,
            "package_count": len(packages), "signed_snapshot_rechecked": True,
            "archive_bytes_checked": False, "installed_closure_checked": False,
            "package_scripts_executed": False, "image_built": False,
            "private_mode_approved": False}


def prefetch_archives(archives, *, open_url=None,
                      manifest_path=prepare.PACKAGE_CLOSURE_LOCK,
                      manifest_sha256=prepare.PACKAGE_CLOSURE_SHA256,
                      manifest_bytes=MANIFEST_BYTES):
    _, packages = reviewed_manifest(manifest_path, manifest_sha256, manifest_bytes)
    reviewed_snapshot_time()
    fd = open_directory(archives, "guest archive")
    downloaded = reused = 0
    try:
        for package in (*packages, *prepare.DISK_TOOL_PACKAGES.values()):
            if snapshot_fetch.verify_cached(fd, package):
                reused += 1
                continue
            snapshot_fetch.download_one(fd, package, SNAPSHOT, open_url=open_url)
            if not snapshot_fetch.verify_cached(fd, package):
                raise ValueError("guest archive missing after download")
            downloaded += 1
    finally:
        os.close(fd)
    return {"status": "diagnostic-guest-archive-hashes-matched-signature-unchecked",
            "guest_package_closure_sha256": manifest_sha256,
            "package_count": len(packages), "downloaded_count": downloaded,
            "reused_count": reused, "signed_snapshot_rechecked": False,
            "archive_hashes_matched_source_lock": True,
            "installed_closure_checked": False,
            "package_scripts_executed": False, "image_built": False,
            "private_mode_approved": False}


def verify_cached_archives(metadata, archives, *,
                           manifest_path=prepare.PACKAGE_CLOSURE_LOCK,
                           manifest_sha256=prepare.PACKAGE_CLOSURE_SHA256,
                           manifest_bytes=MANIFEST_BYTES):
    packages = authenticated_packages(
        metadata, manifest_path=manifest_path, manifest_sha256=manifest_sha256,
        manifest_bytes=manifest_bytes,
    )
    fd = open_directory(archives, "guest archive")
    try:
        for package in (*packages, *prepare.DISK_TOOL_PACKAGES.values()):
            if not snapshot_fetch.verify_cached(fd, package):
                raise ValueError("guest archive absent from offline cache")
    finally:
        os.close(fd)
    return {"status": "diagnostic-guest-archives-matched-signed-snapshot-unbuilt",
            "guest_package_closure_sha256": manifest_sha256,
            "signed_inrelease_sha256": INRELEASE_SHA256,
            "signed_packages_index_sha256": PACKAGES_SHA256,
            "package_count": len(packages), "signed_snapshot_rechecked": True,
            "archive_bytes_checked": True, "installed_closure_checked": False,
            "package_scripts_executed": False, "image_built": False,
            "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    metadata = sub.add_parser("metadata")
    metadata.add_argument("--directory", required=True, type=Path)
    verification = sub.add_parser("verify-index")
    verification.add_argument("--metadata-directory", required=True, type=Path)
    prefetch = sub.add_parser("prefetch")
    prefetch.add_argument("--archives", required=True, type=Path)
    archives = sub.add_parser("verify-archives")
    archives.add_argument("--metadata-directory", required=True, type=Path)
    archives.add_argument("--archives", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "metadata":
            report = fetch_metadata(args.directory)
        elif args.command == "verify-index":
            report = verify_index(args.metadata_directory)
        elif args.command == "prefetch":
            report = prefetch_archives(args.archives)
        else:
            report = verify_cached_archives(args.metadata_directory, args.archives)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            urllib.error.URLError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
