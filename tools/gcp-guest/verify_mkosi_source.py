#!/usr/bin/env python3
"""Verify the pinned mkosi source files against a signed Debian Sources index.

This authenticates archive membership only. It neither installs the toolchain
nor builds, signs, or approves a guest image.
"""

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import re
import sys

import debian_snapshot


ROOT = Path(__file__).resolve().parents[2]
IDENTITIES = ROOT / "deploy/gcp/guest/input-identities.json"
SOURCE_VERSION = "25.3-7"
SOURCE_DIRECTORY = "pool/main/m/mkosi"
SOURCE_FILES = {
    "mkosi_25.3-7.dsc": "mkosi_25.3-7.dsc_sha256",
    "mkosi_25.3.orig.tar.gz": "mkosi_25.3.orig.tar.gz_sha256_from_dsc",
    "mkosi_25.3-7.debian.tar.xz": "mkosi_25.3-7.debian.tar.xz_sha256_from_dsc",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate source identity field")
        result[key] = value
    return result


def source_record(index):
    """Find exactly one mkosi version in Debian's compressed Sources index."""
    found = None
    paragraph = {}
    current = None

    def finish():
        nonlocal found
        if paragraph.get("Package") == ["mkosi"] and paragraph.get("Version") == [SOURCE_VERSION]:
            if found is not None:
                raise ValueError("duplicate mkosi source record")
            found = dict(paragraph)

    with lzma.open(index, "rt", encoding="utf-8") as stream:
        for line in stream:
            if line == "\n":
                finish()
                paragraph = {}
                current = None
            elif line.startswith((" ", "\t")):
                if current is None:
                    raise ValueError("malformed Debian source continuation")
                paragraph[current].append(line.strip())
            else:
                if ":" not in line:
                    raise ValueError("malformed Debian source field")
                key, value = line.split(":", 1)
                if not key or key in paragraph:
                    raise ValueError("duplicate or empty Debian source field")
                current = key
                paragraph[key] = [value.strip()] if value.strip() else []
    if paragraph:
        finish()
    if found is None:
        raise ValueError("pinned mkosi source record absent")
    return found


def verify(inrelease, sources_index, source_files, identities_path=IDENTITIES):
    identities = json.loads(identities_path.read_text(), object_pairs_hook=unique_object)
    metadata = identities["downloaded_metadata"]
    snapshot = metadata["trixie_snapshot_candidate"]
    if identities["mkosi_source"]["distribution_package_version"] != SOURCE_VERSION:
        raise ValueError("mkosi package version differs from reviewed identity")
    if digest(inrelease) != snapshot["inrelease_sha256"]:
        raise ValueError("Debian InRelease differs from reviewed snapshot")
    debian_snapshot.verify_signature(inrelease)
    epoch, (signed_hash, signed_size) = debian_snapshot.release_fields(
        inrelease, debian_snapshot.SOURCE_INDEX_PATH
    )
    if epoch != snapshot["signed_release_date_epoch"]:
        raise ValueError("source index Release date differs from reviewed snapshot")
    if signed_hash != snapshot["main_source_sources_xz_sha256"] or signed_size != snapshot["main_source_sources_xz_size"]:
        raise ValueError("source index identity differs from reviewed snapshot")
    if sources_index.is_symlink() or not sources_index.is_file() or sources_index.stat().st_size != signed_size or digest(sources_index) != signed_hash:
        raise ValueError("Debian Sources index differs from signed Release")
    record = source_record(sources_index)
    if record.get("Directory") != [SOURCE_DIRECTORY]:
        raise ValueError("mkosi source directory differs")
    lines = record.get("Checksums-Sha256", [])
    signed_files = {}
    for line in lines:
        parts = line.split()
        if len(parts) != 3 or not SHA256.fullmatch(parts[0]) or not parts[1].isdigit() or parts[2] in signed_files:
            raise ValueError("malformed or duplicate mkosi source checksum")
        signed_files[parts[2]] = (parts[0], int(parts[1]))
    if set(signed_files) != set(SOURCE_FILES) or set(source_files) != set(SOURCE_FILES):
        raise ValueError("mkosi source file set differs")
    for name, manifest_key in SOURCE_FILES.items():
        path = source_files[name]
        sha, size = signed_files[name]
        if sha != metadata[manifest_key] or size <= 0 or path.name != name or path.is_symlink() or not path.is_file() or path.stat().st_size != size or digest(path) != sha:
            raise ValueError(f"mkosi source file differs from signed index: {name}")
    return {
        "status": "source-membership-verified-toolchain-unreviewed",
        "source_version": SOURCE_VERSION,
        "inrelease_sha256": snapshot["inrelease_sha256"],
        "sources_index_sha256": signed_hash,
        "source_file_sha256": {name: signed_files[name][0] for name in sorted(SOURCE_FILES)},
        "image_built": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--sources-index", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--identities", type=Path, default=IDENTITIES)
    args = parser.parse_args()
    try:
        files = {name: args.source_dir / name for name in SOURCE_FILES}
        report = verify(args.inrelease, args.sources_index, files, args.identities)
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, lzma.LZMAError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "image_built": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
