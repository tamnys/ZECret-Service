#!/usr/bin/env python3
"""Inspect a hash-pinned, non-bootable BaseTrees root/verity raw disk.

The root hash reconstructed from GPT partition UUIDs is self-reported by the
disk, not a trusted boot commitment. A successful report proves local disk
shape and userspace dm-verity consistency only; it never approves a release.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
import tempfile
import uuid
import zlib

import inspect_raw_gpt as gpt
import inspect_raw_verity as verity


KINDS = {"root-x86-64", "root-x86-64-verity"}


def disk_layout(path, expected_sha256, expected_bytes, sector_size):
    if (not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or type(expected_bytes) is not int or expected_bytes <= 0
            or sector_size not in (512, 1024, 2048, 4096)):
        raise ValueError("explicit raw identity and supported sector size required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != expected_bytes
                or info.st_size % sector_size):
            raise ValueError("raw disk type or size differs")
        last_lba = info.st_size // sector_size - 1
        if last_lba < 3 or gpt.digest(descriptor, info.st_size) != expected_sha256:
            raise ValueError("raw disk SHA-256 or GPT space differs")
        gpt.protective_mbr(descriptor, last_lba, sector_size)
        primary = gpt.header(descriptor, 1, sector_size, last_lba)
        backup = gpt.header(descriptor, last_lba, sector_size, last_lba)
        if primary[:3] != backup[:3] or primary[4:] != backup[4:]:
            raise ValueError("primary and backup GPT metadata differ")
        first, last, disk_id, primary_lba, count, entry_size, entries_crc = primary
        backup_lba = backup[3]
        checksum = 0
        for offset in range(0, count * entry_size, 1024 * 1024):
            length = min(1024 * 1024, count * entry_size - offset)
            one = gpt.read_at(descriptor, primary_lba * sector_size + offset, length)
            two = gpt.read_at(descriptor, backup_lba * sector_size + offset, length)
            if one != two:
                raise ValueError("primary and backup GPT entry arrays differ")
            checksum = zlib.crc32(one, checksum)
        if checksum != entries_crc:
            raise ValueError("GPT entry array CRC differs")
        partitions = []
        ids = set()
        for index in range(count):
            data = gpt.read_at(descriptor,
                               primary_lba * sector_size + index * entry_size, 128)
            kind = uuid.UUID(bytes_le=data[:16])
            if kind.int == 0:
                if any(data):
                    raise ValueError("unused GPT entry contains data")
                continue
            label = gpt.TYPES.get(kind)
            if label not in KINDS:
                raise ValueError("diagnostic disk contains an ESP or unreviewed partition")
            partition_id = uuid.UUID(bytes_le=data[16:32])
            start, end, flags = struct.unpack_from("<QQQ", data, 32)
            if (partition_id.int == 0 or partition_id in ids
                    or not first <= start <= end <= last
                    or not flags & gpt.READ_ONLY_FLAG):
                raise ValueError("GPT partition identity, extent, or read-only flag differs")
            ids.add(partition_id)
            partitions.append({"type": label, "type_guid": str(kind),
                               "partition_guid": str(partition_id),
                               "first_lba": start, "last_lba": end,
                               "attributes": flags})
        if len(partitions) != 2 or {part["type"] for part in partitions} != KINDS:
            raise ValueError("diagnostic GPT does not contain exactly root and verity")
        ordered = sorted(partitions, key=lambda item: item["first_lba"])
        if ordered[0]["last_lba"] >= ordered[1]["first_lba"]:
            raise ValueError("GPT partitions overlap")
        root = next(part for part in partitions if part["type"] == "root-x86-64")
        if (root["last_lba"] - root["first_lba"] + 1) * sector_size < 1024 + 58:
            raise ValueError("root partition cannot contain an ext4 superblock")
        ext4_offset = root["first_lba"] * sector_size + 1024 + 56
        if gpt.read_at(descriptor, ext4_offset, 2) != b"\x53\xef":
            raise ValueError("root partition lacks ext4 superblock magic")
        if (os.fstat(descriptor).st_size != expected_bytes
                or gpt.digest(descriptor, expected_bytes) != expected_sha256):
            raise ValueError("raw disk changed during inspection")
        return {"status": "diagnostic-two-partition-gpt-unapproved",
                "raw_disk_sha256": expected_sha256,
                "raw_disk_bytes": expected_bytes, "sector_size": sector_size,
                "disk_guid": str(uuid.UUID(bytes_le=disk_id)),
                "gpt_copies_checked": 2, "gpt_entry_size_bytes": entry_size,
                "partitions": partitions, "root_ext4_magic_checked": True,
                "esp_included": False, "uki_included": False,
                "private_mode_approved": False}
    finally:
        os.close(descriptor)


def reconstructed_roothash(layout):
    """DPS root/hash GUID halves; diagnostic until bound into signed UKI."""
    by_kind = {part["type"]: part for part in layout["partitions"]}
    root = uuid.UUID(by_kind["root-x86-64"]["partition_guid"])
    hashes = uuid.UUID(by_kind["root-x86-64-verity"]["partition_guid"])
    return root.hex + hashes.hex


def inspect(path, expected_sha256, expected_bytes, sector_size,
            inrelease, packages_index, archives, scratch):
    if platform.machine() != "x86_64":
        raise ValueError("reviewed Debian verity tools require x86_64 Linux")
    layout = disk_layout(path, expected_sha256, expected_bytes, sector_size)
    roothash = reconstructed_roothash(layout)
    if not re.fullmatch(r"[0-9a-f]{64}", roothash):
        raise ValueError("GPT partition UUID halves cannot form a root hash")
    toolchain = verity.authenticated_toolchain(inrelease, packages_index, archives)
    scratch = verity.esp.workspace_scratch(scratch)
    with tempfile.TemporaryDirectory(prefix="zrpc-basetree-verity-", dir=scratch) as directory:
        root = Path(directory)
        images = verity.partition_images(path, layout, expected_sha256,
                                          expected_bytes, sector_size, root)
        data_path, data_bytes, data_guid = images["root-x86-64"]
        hash_path, hash_bytes, hash_guid = images["root-x86-64-verity"]
        header = verity.verity_header(
            verity.run_verity(toolchain, ["dump", str(hash_path)], root), data_bytes)
        verity.run_verity(toolchain,
                          ["verify", str(data_path), str(hash_path), roothash], root)
        with data_path.open("rb") as data_file, hash_path.open("rb") as hash_file:
            data_sha256 = hashlib.file_digest(data_file, "sha256").hexdigest()
            hash_sha256 = hashlib.file_digest(hash_file, "sha256").hexdigest()
    return {"status": "diagnostic-no-boot-root-verity-inspected-unapproved",
            "raw_disk_sha256": expected_sha256, "raw_disk_bytes": expected_bytes,
            "sector_size": sector_size, "gpt_copies_checked": 2,
            "disk_guid": layout["disk_guid"], "root_partition_guid": data_guid,
            "partitions": layout["partitions"],
            "root_partition_bytes": data_bytes,
            "root_partition_sha256": data_sha256,
            "verity_partition_guid": hash_guid,
            "verity_partition_bytes": hash_bytes,
            "verity_partition_sha256": hash_sha256,
            "self_reported_gpt_roothash": roothash,
            "verity_header": header,
            "verity_userspace_verified": True,
            "signed_tool_archives_sha256": toolchain[3],
            "root_ext4_magic_checked": True,
            "esp_included": False, "uki_included": False,
            "trusted_roothash_bound_to_boot": False,
            "root_contents_approved": False,
            "disk_root_contents_audited": False,
            "boot_verified": False, "production_image_built": False,
            "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_disk", type=Path)
    parser.add_argument("expected_sha256")
    parser.add_argument("expected_bytes", type=int)
    parser.add_argument("sector_size", type=int)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect(args.raw_disk, args.expected_sha256,
                         args.expected_bytes, args.sector_size,
                         args.inrelease, args.packages_index,
                         args.archives, args.scratch)
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
