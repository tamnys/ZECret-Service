#!/usr/bin/env python3
"""Read-only GPT shape check for a hash-pinned GCP guest disk.raw.

This checks only the protective MBR, both GPT copies, and the three partition
types in the reviewed repart profile. It does not inspect ESP contents, the
UKI, dm-verity, filesystems, Secure Boot, or hardware. Its receipt cannot
authorize image import or private mode. GPT entry bytes beyond the standard
128-byte core are CRC/hash-bound but not semantically interpreted.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import uuid
import zlib


# UEFI GPT layout: https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html
# Partition types: https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
TYPES = {
    uuid.UUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709"): "root-x86-64",
    uuid.UUID("2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"): "root-x86-64-verity",
    uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"): "esp",
}
HEADER = struct.Struct("<8sIIIIQQQQ16sQIII")
READ_ONLY_FLAG = 1 << 60  # systemd-repart ReadOnly=yes and verity default.


def read_at(fd, offset, count):
    data = os.pread(fd, count, offset)
    if len(data) != count:
        raise ValueError("raw disk ends inside GPT metadata")
    return data


def digest(fd, size):
    result = hashlib.sha256()
    offset = 0
    while offset < size:
        block = read_at(fd, offset, min(1024 * 1024, size - offset))
        result.update(block)
        offset += len(block)
    return result.hexdigest()


def header(fd, lba, sector_size, last_lba):
    data = read_at(fd, lba * sector_size, sector_size)
    (magic, revision, length, checksum, reserved, current, alternate,
     first, last, disk_id, entries_lba, count, entry_size, entries_crc) = HEADER.unpack_from(data)
    if (magic != b"EFI PART" or revision != 0x10000 or
            not HEADER.size <= length <= sector_size or reserved != 0 or
            current != lba or alternate != (last_lba if lba == 1 else 1) or
            first > last or last >= last_lba or disk_id == bytes(16) or
            count == 0 or entry_size < 128 or entry_size % 8):
        raise ValueError("GPT header fields differ")
    checked = bytearray(data[:length])
    checked[16:20] = bytes(4)
    if zlib.crc32(checked) != checksum or any(data[length:]):
        raise ValueError("GPT header CRC or reserved bytes differ")
    array_sectors = (count * entry_size + sector_size - 1) // sector_size
    if (entries_lba < 2 or entries_lba + array_sectors > last_lba or
            (lba == 1 and entries_lba + array_sectors > first) or
            (lba == last_lba and entries_lba <= last)):
        raise ValueError("GPT entry array lies outside its reserved area")
    return (first, last, disk_id, entries_lba, count, entry_size, entries_crc)


def protective_mbr(fd, last_lba, sector_size):
    data = read_at(fd, 0, sector_size)
    if data[510:512] != b"\x55\xaa":
        raise ValueError("protective MBR signature absent")
    entries = [data[446 + i * 16:462 + i * 16] for i in range(4)]
    first = entries[0]
    if (first[0] != 0 or first[4] != 0xee or
            struct.unpack_from("<I", first, 8)[0] != 1 or
            struct.unpack_from("<I", first, 12)[0] != min(last_lba, 0xffffffff) or
            any(any(entry) for entry in entries[1:])):
        raise ValueError("hybrid or incomplete protective MBR")


def partitions(fd, first_lba, last_lba, table_offset, count, entry_size):
    found = []
    ids = set()
    for index in range(count):
        data = read_at(fd, table_offset + index * entry_size, 128)
        kind = uuid.UUID(bytes_le=data[:16])
        if kind.int == 0:
            if any(data):
                raise ValueError("unused GPT entry contains data")
            continue
        if kind not in TYPES:
            raise ValueError("unreviewed GPT partition type")
        partition_id = uuid.UUID(bytes_le=data[16:32])
        start, end, flags = struct.unpack_from("<QQQ", data, 32)
        if (partition_id.int == 0 or partition_id in ids or
                not first_lba <= start <= end <= last_lba or
                (TYPES[kind] in ("root-x86-64", "root-x86-64-verity") and
                 not flags & READ_ONLY_FLAG)):
            raise ValueError("GPT partition identity, extent, or read-only flag differs")
        ids.add(partition_id)
        found.append({"type": TYPES[kind], "type_guid": str(kind),
                      "partition_guid": str(partition_id), "first_lba": start,
                      "last_lba": end, "attributes": flags})
    if {entry["type"] for entry in found} != set(TYPES.values()) or len(found) != len(TYPES):
        raise ValueError("GPT does not contain exactly the reviewed three partitions")
    by_start = sorted(found, key=lambda entry: entry["first_lba"])
    if any(left["last_lba"] >= right["first_lba"]
           for left, right in zip(by_start, by_start[1:])):
        raise ValueError("GPT partitions overlap")
    return found


def inspect(path, expected_sha256, expected_bytes, sector_size):
    if (not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or
            type(expected_bytes) is not int or expected_bytes <= 0 or
            sector_size not in (512, 1024, 2048, 4096)):
        raise ValueError("explicit raw identity and supported sector size required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected_bytes or info.st_size % sector_size:
            raise ValueError("raw disk type or size differs")
        last_lba = info.st_size // sector_size - 1
        if last_lba < 3 or digest(fd, info.st_size) != expected_sha256:
            raise ValueError("raw disk SHA-256 or GPT space differs")
        protective_mbr(fd, last_lba, sector_size)
        primary = header(fd, 1, sector_size, last_lba)
        backup = header(fd, last_lba, sector_size, last_lba)
        if primary[:3] != backup[:3] or primary[4:] != backup[4:]:
            raise ValueError("primary and backup GPT metadata differ")
        first, last, disk_id, primary_lba, count, entry_size, entries_crc = primary
        backup_lba = backup[3]
        array_bytes = count * entry_size
        checksum = 0
        for offset in range(0, array_bytes, 1024 * 1024):
            length = min(1024 * 1024, array_bytes - offset)
            one = read_at(fd, primary_lba * sector_size + offset, length)
            two = read_at(fd, backup_lba * sector_size + offset, length)
            if one != two:
                raise ValueError("primary and backup GPT entry arrays differ")
            checksum = zlib.crc32(one, checksum)
        if checksum != entries_crc:
            raise ValueError("GPT entry array CRC differs")
        entries = partitions(fd, first, last, primary_lba * sector_size, count, entry_size)
        if os.fstat(fd).st_size != expected_bytes or digest(fd, expected_bytes) != expected_sha256:
            raise ValueError("raw disk changed during inspection")
        return {"status": "diagnostic-gpt-only-unapproved", "raw_disk_sha256": expected_sha256,
                "raw_disk_bytes": expected_bytes, "sector_size": sector_size,
                "disk_guid": str(uuid.UUID(bytes_le=disk_id)), "gpt_copies_checked": 2,
                "gpt_entry_size_bytes": entry_size, "partitions": entries,
                "esp_contents_checked": False,
                "uki_checked": False, "dm_verity_checked": False,
                "component_identity_checked": False, "private_mode_approved": False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_disk")
    parser.add_argument("expected_sha256")
    parser.add_argument("expected_bytes", type=int)
    parser.add_argument("sector_size", type=int,
                        help="reviewed systemd-repart sector size, with no implicit default")
    args = parser.parse_args()
    try:
        report = inspect(args.raw_disk, args.expected_sha256,
                         args.expected_bytes, args.sector_size)
    except (OSError, ValueError, struct.error) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
