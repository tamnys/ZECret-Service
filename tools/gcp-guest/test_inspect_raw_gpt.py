#!/usr/bin/env python3
"""Synthetic GPT only; the fixture has no EFI, UKI, rootfs, or verity data."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib


SPEC = importlib.util.spec_from_file_location("inspect_raw_gpt", Path(__file__).with_name("inspect_raw_gpt.py"))
gpt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gpt)

SECTOR = 512
SECTORS = 256
ENTRY_COUNT = 128
ENTRY_SIZE = 128
TABLE_BYTES = ENTRY_COUNT * ENTRY_SIZE
DISK_ID = uuid.UUID("831d38ce-3138-41f1-89ef-600762bb4be6")
TYPE_IDS = list(gpt.TYPES)


def synthetic_disk(*, extra=False, overlap=False, writable_root=False):
    disk = bytearray(SECTOR * SECTORS)
    disk[510:512] = b"\x55\xaa"
    struct.pack_into("<B3sB3sII", disk, 446, 0, bytes(3), 0xee, bytes(3), 1, SECTORS - 1)
    entries = bytearray(TABLE_BYTES)
    ranges = [(40, 79), (80 if not overlap else 70, 119), (120, 159)]
    for index, (kind, (first, last)) in enumerate(zip(TYPE_IDS, ranges)):
        flags = gpt.READ_ONLY_FLAG if index < 2 else 0
        if index == 0 and writable_root:
            flags = 0
        struct.pack_into("<16s16sQQQ", entries, index * ENTRY_SIZE,
                         kind.bytes_le, uuid.UUID(int=index + 1).bytes_le,
                         first, last, flags)
    if extra:
        struct.pack_into("<16s16sQQQ", entries, 3 * ENTRY_SIZE,
                         TYPE_IDS[2].bytes_le, uuid.UUID(int=4).bytes_le,
                         160, 170, 0)
    table_crc = zlib.crc32(entries)
    primary_table_lba = 2
    backup_table_lba = SECTORS - 1 - TABLE_BYTES // SECTOR
    disk[primary_table_lba * SECTOR:(primary_table_lba * SECTOR) + TABLE_BYTES] = entries
    disk[backup_table_lba * SECTOR:(backup_table_lba * SECTOR) + TABLE_BYTES] = entries
    for current, alternate, table in ((1, SECTORS - 1, primary_table_lba),
                                      (SECTORS - 1, 1, backup_table_lba)):
        offset = current * SECTOR
        gpt.HEADER.pack_into(disk, offset, b"EFI PART", 0x10000,
                             gpt.HEADER.size, 0, 0, current, alternate,
                             34, backup_table_lba - 1, DISK_ID.bytes_le,
                             table, ENTRY_COUNT, ENTRY_SIZE, table_crc)
        struct.pack_into("<I", disk, offset + 16,
                         zlib.crc32(disk[offset:offset + gpt.HEADER.size]))
    return disk


class RawGptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-gpt-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "disk.raw"

    def inspect(self, image):
        self.path.write_bytes(image)
        return gpt.inspect(self.path, hashlib.sha256(image).hexdigest(), len(image), SECTOR)

    def test_three_partition_gpt_is_diagnostic_only(self):
        report = self.inspect(synthetic_disk())
        self.assertEqual(report["status"], "diagnostic-gpt-only-unapproved")
        self.assertEqual([entry["type"] for entry in report["partitions"]],
                         ["root-x86-64", "root-x86-64-verity", "esp"])
        self.assertEqual(report["gpt_copies_checked"], 2)
        self.assertEqual(report["gpt_entry_size_bytes"], ENTRY_SIZE)
        for field in ("esp_contents_checked", "uki_checked", "dm_verity_checked",
                      "component_identity_checked", "private_mode_approved"):
            self.assertFalse(report[field])

    def test_synthetic_layout_agrees_with_maintained_partx(self):
        if not shutil.which("partx"):
            self.skipTest("read-only util-linux partx unavailable")
        self.inspect(synthetic_disk())
        result = subprocess.run(["partx", "--raw", "--noheadings",
                                 "--output", "TYPE,START,SECTORS", str(self.path)],
                                check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split() for line in result.stdout.splitlines()]
        self.assertEqual(rows, [[str(kind), str(start), "40"]
                                for kind, start in zip(TYPE_IDS, (40, 80, 120))])

    def test_rejects_corruption_hybrid_mbr_and_unreviewed_partitions(self):
        for image in (synthetic_disk(extra=True), synthetic_disk(overlap=True),
                      synthetic_disk(writable_root=True)):
            with self.assertRaises(ValueError):
                self.inspect(image)
        for offset in (SECTOR + 16, (SECTORS - 1) * SECTOR + 16,
                       (SECTORS - 33) * SECTOR):
            image = synthetic_disk()
            image[offset] ^= 1
            with self.assertRaises(ValueError):
                self.inspect(image)
        hybrid = synthetic_disk()
        hybrid[462 + 4] = 0x83
        with self.assertRaises(ValueError):
            self.inspect(hybrid)

    def test_requires_reviewed_identity_and_no_symlink(self):
        image = synthetic_disk()
        self.path.write_bytes(image)
        with self.assertRaises(ValueError):
            gpt.inspect(self.path, "0" * 64, len(image), SECTOR)
        with self.assertRaises(ValueError):
            gpt.inspect(self.path, hashlib.sha256(image).hexdigest(), len(image), 4096)
        link = Path(self.temporary.name) / "redirected.raw"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            gpt.inspect(link, hashlib.sha256(image).hexdigest(), len(image), SECTOR)

    def test_cli_rejection_is_nonaccepting(self):
        image = synthetic_disk()
        self.path.write_bytes(image)
        result = subprocess.run([sys.executable, str(Path(gpt.__file__)),
                                 str(self.path), "0" * 64, str(len(image)), str(SECTOR)],
                                check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual({"status": "blocked", "reason": "raw disk SHA-256 or GPT space differs",
                          "private_mode_approved": False}, json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
