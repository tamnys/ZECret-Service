"""Synthetic GPT/verity negatives; no fixture is production evidence."""

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import uuid
import zlib

import inspect_basetree_disk as diagnostic
import inspect_raw_gpt as gpt


SECTOR = 512
SECTORS = 256
ENTRY_COUNT = 128
ENTRY_SIZE = 128
TABLE_BYTES = ENTRY_COUNT * ENTRY_SIZE
KINDS = {label: kind for kind, label in gpt.TYPES.items()}


def synthetic_disk(*, extra_esp=False, overlap=False, writable=False,
                   ext4=True):
    image = bytearray(SECTOR * SECTORS)
    image[510:512] = b"\x55\xaa"
    struct.pack_into("<B3sB3sII", image, 446, 0, bytes(3), 0xee,
                     bytes(3), 1, SECTORS - 1)
    entries = bytearray(TABLE_BYTES)
    parts = [("root-x86-64", 40, 79, uuid.UUID(hex="11" * 16)),
             ("root-x86-64-verity", 70 if overlap else 80, 119,
              uuid.UUID(hex="22" * 16))]
    if extra_esp:
        parts.append(("esp", 120, 159, uuid.UUID(hex="33" * 16)))
    for index, (kind, start, end, part_id) in enumerate(parts):
        flags = 0 if writable and index == 0 else gpt.READ_ONLY_FLAG
        struct.pack_into("<16s16sQQQ", entries, index * ENTRY_SIZE,
                         KINDS[kind].bytes_le, part_id.bytes_le,
                         start, end, flags)
    table_crc = zlib.crc32(entries)
    primary_table = 2
    backup_table = SECTORS - 1 - TABLE_BYTES // SECTOR
    image[primary_table * SECTOR:primary_table * SECTOR + TABLE_BYTES] = entries
    image[backup_table * SECTOR:backup_table * SECTOR + TABLE_BYTES] = entries
    for current, alternate, table in ((1, SECTORS - 1, primary_table),
                                      (SECTORS - 1, 1, backup_table)):
        offset = current * SECTOR
        gpt.HEADER.pack_into(image, offset, b"EFI PART", 0x10000,
                             gpt.HEADER.size, 0, 0, current, alternate,
                             34, backup_table - 1,
                             uuid.UUID(int=42).bytes_le, table,
                             ENTRY_COUNT, ENTRY_SIZE, table_crc)
        struct.pack_into("<I", image, offset + 16,
                         zlib.crc32(image[offset:offset + gpt.HEADER.size]))
    if ext4:
        image[40 * SECTOR + 1024 + 56:40 * SECTOR + 1024 + 58] = b"\x53\xef"
    return image


class DiskInspectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-verity-disk-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.path = self.scratch / "disk.raw"

    def layout(self, image):
        self.path.write_bytes(image)
        return diagnostic.disk_layout(self.path, hashlib.sha256(image).hexdigest(),
                                      len(image), SECTOR)

    def test_exact_two_partition_gpt_is_diagnostic_only(self):
        report = self.layout(synthetic_disk())
        self.assertEqual(report["status"], "diagnostic-two-partition-gpt-unapproved")
        self.assertEqual({part["type"] for part in report["partitions"]},
                         diagnostic.KINDS)
        self.assertEqual(report["gpt_copies_checked"], 2)
        self.assertTrue(report["root_ext4_magic_checked"])
        self.assertEqual(diagnostic.reconstructed_roothash(report),
                         "11" * 16 + "22" * 16)
        self.assertFalse(report["esp_included"])
        self.assertFalse(report["uki_included"])
        self.assertFalse(report["private_mode_approved"])

    def test_rejects_extra_boot_partition_overlap_writes_and_missing_ext4(self):
        for image in (synthetic_disk(extra_esp=True), synthetic_disk(overlap=True),
                      synthetic_disk(writable=True), synthetic_disk(ext4=False)):
            with self.assertRaises(ValueError):
                self.layout(image)

    def test_rejects_gpt_corruption_wrong_identity_and_redirect(self):
        original = synthetic_disk()
        for offset in (SECTOR + 16, (SECTORS - 1) * SECTOR + 16,
                       (SECTORS - 33) * SECTOR):
            changed = bytearray(original)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                self.layout(changed)
        self.path.write_bytes(original)
        with self.assertRaises(ValueError):
            diagnostic.disk_layout(self.path, "0" * 64, len(original), SECTOR)
        link = self.scratch / "redirect.raw"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            diagnostic.disk_layout(link, hashlib.sha256(original).hexdigest(),
                                   len(original), SECTOR)

    def test_mocked_verity_failure_cannot_return_success(self):
        image = synthetic_disk()
        self.path.write_bytes(image)
        digest = hashlib.sha256(image).hexdigest()
        toolchain = (b"synthetic", b"synthetic", (), {})

        def failed_verify(_toolchain, args, _scratch):
            if args[0] == "verify":
                raise ValueError("signed veritysetup operation failed")
            return "Hash type: 1\nData blocks: 5\nData block size: 4096\nHash block size: 4096\nHash algorithm: sha256\n"

        with (mock.patch.object(diagnostic.platform, "machine", return_value="x86_64"),
              mock.patch.object(diagnostic.verity, "authenticated_toolchain",
                                return_value=toolchain),
              mock.patch.object(diagnostic.verity.esp, "workspace_scratch",
                                return_value=self.scratch),
              mock.patch.object(diagnostic.verity, "run_verity",
                                side_effect=failed_verify)):
            with self.assertRaisesRegex(ValueError, "signed veritysetup"):
                diagnostic.inspect(self.path, digest, len(image), SECTOR,
                                   self.path, self.path, self.scratch, self.scratch)

    def test_cli_failure_remains_nonaccepting(self):
        image = synthetic_disk()
        self.path.write_bytes(image)
        with mock.patch.object(diagnostic, "inspect", side_effect=ValueError("synthetic rejected")):
            result = diagnostic.main([str(self.path), hashlib.sha256(image).hexdigest(),
                                      str(len(image)), str(SECTOR), "--inrelease",
                                      str(self.path), "--packages-index", str(self.path),
                                      "--archives", str(self.scratch), "--scratch",
                                      str(self.scratch)])
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
