#!/usr/bin/env python3
"""Synthetic root/verity checks; signed Debian artifacts are opt-in fixtures."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import inspect_raw_verity as verity
import test_inspect_raw_esp as esp_fixture


SECTOR = esp_fixture.SECTOR
ROOT_FIRST = 40
ROOT_LAST = 79
HASH_FIRST = 80
HASH_LAST = 119
PARTITION_BYTES = (ROOT_LAST - ROOT_FIRST + 1) * SECTOR


class RawVerityInspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="synthetic-verity-", dir=os.environ.get("CODEX_TMP_DIR"),
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def signed_inputs(self):
        return esp_fixture.EspInspectorTests.signed_inputs(self)

    def build_fixture(self, *, cmdline):
        return esp_fixture.EspInspectorTests.build_fixture(self, cmdline=cmdline)

    def test_header_requires_complete_partition_and_sha256(self):
        output = ("VERITY header information\nHash type: 1\nData blocks: 5\n"
                  "Data block size: 4096\nHash block size: 4096\n"
                  "Hash algorithm: sha256\n")
        report = verity.verity_header(output, PARTITION_BYTES)
        self.assertEqual(report["data_blocks"], 5)
        for changed in (output.replace("Data blocks: 5", "Data blocks: 4"),
                        output.replace("Hash algorithm: sha256", "Hash algorithm: sha512"),
                        output.replace("Hash type: 1", "Hash type: 0"),
                        output + "Data blocks: 5\n",
                        output.replace("Hash block size: 4096", "")):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    verity.verity_header(changed, PARTITION_BYTES)

    def test_cli_rejection_never_approves(self):
        result = subprocess.run(
            [sys.executable, str(Path(verity.__file__)),
             str(self.root / "missing.raw"), "0" * 64, "512", "512",
             "--inrelease", str(self.root / "missing-release"),
             "--packages-index", str(self.root / "missing-index"),
             "--archives", str(self.root), "--scratch", str(self.root)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "blocked")
        for field in ("complete_builder_toolchain", "verity_userspace_verified",
                      "image_built", "private_mode_approved"):
            self.assertIs(report[field], False)

    def signed_verity_partition_pair(self):
        inrelease, index, archives = self.signed_inputs()
        toolchain = verity.authenticated_toolchain(inrelease, index, archives)
        data = self.root / "synthetic-root.img"
        hashes = self.root / "synthetic-hash.img"
        data.write_bytes(bytes(range(256)) * (PARTITION_BYTES // 256))
        hashes.write_bytes(bytes(PARTITION_BYTES))
        output = verity.run_verity(
            toolchain, ["--hash=sha256", "format", str(data), str(hashes)], self.root,
        )
        match = re.search(r"^Root hash:\s*([0-9a-f]{64})\s*$", output, re.MULTILINE)
        if match is None:
            self.fail("signed veritysetup did not report a SHA-256 root hash")
        self.assertEqual(data.stat().st_size, PARTITION_BYTES)
        self.assertEqual(hashes.stat().st_size, PARTITION_BYTES)
        return data.read_bytes(), hashes.read_bytes(), match.group(1)

    def raw_fixture(self, data, hashes, cmdline):
        arguments = self.build_fixture(cmdline=cmdline)
        disk = arguments[0]
        raw = bytearray(disk.read_bytes())
        raw[ROOT_FIRST * SECTOR:(ROOT_LAST + 1) * SECTOR] = data
        raw[HASH_FIRST * SECTOR:(HASH_LAST + 1) * SECTOR] = hashes
        disk.write_bytes(raw)
        return (disk, hashlib.sha256(raw).hexdigest(), len(raw), SECTOR,
                *arguments[3:], self.root)

    def test_signed_pair_verifies_then_tampered_data_fails(self):
        data, hashes, root_hash = self.signed_verity_partition_pair()
        args = self.raw_fixture(
            data, hashes,
            f"roothash={root_hash} {esp_fixture.prepare.FIXED_KERNEL_CMDLINE}",
        )
        report = verity.inspect(*args)
        self.assertEqual(report["status"], "diagnostic-raw-root-verity-unapproved")
        self.assertTrue(report["verity_userspace_verified"])
        self.assertEqual(report["verity_header"]["data_blocks"], 5)
        for field in ("complete_builder_toolchain", "signed_uki_checked",
                      "cmdline_approved", "dm_verity_boot_checked", "image_built",
                      "private_mode_approved"):
            self.assertIs(report[field], False)
        original = args[0].read_bytes()
        damaged = bytearray(original)
        damaged[ROOT_FIRST * SECTOR] ^= 1
        args[0].write_bytes(damaged)
        with self.assertRaisesRegex(ValueError, "signed veritysetup operation failed"):
            verity.inspect(args[0], hashlib.sha256(damaged).hexdigest(),
                           *args[2:])
        damaged = bytearray(original)
        damaged[HASH_FIRST * SECTOR + 4096] ^= 1
        args[0].write_bytes(damaged)
        with self.assertRaisesRegex(ValueError, "signed veritysetup operation failed"):
            verity.inspect(args[0], hashlib.sha256(damaged).hexdigest(),
                           *args[2:])

    def test_signed_pair_rejects_wrong_uki_roothash(self):
        data, hashes, root_hash = self.signed_verity_partition_pair()
        wrong_hash = "0" * 64 if root_hash != "0" * 64 else "1" * 64
        args = self.raw_fixture(
            data, hashes,
            f"roothash={wrong_hash} {esp_fixture.prepare.FIXED_KERNEL_CMDLINE}",
        )
        with self.assertRaisesRegex(ValueError, "signed veritysetup operation failed"):
            verity.inspect(*args)

if __name__ == "__main__":
    unittest.main()
