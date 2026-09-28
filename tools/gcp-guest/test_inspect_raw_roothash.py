#!/usr/bin/env python3
"""Synthetic inspector reports; no disk signature or hardware acceptance."""

import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import uuid

import inspect_raw_roothash as roothash
import prepare
import test_inspect_raw_gpt as gpt_fixture


RAW_SHA256 = "a" * 64
RAW_BYTES = 1024 * 1024
UKI_SHA256 = "b" * 64
ROOT = "12345678-1234-1234-1234-123456789abc"
HASHES = "abcdef01-2345-6789-abcd-ef0123456789"
ESP = str(uuid.UUID(int=3))
EXPECTED_ROOT_HASH = uuid.UUID(ROOT).hex + uuid.UUID(HASHES).hex
CMDLINE = f"roothash={EXPECTED_ROOT_HASH} {prepare.FIXED_KERNEL_CMDLINE}"


def reports():
    common = {"raw_disk_sha256": RAW_SHA256, "raw_disk_bytes": RAW_BYTES,
              "private_mode_approved": False}
    layout = {**common, "status": "diagnostic-gpt-only-unapproved",
              "gpt_copies_checked": 2, "sector_size": 512,
              "partitions": [
                  {"type": "root-x86-64", "partition_guid": ROOT},
                  {"type": "root-x86-64-verity", "partition_guid": HASHES},
                  {"type": "esp", "partition_guid": ESP},
              ]}
    boot = {**common, "status": "diagnostic-esp-uki-sections-unapproved",
            "uki_sha256": UKI_SHA256, "uki_cmdline_for_review": CMDLINE}
    verity = {**common, "status": "diagnostic-raw-root-verity-unapproved",
              "uki_sha256": UKI_SHA256, "uki_cmdline_for_review": CMDLINE,
              "root_partition_guid": ROOT, "verity_partition_guid": HASHES,
              "verity_userspace_verified": True}
    return layout, boot, verity


class RootHashCrossCheckTests(unittest.TestCase):
    def setUp(self):
        self.layout, self.boot, self.verity = reports()

    def check(self):
        return roothash.inspect(self.layout, self.boot, self.verity,
                                RAW_SHA256, RAW_BYTES)

    def test_matches_exact_production_report_fields_but_never_approves(self):
        receipt = self.check()
        self.assertEqual(receipt["status"], roothash.STATUS)
        self.assertEqual(receipt["roothash"], EXPECTED_ROOT_HASH)
        self.assertEqual(receipt["uki_sha256"], UKI_SHA256)
        self.assertIs(receipt["fixed_cmdline_matched"], True)
        self.assertIs(receipt["gpt_roothash_matched"], True)
        self.assertIs(receipt["signed_uki_checked"], False)
        self.assertIs(receipt["private_mode_approved"], False)

    def test_accepts_actual_gpt_inspector_report_shape(self):
        image = gpt_fixture.synthetic_disk()
        with tempfile.TemporaryDirectory(
                prefix="synthetic-roothash-", dir=os.environ.get("CODEX_TMP_DIR")) as scratch:
            path = Path(scratch) / "disk.raw"
            path.write_bytes(image)
            disk_sha256 = hashlib.sha256(image).hexdigest()
            layout = gpt_fixture.gpt.inspect(
                path, disk_sha256, len(image), gpt_fixture.SECTOR)
        partitions = {row["type"]: uuid.UUID(row["partition_guid"])
                      for row in layout["partitions"]}
        cmdline = ("roothash=" + partitions["root-x86-64"].hex
                   + partitions["root-x86-64-verity"].hex
                   + " " + prepare.FIXED_KERNEL_CMDLINE)
        for report in (self.boot, self.verity):
            report["raw_disk_sha256"] = disk_sha256
            report["raw_disk_bytes"] = len(image)
            report["uki_cmdline_for_review"] = cmdline
        self.verity["root_partition_guid"] = str(partitions["root-x86-64"])
        self.verity["verity_partition_guid"] = str(partitions["root-x86-64-verity"])
        receipt = roothash.inspect(
            layout, self.boot, self.verity, disk_sha256, len(image))
        self.assertEqual(receipt["roothash"],
                         partitions["root-x86-64"].hex
                         + partitions["root-x86-64-verity"].hex)
        self.assertIs(receipt["private_mode_approved"], False)

    def test_missing_duplicate_wrong_roothash_and_altered_flags_fail(self):
        changed = (
            prepare.FIXED_KERNEL_CMDLINE,
            f"roothash={EXPECTED_ROOT_HASH} {CMDLINE}",
            f"roothash={'f' * 64} {prepare.FIXED_KERNEL_CMDLINE}",
            CMDLINE.replace("systemd.gpt_auto=0", "systemd.gpt_auto=1"),
            CMDLINE + " init=/bin/sh",
        )
        for cmdline in changed:
            with self.subTest(cmdline=cmdline):
                self.boot["uki_cmdline_for_review"] = cmdline
                with self.assertRaisesRegex(ValueError, "command line differs"):
                    self.check()
        self.boot["uki_cmdline_for_review"] = CMDLINE
        self.verity["uki_cmdline_for_review"] = CMDLINE + " debug"
        with self.assertRaisesRegex(ValueError, "command line differs"):
            self.check()

    def test_each_report_must_describe_the_same_explicit_raw_disk(self):
        for report in (self.layout, self.boot, self.verity):
            for field, changed in (("raw_disk_sha256", "c" * 64),
                                   ("raw_disk_bytes", RAW_BYTES + 1)):
                with self.subTest(report=report["status"], field=field):
                    original = report[field]
                    report[field] = changed
                    with self.assertRaisesRegex(ValueError, "raw disk identity"):
                        self.check()
                    report[field] = original
        with self.assertRaisesRegex(ValueError, "explicit raw disk identity"):
            roothash.inspect(self.layout, self.boot, self.verity,
                             "not-a-digest", RAW_BYTES)

    def test_rejects_mixed_uki_or_verity_gpt_pair(self):
        self.verity["uki_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "different UKIs"):
            self.check()
        self.verity["uki_sha256"] = UKI_SHA256
        self.verity["root_partition_guid"] = ESP
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.check()
        self.verity["root_partition_guid"] = ROOT
        self.verity["verity_userspace_verified"] = False
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.check()

    def test_rejects_duplicate_partition_or_noncanonical_guid(self):
        self.layout["partitions"][2]["type"] = "root-x86-64"
        with self.assertRaisesRegex(ValueError, "partition set differs"):
            self.check()
        self.layout, self.boot, self.verity = reports()
        self.layout["partitions"][2]["partition_guid"] = ROOT
        with self.assertRaisesRegex(ValueError, "partition set differs"):
            self.check()
        self.layout, self.boot, self.verity = reports()
        self.layout["partitions"][0]["partition_guid"] = ROOT.upper()
        with self.assertRaisesRegex(ValueError, "not canonical"):
            self.check()

    def test_requires_production_sector_size(self):
        self.layout["sector_size"] = 4096
        with self.assertRaisesRegex(ValueError, "GPT report is incomplete"):
            self.check()

    def test_rejects_noninspector_or_claimed_approved_reports(self):
        for report in (self.layout, self.boot, self.verity):
            with self.subTest(report=report["status"]):
                altered = copy.deepcopy(report)
                altered["private_mode_approved"] = True
                original = report.copy()
                report.update(altered)
                with self.assertRaisesRegex(ValueError, "report status"):
                    self.check()
                report.clear()
                report.update(original)
        self.boot["status"] = "simulation"
        with self.assertRaisesRegex(ValueError, "report status"):
            self.check()


if __name__ == "__main__":
    unittest.main()
