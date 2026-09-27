"""Negative gates for the diagnostic initrd build preflight."""

import hashlib
from pathlib import Path
import unittest
from unittest import mock

import preflight_initrd_build as probe


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.metadata = Path("/synthetic/metadata")
        self.archives = Path("/synthetic/archives")
        self.artifact = Path("/synthetic/candidate")
        self.source = {
            "status": probe.initrd_input.STATUS,
            "archive_sha256": "a" * 64, "manifest_sha256": "b" * 64,
            "package_control_scripts_executed": False,
            "runtime_closure_verified": False, "initrd_built": False,
            "boot_verified": False, "private_mode_approved": False,
        }
        self.revision = "c" * 40
        self.binary = (b"\x7fELF\x02\x01" + bytes(10) + b"\x02\x00\x3e\x00" + bytes(44))
        self.receipt = {
            "status": "diagnostic-unsigned-x86_64-rust-inputs-unapproved",
            "artifacts": {"early_init": {"path": "early_init",
                                         "sha256": hashlib.sha256(self.binary).hexdigest()}},
            "reproduction_manifest_sha256": "d" * 64,
            "image_built": False, "private_mode_approved": False,
        }
        self.verify = mock.patch.object(probe.initrd_input, "verify",
                                        return_value=self.source)
        self.profile = mock.patch.object(probe.prepare, "validate_boot_profile")
        self.verify.start()
        self.profile.start()
        self.addCleanup(self.verify.stop)
        self.addCleanup(self.profile.stop)

    def test_missing_rust_receipt_keeps_build_blocked(self):
        with mock.patch.object(probe.rust_inputs, "inspect") as inspect:
            report = probe.preflight(self.metadata, self.archives, self.artifact)
        inspect.assert_not_called()
        self.assertEqual(report["status"], "blocked")
        self.assertIsNone(report["early_init_sha256"])
        for field in ("package_control_scripts_executed", "network_used_for_build",
                      "mkosi_executed", "initrd_built", "boot_verified",
                      "private_mode_approved"):
            self.assertIs(report[field], False)

    def test_bad_signed_source_never_reads_rust_receipt(self):
        with (mock.patch.object(probe.initrd_input, "verify",
                                side_effect=ValueError("signed source changed")),
              mock.patch.object(probe.rust_inputs, "inspect") as inspect):
            with self.assertRaisesRegex(ValueError, "signed source changed"):
                probe.preflight(self.metadata, self.archives, self.artifact,
                                Path("/synthetic/bundle"), self.revision)
        inspect.assert_not_called()

    def test_changed_source_status_rejects_before_receipt(self):
        self.source["initrd_built"] = True
        with mock.patch.object(probe.rust_inputs, "inspect") as inspect:
            with self.assertRaisesRegex(ValueError, "changed diagnostic state"):
                probe.preflight(self.metadata, self.archives, self.artifact,
                                Path("/synthetic/bundle"), self.revision)
        inspect.assert_not_called()

    def test_stale_commit_and_invalid_receipt_are_rejected(self):
        with mock.patch.object(probe.rust_inputs, "git_output",
                               return_value=("e" * 40).encode()):
            with self.assertRaisesRegex(ValueError, "selected source HEAD"):
                probe.preflight(self.metadata, self.archives, self.artifact,
                                Path("/synthetic/bundle"), self.revision)
        with (mock.patch.object(probe.rust_inputs, "git_output",
                                return_value=self.revision.encode()),
              mock.patch.object(probe.rust_inputs, "inspect",
                                side_effect=ValueError("two independent binary receipts do not match"))):
            with self.assertRaisesRegex(ValueError, "two independent"):
                probe.preflight(self.metadata, self.archives, self.artifact,
                                Path("/synthetic/bundle"), self.revision)

    def test_changed_early_init_rejects_even_if_receipt_exists(self):
        with (mock.patch.object(probe.rust_inputs, "git_output",
                                return_value=self.revision.encode()),
              mock.patch.object(probe.rust_inputs, "inspect", return_value=self.receipt),
              mock.patch.object(probe.rust_inputs, "regular_bytes",
                                return_value=self.binary + b"changed")):
            with self.assertRaisesRegex(ValueError, "early init differs"):
                probe.preflight(self.metadata, self.archives, self.artifact,
                                Path("/synthetic/bundle"), self.revision)

    def test_valid_receipt_remains_a_preflight_only(self):
        with (mock.patch.object(probe.rust_inputs, "git_output",
                                return_value=self.revision.encode()),
              mock.patch.object(probe.rust_inputs, "inspect", return_value=self.receipt),
              mock.patch.object(probe.rust_inputs, "regular_bytes",
                                return_value=self.binary)):
            report = probe.preflight(self.metadata, self.archives, self.artifact,
                                     Path("/synthetic/bundle"), self.revision)
        self.assertEqual(report["early_init_sha256"], self.receipt["artifacts"]["early_init"]["sha256"])
        self.assertIs(report["initrd_built"], False)
        self.assertIs(report["mkosi_executed"], False)


if __name__ == "__main__":
    unittest.main()
