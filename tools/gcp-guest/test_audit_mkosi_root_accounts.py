"""Synthetic rejection tests for the produced mkosi root account checkpoint."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import audit_mkosi_root_accounts as audit


class ProducedRootAccountTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mkosi-root-accounts-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.profile = self.workspace / "profile"
        self.root = (self.workspace / "profile-output" /
                     audit.profile_builder.OUTPUT_NAME)
        self.artifact = self.workspace / "expected-accounts"
        (self.root / "etc").mkdir(parents=True)
        (self.artifact / "etc").mkdir(parents=True)
        self.rows = []
        for name in audit.accounts.OUTPUT_FILES:
            data = (name + ":signed-source-bytes\n").encode()
            published_mode = 0o400 if name == "shadow" else 0o444
            generated_mode = 0o600 if name == "shadow" else 0o644
            expected = self.artifact / "etc" / name
            actual = self.root / "etc" / name
            expected.write_bytes(data)
            actual.write_bytes(data)
            expected.chmod(published_mode)
            actual.chmod(generated_mode)
            self.rows.append({
                "path": "etc/" + name, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": published_mode, "sysusers_generated_mode": generated_mode,
                "expected_root_uid": os.geteuid(),
                "expected_root_gid": os.getegid(),
            })
        self.receipt = {
            "status": "diagnostic-verified-guest-account-artifact-unbuilt",
            "outputs": self.rows,
            "independent_generation_runs_matched": True,
            "package_scripts_executed": False,
            "installed_rootfs_accounts_compared": False,
            "image_built": False,
            "private_mode_approved": False,
        }
        self.profile_report = {
            "status": audit.profile_builder.STATUS,
            "base_tree_sha256": "a" * 64,
            "package_install_configured": False,
            "package_scripts_executed": False,
            "root_directory_built": False,
        }

    def run_audit(self):
        with (mock.patch.object(audit.profile_builder, "verify_profile",
                                return_value=self.profile_report) as verified_profile,
              mock.patch.object(audit.accounts, "verify",
                                return_value=self.receipt) as verified_accounts):
            report = audit.audit(self.workspace, self.workspace, self.workspace,
                                 self.profile, self.workspace, self.artifact)
        verified_profile.assert_called_once()
        verified_accounts.assert_called_once()
        return report

    def test_exact_bytes_generated_modes_and_numeric_owners_match(self):
        report = self.run_audit()
        self.assertEqual(report["status"], audit.STATUS)
        self.assertTrue(report["account_artifact_regenerated_and_verified"])
        self.assertTrue(report["produced_root_account_bytes_modes_owners_compared"])
        for field in ("post_mkosi_tree_audited", "disk_image_built",
                      "boot_verified", "private_mode_approved"):
            self.assertFalse(report[field])

    def test_changed_bytes_modes_and_owners_are_rejected(self):
        self.run_audit()
        for name in audit.accounts.OUTPUT_FILES:
            path = self.root / "etc" / name
            original = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            with self.subTest(name=name, mutation="bytes"):
                path.write_bytes(original + b"x")
                with self.assertRaisesRegex(ValueError, "metadata differs"):
                    self.run_audit()
                path.write_bytes(original)
            with self.subTest(name=name, mutation="mode"):
                path.chmod(0o666)
                with self.assertRaisesRegex(ValueError, "metadata differs"):
                    self.run_audit()
                path.chmod(mode)
            with self.subTest(name=name, mutation="owner"):
                row = next(row for row in self.rows if row["path"] == "etc/" + name)
                row["expected_root_uid"] = os.geteuid() + 1
                with self.assertRaisesRegex(ValueError, "metadata differs"):
                    self.run_audit()
                row["expected_root_uid"] = os.geteuid()
                row["expected_root_gid"] = os.getegid() + 1
                with self.assertRaisesRegex(ValueError, "metadata differs"):
                    self.run_audit()
                row["expected_root_gid"] = os.getegid()

    def test_same_size_byte_mutation_is_rejected(self):
        path = self.root / "etc/passwd"
        data = path.read_bytes()
        path.write_bytes(b"X" + data[1:])
        with self.assertRaisesRegex(ValueError, "produced root account bytes differ"):
            self.run_audit()

    def test_shadow_difference_reports_field_positions_without_contents(self):
        expected = b"root:!secret:20361:0:99999:7:::\n"
        observed = b"root:!secret:00000:0:99999:7:::\n"
        summary = audit.shadow_difference_summary(expected, observed)
        self.assertEqual(summary, "; differing_lines=1 differing_field_indexes=[2]")
        self.assertNotIn("secret", summary)
        self.assertNotIn("20361", summary)
        self.assertNotIn("00000", summary)

    def test_redirected_or_missing_output_is_rejected(self):
        group = self.root / "etc/group"
        group.unlink()
        group.symlink_to(self.artifact / "etc/group")
        with self.assertRaises(OSError):
            self.run_audit()
        group.unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_audit()

    def test_mutated_expected_artifact_or_inventory_is_rejected(self):
        expected = self.artifact / "etc/passwd"
        expected.chmod(0o600)
        expected.write_bytes(b"X" + expected.read_bytes()[1:])
        expected.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "signed-source account artifact bytes differ"):
            self.run_audit()
        self.rows.append(dict(self.rows[0]))
        with self.assertRaisesRegex(ValueError, "output inventory differs"):
            self.run_audit()

    def test_source_reverification_failure_stops_audit(self):
        with (mock.patch.object(audit.profile_builder, "verify_profile",
                                side_effect=ValueError("source changed")),
              mock.patch.object(audit.accounts, "verify") as verified_accounts):
            with self.assertRaisesRegex(ValueError, "source changed"):
                audit.audit(self.workspace, self.workspace, self.workspace,
                            self.profile, self.workspace, self.artifact)
            verified_accounts.assert_not_called()
        with (mock.patch.object(audit.profile_builder, "verify_profile",
                                return_value=self.profile_report),
              mock.patch.object(audit.accounts, "verify",
                                side_effect=ValueError("artifact changed"))):
            with self.assertRaisesRegex(ValueError, "artifact changed"):
                audit.audit(self.workspace, self.workspace, self.workspace,
                            self.profile, self.workspace, self.artifact)


if __name__ == "__main__":
    unittest.main()
