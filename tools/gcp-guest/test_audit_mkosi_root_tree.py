"""Negative coverage for the non-accepting produced-root provenance check."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import audit_mkosi_root_tree as audit


def source_row(path, kind, mode, uid, gid, data=None, target=None):
    row = {"path": path, "kind": kind, "output_mode": mode,
           "uid": uid, "gid": gid}
    if kind in {"file", "hardlink"}:
        row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    if target is not None:
        row["target"] = target
    return row


class ProducedRootAuditTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mkosi-root-audit-",
                                                dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.profile = self.workspace / "profile"
        self.root = self.workspace / "profile-output" / audit.profile.OUTPUT_NAME
        self.root.mkdir(parents=True, mode=0o700)
        (self.root / "bin").mkdir(mode=0o755)
        (self.root / "etc").mkdir(mode=0o755)
        (self.root / "bin/runner").write_bytes(b"signed executable\n")
        (self.root / "bin/runner").chmod(0o755)
        (self.root / "etc/config").write_bytes(b"signed configuration\n")
        (self.root / "etc/config").chmod(0o644)
        (self.root / "bin/alias").symlink_to("runner")
        os.link(self.root / "bin/runner", self.root / "bin/runner-hardlink")
        for path in (self.root / "bin/runner", self.root / "etc/config",
                     self.root / "bin/alias", self.root / "bin", self.root / "etc",
                     self.root):
            os.utime(path, ns=(0, 0), follow_symlinks=False)
        uid, gid = os.getuid(), os.getgid()
        self.entries = [
            source_row(".", "directory", 0o700, uid, gid),
            source_row("bin", "directory", 0o755, uid, gid),
            source_row("etc", "directory", 0o755, uid, gid),
            source_row("bin/runner", "file", 0o755, uid, gid,
                       b"signed executable\n"),
            source_row("bin/runner-hardlink", "hardlink", 0o755, uid, gid,
                       b"signed executable\n", "bin/runner"),
            source_row("etc/config", "file", 0o644, uid, gid,
                       b"signed configuration\n"),
            source_row("bin/alias", "symlink", 0o777, uid, gid,
                       target="runner"),
        ]
        self.source = {
            "status": audit.base_tree.STATUS,
            "entry_count": len(self.entries),
            "archive_sha256": "a" * 64, "manifest_sha256": "b" * 64,
            "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
            "package_scripts_executed": False, "image_built": False,
            "boot_verified": False, "private_mode_approved": False,
        }
        self.pinned_profile = {
            "status": audit.profile.STATUS,
            "base_tree_sha256": self.source["archive_sha256"],
            "profile_manifest_sha256": "c" * 64,
            "package_install_configured": False,
            "package_scripts_executed": False,
            "root_directory_built": False, "disk_image_built": False,
            "boot_verified": False, "private_mode_approved": False,
        }

    def run_audit(self):
        with (mock.patch.object(audit.base_tree, "verify", return_value=self.source) as verified,
              mock.patch.object(audit.profile, "checked_profile_path",
                                return_value=self.profile),
              mock.patch.object(audit.profile, "verify_profile",
                                return_value=self.pinned_profile) as checked_profile,
              mock.patch.object(audit.preflight, "authenticated_archives",
                                return_value=["synthetic signed package"]),
              mock.patch.object(audit.base_tree, "source_plan",
                                return_value=(None, self.entries))):
            result = audit.audit(Path("/synthetic/metadata"),
                                 Path("/synthetic/archives"),
                                 Path("/synthetic/artifact"), self.profile,
                                 self.workspace)
        self.assertEqual(verified.call_count, 2)
        self.assertEqual(checked_profile.call_count, 2)
        return result

    @staticmethod
    def changed(result):
        return {(item["path"], item["difference"])
                for item in result["differences"]}

    def test_exact_source_baseline_is_still_not_boot_or_private_approval(self):
        result = self.run_audit()
        self.assertEqual(result["status"], audit.STATUS)
        self.assertEqual(result["differences"], [])
        self.assertTrue(result["source_baseline_exact"])
        self.assertEqual(result["signed_entry_count"], len(self.entries))
        self.assertEqual(result["produced_entry_count"], len(self.entries))
        for field in ("generated_effects_approved", "post_mkosi_tree_audited",
                      "mkosi_execution_verified", "disk_image_built",
                      "boot_verified", "private_mode_approved"):
            self.assertFalse(result[field])

    def test_added_executable_and_configuration_are_unapproved(self):
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "usr/local/bin/exec").write_bytes(b"unreviewed executable")
        (self.root / "usr/local/bin/exec").chmod(0o755)
        (self.root / "etc/other.conf").write_bytes(b"unreviewed configuration")
        result = self.run_audit()
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["source_baseline_exact"])
        self.assertIn(("usr/local/bin/exec", "added"), self.changed(result))
        self.assertIn(("etc/other.conf", "added"), self.changed(result))
        self.assertFalse(result["generated_effects_approved"])

    def test_changed_content_mode_and_link_target_are_reported(self):
        (self.root / "etc/config").write_bytes(b"changed configuration\n")
        (self.root / "bin/runner").chmod(0o700)
        (self.root / "bin/alias").unlink()
        (self.root / "bin/alias").symlink_to("/outside")
        changes = self.changed(self.run_audit())
        self.assertIn(("etc/config", "content"), changes)
        self.assertIn(("bin/runner", "mode"), changes)
        self.assertIn(("bin/alias", "link-target"), changes)

    def test_hardlink_break_and_owner_policy_drift_are_detected(self):
        (self.root / "bin/runner-hardlink").unlink()
        (self.root / "bin/runner-hardlink").write_bytes(b"signed executable\n")
        (self.root / "bin/runner-hardlink").chmod(0o755)
        next(row for row in self.entries if row["path"] == "etc/config")["uid"] += 1
        changes = self.changed(self.run_audit())
        self.assertIn(("bin/runner-hardlink", "hardlink"), changes)
        self.assertIn(("etc/config", "owner"), changes)

    def test_external_hardlink_to_signed_file_is_rejected(self):
        os.link(self.root / "etc/config", self.workspace / "mutable-alias")
        with self.assertRaisesRegex(ValueError, "outside hardlink: etc/config"):
            self.run_audit()

    def test_timestamp_and_xattr_drift_are_not_silent(self):
        os.utime(self.root / "etc/config", ns=(1_000_000_000, 1_000_000_000))
        self.assertIn(("etc/config", "mtime"), self.changed(self.run_audit()))
        os.utime(self.root / "etc/config", ns=(0, 0))
        os.setxattr(self.root / "etc/config", "user.zrpc-test", b"unreviewed")
        with self.assertRaisesRegex(ValueError, "extended attributes"):
            self.run_audit()

    def test_symlink_directory_cannot_redirect_tree_scan(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        (outside / "secret").write_text("outside-canary")
        (self.root / "etc/config").unlink()
        (self.root / "etc").rmdir()
        (self.root / "etc").symlink_to(outside)
        result = self.run_audit()
        self.assertIn(("etc", "kind"), self.changed(result))
        self.assertIn(("etc/config", "missing"), self.changed(result))
        self.assertNotIn("etc/secret", {item["path"] for item in result["differences"]})

    def test_signed_executable_replaced_by_link_is_not_opened(self):
        outside = self.root.parent / "outside-executable"
        outside.write_bytes(b"outside-canary")
        (self.root / "bin/runner-hardlink").unlink()
        (self.root / "bin/runner").unlink()
        (self.root / "bin/runner").symlink_to(outside)
        changes = self.changed(self.run_audit())
        self.assertIn(("bin/runner", "kind"), changes)
        self.assertIn(("bin/runner-hardlink", "missing"), changes)
        self.assertNotIn("outside-executable", {path for path, _ in changes})

    def test_forged_source_acceptance_is_rejected_before_tree_scan(self):
        self.source["private_mode_approved"] = True
        with (mock.patch.object(audit.base_tree, "verify", return_value=self.source),
              mock.patch.object(audit, "scan_root") as scan):
            with self.assertRaisesRegex(ValueError, "changed diagnostic state"):
                audit.audit(Path("/synthetic/metadata"), Path("/synthetic/archives"),
                            Path("/synthetic/artifact"), self.profile,
                            self.workspace)
        scan.assert_not_called()

    def test_redirected_mkosi_output_parent_is_rejected(self):
        relocated = self.workspace / "relocated-output"
        self.root.parent.rename(relocated)
        self.root.parent.symlink_to(relocated)
        with (mock.patch.object(audit.base_tree, "verify", return_value=self.source),
              mock.patch.object(audit.profile, "checked_profile_path",
                                return_value=self.profile),
              mock.patch.object(audit.profile, "verify_profile",
                                return_value=self.pinned_profile),
              mock.patch.object(audit.preflight, "authenticated_archives",
                                return_value=["synthetic signed package"]),
              mock.patch.object(audit.base_tree, "source_plan",
                                return_value=(None, self.entries))):
            with self.assertRaisesRegex(ValueError, "output directory is redirected"):
                audit.audit(Path("/synthetic/metadata"), Path("/synthetic/archives"),
                            Path("/synthetic/artifact"), self.profile,
                            self.workspace)

    def test_special_files_and_replaced_source_are_blocked(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaisesRegex(ValueError, "unsupported file type"):
            self.run_audit()
        (self.root / "pipe").unlink()
        with (mock.patch.object(audit.base_tree, "verify",
                                side_effect=(self.source, {**self.source,
                                                           "manifest_sha256": "c" * 64})),
              mock.patch.object(audit.profile, "checked_profile_path",
                                return_value=self.profile),
              mock.patch.object(audit.profile, "verify_profile",
                                return_value=self.pinned_profile),
              mock.patch.object(audit.preflight, "authenticated_archives",
                                return_value=["synthetic signed package"]),
              mock.patch.object(audit.base_tree, "source_plan",
                                return_value=(None, self.entries))):
            with self.assertRaisesRegex(ValueError, "changed during root scan"):
                audit.audit(Path("/synthetic/metadata"), Path("/synthetic/archives"),
                            Path("/synthetic/artifact"), self.profile,
                            self.workspace)

    def test_cli_failure_keeps_every_acceptance_flag_false(self):
        with (mock.patch.object(audit, "audit", side_effect=ValueError("source unavailable")),
              contextlib.redirect_stdout(io.StringIO()) as output):
            code = audit.main(["--metadata", "/synthetic/metadata",
                               "--archives", "/synthetic/archives",
                               "--artifact", "/synthetic/artifact",
                               "--profile", str(self.profile),
                               "--workspace", str(self.workspace)])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["post_mkosi_tree_audited"])
        self.assertFalse(result["private_mode_approved"])


if __name__ == "__main__":
    unittest.main()
