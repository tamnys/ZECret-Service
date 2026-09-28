"""Negative coverage for the non-accepting produced-root provenance check."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
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
        self.account_artifact = self.workspace / "expected-accounts"
        self.root = self.workspace / "profile-output" / audit.profile.OUTPUT_NAME
        self.root.mkdir(parents=True, mode=0o700)
        (self.root / "bin").mkdir(mode=0o755)
        (self.root / "etc").mkdir(mode=0o755)
        (self.root / "usr/lib/sysusers.d").mkdir(parents=True, mode=0o755)
        (self.root / "bin/runner").write_bytes(b"signed executable\n")
        (self.root / "bin/runner").chmod(0o755)
        (self.root / "etc/config").write_bytes(b"signed configuration\n")
        (self.root / "etc/config").chmod(0o644)
        (self.root / "bin/alias").symlink_to("runner")
        os.link(self.root / "bin/runner", self.root / "bin/runner-hardlink")
        self.account_files = {
            "passwd": (b"synthetic passwd\n", 0o644),
            "group": (b"synthetic group\n", 0o644),
            "shadow": (b"synthetic shadow\n", 0o644),
        }
        self.project = b"synthetic project sysusers\n"
        for name, (data, mode) in self.account_files.items():
            path = self.root / "etc" / name
            path.write_bytes(data)
            path.chmod(mode)
            os.utime(path, ns=(0, 0))
        (self.root / "usr/lib/sysusers.d/zrpc.conf").write_bytes(self.project)
        (self.root / "usr/lib/sysusers.d/zrpc.conf").chmod(0o644)
        os.utime(self.root / "usr/lib/sysusers.d/zrpc.conf", ns=(0, 0))
        for path in (self.root / "bin/runner", self.root / "etc/config",
                     self.root / "bin/alias", self.root / "bin", self.root / "etc",
                     self.root / "usr/lib/sysusers.d", self.root / "usr/lib",
                     self.root / "usr", self.root):
            os.utime(path, ns=(0, 0), follow_symlinks=False)
        uid, gid = os.getuid(), os.getgid()
        self.entries = [
            source_row(".", "directory", 0o700, uid, gid),
            source_row("bin", "directory", 0o755, uid, gid),
            source_row("etc", "directory", 0o755, uid, gid),
            source_row("usr", "directory", 0o755, uid, gid),
            source_row("usr/lib", "directory", 0o755, uid, gid),
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
            "account_files_preseeded_from_signed_source": True,
            "committed_rootfs_overlay_included": False,
            "package_install_configured": False,
            "package_scripts_executed": False,
            "root_directory_built": False, "disk_image_built": False,
            "boot_verified": False, "private_mode_approved": False,
        }

    def run_audit(self):
        # The unit test runs without CAP_CHOWN; the real ExtraTrees tar owns
        # these paths as root. Preserve its parsing, then map only synthetic
        # overlay owners to this test process for the filesystem scan.
        compose = audit.expected_input_rows

        def local_owners(entries, account_tree, source_overlay=None):
            rows = compose(entries, account_tree, source_overlay)
            for row in rows:
                if row["path"] in audit.ACCOUNT_DIRECTORIES | audit.ACCOUNT_FILES:
                    row["uid"], row["gid"] = os.getuid(), os.getgid()
            return rows

        with (mock.patch.object(audit.base_tree, "verify", return_value=self.source) as verified,
              mock.patch.object(audit.profile, "checked_profile_path",
                                return_value=self.profile),
              mock.patch.object(audit.profile, "verify_profile",
                                return_value=self.pinned_profile) as checked_profile,
              mock.patch.object(audit.profile, "verified_account_files",
                                return_value=self.account_files),
              mock.patch.object(audit.profile, "project_sysusers_bytes",
                                return_value=self.project),
              mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES,
                              {"shadow": 0o644}),
              mock.patch.object(audit, "expected_input_rows",
                                side_effect=local_owners),
              mock.patch.object(audit.preflight, "authenticated_archives",
                                return_value=["synthetic signed package"]),
              mock.patch.object(audit.base_tree, "source_plan",
                                return_value=(None, self.entries))):
            result = audit.audit(Path("/synthetic/metadata"),
                                 Path("/synthetic/archives"),
                                 Path("/synthetic/artifact"),
                                 self.account_artifact, self.profile,
                                 self.workspace)
        self.assertEqual(verified.call_count, 2)
        self.assertEqual(checked_profile.call_count, 2)
        return result

    def test_account_overlay_has_only_reviewed_root_owned_paths(self):
        with mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES,
                             {"shadow": 0o644}):
            account_tree = audit.profile.account_tree_bytes(
                self.project, self.account_files)
            rows = audit.expected_input_rows(self.entries, account_tree)
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(set(by_path) - {row["path"] for row in self.entries},
                         {"usr/lib/sysusers.d", *audit.ACCOUNT_FILES})
        for path in audit.ACCOUNT_DIRECTORIES | audit.ACCOUNT_FILES:
            self.assertEqual((by_path[path]["uid"], by_path[path]["gid"]), (0, 0))
        self.assertEqual(by_path["etc/passwd"]["sha256"],
                         hashlib.sha256(self.account_files["passwd"][0]).hexdigest())

    def test_account_overlay_rejects_unreviewed_tar_member(self):
        source = audit.profile.account_tree_bytes(self.project, self.account_files)
        rewritten = io.BytesIO()
        with (tarfile.open(fileobj=io.BytesIO(source), mode="r:") as original,
              tarfile.open(fileobj=rewritten, mode="w:",
                           format=tarfile.USTAR_FORMAT) as changed):
            for member in original:
                changed.addfile(member, original.extractfile(member)
                                if member.isfile() else None)
            extra = tarfile.TarInfo("usr/local/bin/extra")
            extra.size = len(b"unexpected executable")
            extra.mode = 0o755
            changed.addfile(extra, io.BytesIO(b"unexpected executable"))
        with (mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES,
                              {"shadow": 0o644}),
              self.assertRaisesRegex(ValueError, "unreviewed path")):
            audit.expected_input_rows(self.entries, rewritten.getvalue())

    def test_source_overlay_links_are_expected_and_changed_targets_are_deltas(self):
        account_tree = audit.profile.account_tree_bytes(self.project, self.account_files)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
            for name in ("etc/systemd", "etc/systemd/system"):
                entry = tarfile.TarInfo(name)
                entry.type = tarfile.DIRTYPE
                entry.mode = 0o755
                archive.addfile(entry)
            entry = tarfile.TarInfo("etc/systemd/system/default.target")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/usr/lib/systemd/system/zrpc.target"
            entry.mode = 0o777
            archive.addfile(entry)
        with mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES, {"shadow": 0o644}):
            rows = audit.expected_input_rows(self.entries, account_tree, stream.getvalue())
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(by_path["etc/systemd/system/default.target"]["target"],
                         "/usr/lib/systemd/system/zrpc.target")
        (self.root / "etc/systemd/system").mkdir(parents=True)
        (self.root / "etc/systemd/system/default.target").symlink_to("/dev/null")
        observed = audit.scan_root(self.root)
        self.assertIn({"path": "etc/systemd/system/default.target",
                       "difference": "link-target"}, audit.differences(rows, observed))

    def test_committed_overlay_combines_with_signed_account_inputs(self):
        account_tree = audit.profile.account_tree_bytes(self.project, self.account_files)
        overlay = audit.profile.source_overlay_bytes(self.workspace)
        with mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES, {"shadow": 0o644}):
            rows = audit.expected_input_rows(self.entries, account_tree, overlay)
        by_path = {row["path"]: row for row in rows}
        self.assertEqual(by_path["etc/systemd/system/default.target"]["target"],
                         "/usr/lib/systemd/system/zrpc.target")
        for name in audit.profile.prepare.MASKS:
            self.assertEqual(by_path["etc/systemd/system/" + name]["target"],
                             "/dev/null")
        self.assertEqual(by_path["usr/lib/systemd/system/zrpc.target"]["sha256"],
                         hashlib.sha256((audit.profile.prepare.PROFILE /
                                         "rootfs/usr/lib/systemd/system/zrpc.target").read_bytes()).hexdigest())

    def test_only_exact_pinned_mkosi_shapes_get_source_consistency_evidence(self):
        expected = self.entries + [
            source_row("usr/lib/systemd", "directory", 0o755, 0, 0),
            source_row("usr/lib/systemd/systemd", "file", 0o755, 0, 0,
                       b"synthetic signed systemd"),
        ]
        observed = {
            "init": {"kind": "symlink", "uid": 0, "gid": 0, "mode": 0o777,
                     "mtime_ns": 0, "target": "/usr/lib/systemd/systemd"},
            "usr/lib/clock-epoch": {
                "kind": "file", "uid": 0, "gid": 0, "mode": 0o644,
                "mtime_ns": 0, "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(), "nlink": 1,
            },
        }
        changes = [{"path": path, "difference": "added"} for path in observed]
        effects = audit.source_consistent_unapproved_effects(expected, observed, changes)
        self.assertEqual({item["path"] for item in effects}, set(observed))
        self.assertTrue(all(item["security_review_required"] for item in effects))
        self.assertEqual(len(changes), 2)  # Raw differences are not consumed.

        changed = {path: dict(row) for path, row in observed.items()}
        changed["init"]["target"] = "/bin/sh"
        changed["usr/lib/clock-epoch"]["sha256"] = "0" * 64
        self.assertEqual(audit.source_consistent_unapproved_effects(
            expected, changed, changes), [])
        self.assertEqual(audit.source_consistent_unapproved_effects(
            [row for row in expected if row["path"] != "usr/lib/systemd/systemd"],
            observed, changes)[0]["path"], "usr/lib/clock-epoch")
        with mock.patch.object(audit.profile.prepare, "SOURCE_COMMIT", "different"):
            with self.assertRaisesRegex(ValueError, "source re-review"):
                audit.source_consistent_unapproved_effects(expected, observed, changes)

    def test_source_overlay_rejects_escaping_path(self):
        account_tree = audit.profile.account_tree_bytes(self.project, self.account_files)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
            entry = tarfile.TarInfo("../outside")
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b"x"))
        with (mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES,
                              {"shadow": 0o644}),
              self.assertRaisesRegex(ValueError, "noncanonical")):
            audit.expected_input_rows(self.entries, account_tree, stream.getvalue())

    @staticmethod
    def changed(result):
        return {(item["path"], item["difference"])
                for item in result["differences"]}

    def test_exact_source_baseline_is_still_not_boot_or_private_approval(self):
        result = self.run_audit()
        self.assertEqual(result["status"], audit.STATUS, result["differences"])
        self.assertEqual(result["differences"], [])
        self.assertTrue(result["authenticated_inputs_exact"])
        self.assertEqual(result["signed_base_entry_count"], len(self.entries))
        self.assertEqual(result["authenticated_input_entry_count"], len(self.entries) + 5)
        self.assertEqual(result["produced_entry_count"], len(self.entries) + 5)
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
        self.assertEqual(result["status"], audit.DELTA_STATUS)
        self.assertFalse(result["authenticated_inputs_exact"])
        self.assertIn(("usr/local/bin/exec", "added"), self.changed(result))
        self.assertIn(("etc/other.conf", "added"), self.changed(result))
        executable = next(item for item in result["difference_evidence"]
                          if item["path"] == "usr/local/bin/exec")
        self.assertIsNone(executable["expected"])
        self.assertEqual(executable["observed"]["sha256"],
                         hashlib.sha256(b"unreviewed executable").hexdigest())
        self.assertEqual(executable["observed"]["mode"], 0o755)
        self.assertNotIn("inode", executable["observed"])
        self.assertNotIn("unreviewed executable", json.dumps(result))
        self.assertFalse(result["generated_effects_approved"])

    def test_changed_signed_account_file_is_reported_as_delta(self):
        (self.root / "etc/passwd").write_bytes(b"changed synthetic passwd\n")
        result = self.run_audit()
        self.assertEqual(result["status"], audit.DELTA_STATUS)
        self.assertIn(("etc/passwd", "content"), self.changed(result))
        self.assertFalse(result["post_mkosi_tree_audited"])

    def test_changed_content_mode_and_link_target_are_reported(self):
        (self.root / "etc/config").write_bytes(b"changed configuration\n")
        (self.root / "bin/runner").chmod(0o700)
        (self.root / "bin/alias").unlink()
        (self.root / "bin/alias").symlink_to("/outside")
        result = self.run_audit()
        changes = self.changed(result)
        self.assertIn(("etc/config", "content"), changes)
        self.assertIn(("bin/runner", "mode"), changes)
        self.assertIn(("bin/alias", "link-target"), changes)
        link = next(item for item in result["difference_evidence"]
                    if item["path"] == "bin/alias")
        self.assertEqual(link["expected"]["target"], "runner")
        self.assertEqual(link["observed"]["target"], "/outside")
        self.assertFalse(result["generated_effects_approved"])

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
        for name in self.account_files:
            (self.root / "etc" / name).unlink()
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
                            Path("/synthetic/artifact"), self.account_artifact,
                            self.profile,
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
              mock.patch.object(audit.profile, "verified_account_files",
                                return_value=self.account_files),
              mock.patch.object(audit.profile, "project_sysusers_bytes",
                                return_value=self.project),
              mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES,
                              {"shadow": 0o644}),
              mock.patch.object(audit.preflight, "authenticated_archives",
                                return_value=["synthetic signed package"]),
              mock.patch.object(audit.base_tree, "source_plan",
                                return_value=(None, self.entries))):
            with self.assertRaisesRegex(ValueError, "output directory is redirected"):
                audit.audit(Path("/synthetic/metadata"), Path("/synthetic/archives"),
                            Path("/synthetic/artifact"), self.account_artifact,
                            self.profile,
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
              mock.patch.object(audit.profile, "verified_account_files",
                                return_value=self.account_files),
              mock.patch.object(audit.profile, "project_sysusers_bytes",
                                return_value=self.project),
              mock.patch.dict(audit.profile.INSTALLED_ACCOUNT_MODES,
                              {"shadow": 0o644}),
              mock.patch.object(audit.preflight, "authenticated_archives",
                                return_value=["synthetic signed package"]),
              mock.patch.object(audit.base_tree, "source_plan",
                                return_value=(None, self.entries))):
            with self.assertRaisesRegex(ValueError, "changed during root scan"):
                audit.audit(Path("/synthetic/metadata"), Path("/synthetic/archives"),
                            Path("/synthetic/artifact"), self.account_artifact,
                            self.profile,
                            self.workspace)

    def test_cli_failure_keeps_every_acceptance_flag_false(self):
        with (mock.patch.object(audit, "audit", side_effect=ValueError("source unavailable")),
              contextlib.redirect_stdout(io.StringIO()) as output):
            code = audit.main(["--metadata", "/synthetic/metadata",
                               "--archives", "/synthetic/archives",
                               "--artifact", "/synthetic/artifact",
                               "--account-artifact", str(self.account_artifact),
                               "--profile", str(self.profile),
                               "--workspace", str(self.workspace)])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["post_mkosi_tree_audited"])
        self.assertFalse(result["private_mode_approved"])

    def test_cli_unreviewed_delta_succeeds_only_as_diagnostic(self):
        (self.root / "etc/config").write_bytes(b"changed")
        report = self.run_audit()
        self.assertEqual(report["status"], audit.DELTA_STATUS)
        with (mock.patch.object(audit, "audit", return_value=report),
              contextlib.redirect_stdout(io.StringIO()) as output):
            code = audit.main(["--metadata", "/synthetic/metadata",
                               "--archives", "/synthetic/archives",
                               "--artifact", "/synthetic/artifact",
                               "--account-artifact", str(self.account_artifact),
                               "--profile", str(self.profile),
                               "--workspace", str(self.workspace)])
        self.assertEqual(code, 0)
        encoded = json.loads(output.getvalue())
        self.assertEqual(encoded["status"], audit.DELTA_STATUS)
        self.assertFalse(encoded["generated_effects_approved"])
        self.assertFalse(encoded["private_mode_approved"])


if __name__ == "__main__":
    unittest.main()
