"""Synthetic negative tests for the non-bootable mkosi BaseTrees profile."""

import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import prepare_guest_basetree_profile as profile


class GuestBaseTreeProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mkosi-basetre-probe-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.artifact = self.workspace / "artifact"
        self.artifact.mkdir()
        self.archive = self.artifact / "guest-root.tar"
        self.archive.write_bytes(b"synthetic authenticated tar bytes")
        self.output = self.workspace / "profile"
        self.account_artifact = self.workspace / "accounts"
        account_etc = self.account_artifact / "etc"
        account_etc.mkdir(parents=True)
        contents = {"passwd": b"root:x:0:0:root:/root:/bin/sh\n",
                    "group": b"root:x:0:\n", "shadow": b"root:!:20708::::::\n"}
        self.account_receipt = {
            "status": "diagnostic-verified-guest-account-artifact-unbuilt",
            "independent_generation_runs_matched": True,
            "package_scripts_executed": False,
            "installed_rootfs_accounts_compared": False,
            "image_built": False,
            "private_mode_approved": False,
            "outputs": [],
        }
        for name, data in contents.items():
            path = account_etc / name
            path.write_bytes(data)
            storage_mode = 0o400 if name == "shadow" else 0o444
            path.chmod(storage_mode)
            self.account_receipt["outputs"].append({
                "path": "etc/" + name, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": storage_mode,
                "sysusers_generated_mode": 0o000 if name == "shadow" else 0o644,
                "expected_root_uid": 0, "expected_root_gid": 0,
            })
        account_verify = mock.patch.object(profile.accounts, "verify",
                                           return_value=self.account_receipt)
        account_verify.start()
        self.addCleanup(account_verify.stop)
        self.source = {
            "archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "manifest_sha256": "a" * 64,
        }

    def prepare(self, include_overlay=False):
        with mock.patch.object(profile.base_tree, "verify", return_value=self.source):
            return profile.prepare_profile(self.workspace, self.workspace,
                                           self.artifact, self.account_artifact, self.output,
                                           self.workspace, include_overlay)

    def verify(self, include_overlay=False):
        with mock.patch.object(profile.base_tree, "verify", return_value=self.source):
            return profile.verify_profile(self.workspace, self.workspace,
                                          self.artifact, self.account_artifact, self.output,
                                          self.workspace, include_overlay)

    @staticmethod
    def rewrite(path, data):
        path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(0o400)

    def test_authenticated_archive_is_snapshotted_into_no_package_profile(self):
        report = self.prepare()
        checked = self.verify()
        self.assertEqual(report, checked)
        self.assertEqual(report["base_tree_sha256"], self.source["archive_sha256"])
        for field in ("package_install_configured", "package_scripts_executed",
                      "root_directory_built", "disk_image_built",
                      "boot_verified", "private_mode_approved"):
            self.assertFalse(report[field])
        config = (self.output / profile.CONFIG).read_text()
        self.assertIn("Distribution=custom\n", config)
        self.assertIn("Format=directory\n", config)
        self.assertIn("BaseTrees=" + str(self.output / profile.INPUT) + "\n", config)
        self.assertIn("ExtraTrees=" + str(self.output / profile.ACCOUNT_TREE) + "\n",
                      config)
        self.assertIn("Packages=\n", config)
        self.assertIn("SourceDateEpoch=0\n", config)
        self.assertIn("WithNetwork=no\nCacheOnly=always\nIncremental=no\n", config)
        self.assertNotIn("FinalizeScripts=", config)
        self.assertNotIn("Initrds=", config)
        self.assertEqual({item.name for item in self.output.iterdir()},
                         {"input", profile.ACCOUNT_TREE,
                          profile.CONFIG, profile.MANIFEST})
        self.assertEqual((self.output / profile.INPUT).stat().st_mode & 0o777, 0o400)
        account_input = self.output / profile.ACCOUNT_TREE
        self.assertEqual(account_input.stat().st_mode & 0o777, 0o400)
        with tarfile.open(account_input) as archive:
            self.assertEqual({member.name for member in archive},
                             {"etc", "usr", "usr/lib", "usr/lib/sysusers.d",
                              "etc/passwd", "etc/group", "etc/shadow",
                              "usr/lib/sysusers.d/zrpc.conf"})
            for name in profile.accounts.OUTPUT_FILES:
                member = archive.getmember("etc/" + name)
                self.assertEqual((member.mode, member.uid, member.gid),
                                 (0o000 if name == "shadow" else 0o644, 0, 0))
                self.assertEqual(archive.extractfile(member).read(),
                                 (self.account_artifact / "etc" / name).read_bytes())
            project = archive.getmember("usr/lib/sysusers.d/zrpc.conf")
            self.assertEqual((project.mode, project.uid, project.gid), (0o644, 0, 0))
            self.assertEqual(archive.extractfile(project).read(),
                             profile.PROJECT_SYSUSERS.read_bytes())
        manifest = json.loads((self.output / profile.MANIFEST).read_bytes())
        self.assertEqual(manifest["project_sysusers_sha256"],
                         hashlib.sha256(profile.PROJECT_SYSUSERS.read_bytes()).hexdigest())
        self.assertEqual(manifest["account_tree_sha256"],
                         hashlib.sha256(account_input.read_bytes()).hexdigest())
        self.assertTrue(manifest["account_artifact_regenerated_and_verified"])
        self.assertTrue(manifest["account_files_preseeded_from_signed_source"])

    def test_source_overlay_is_snapshot_of_production_rootfs_and_overrides(self):
        report = self.prepare(include_overlay=True)
        self.assertEqual(report, self.verify(include_overlay=True))
        self.assertEqual(report["status"], profile.OVERLAY_STATUS)
        self.assertTrue(report["committed_rootfs_overlay_included"])
        for field in ("runtime_binaries_included", "production_package_install_exercised",
                      "package_install_configured", "package_scripts_executed",
                      "root_directory_built", "disk_image_built", "boot_verified",
                      "private_mode_approved"):
            self.assertFalse(report[field])
        config = (self.output / profile.CONFIG).read_text()
        self.assertIn("ExtraTrees=" + str(self.output / profile.ACCOUNT_TREE) + "," +
                      str(self.output / profile.SOURCE_OVERLAY) + "\n", config)
        self.assertIn("Packages=\n", config)
        self.assertIn("Format=directory\n", config)
        self.assertIn("Bootable=no\n", config)
        overlay = self.output / profile.SOURCE_OVERLAY
        with tarfile.open(overlay) as archive:
            self.assertEqual(archive.getmember("etc/systemd/system/default.target").linkname,
                             "/usr/lib/systemd/system/zrpc.target")
            self.assertEqual(archive.getmember("etc/systemd/system/ssh.service").linkname,
                             "/dev/null")
            self.assertEqual(archive.extractfile("usr/lib/systemd/system/zrpc.target").read(),
                             (profile.prepare.PROFILE / "rootfs/usr/lib/systemd/system/zrpc.target").read_bytes())
        manifest = json.loads((self.output / profile.MANIFEST).read_bytes())
        self.assertEqual(manifest["source_overlay_sha256"],
                         hashlib.sha256(overlay.read_bytes()).hexdigest())
        self.rewrite(overlay, overlay.read_bytes()[:-1] + b"X")
        with self.assertRaisesRegex(ValueError, "source overlay differs"):
            self.verify(include_overlay=True)

    def test_overlay_profile_cannot_be_verified_as_minimal_profile(self):
        self.prepare(include_overlay=True)
        with self.assertRaisesRegex(ValueError, "unreviewed inputs"):
            self.verify()

    def test_source_authentication_and_snapshot_hash_fail_closed(self):
        with mock.patch.object(profile.base_tree, "verify",
                               side_effect=ValueError("signed guest closure invalid")):
            with self.assertRaisesRegex(ValueError, "signed guest closure invalid"):
                profile.prepare_profile(self.workspace, self.workspace,
                                        self.artifact, self.account_artifact,
                                        self.output,
                                        self.workspace)
        self.assertFalse(self.output.exists())
        self.source["archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "archive changed"):
            self.prepare()

    def test_mutated_snapshot_config_or_manifest_is_rejected_before_mkosi(self):
        self.prepare()
        archive = self.output / profile.INPUT
        config = self.output / profile.CONFIG
        manifest = self.output / profile.MANIFEST
        for path, changed, expected in (
                (archive, b"modified tar bytes", "archive differs"),
                (config, config.read_bytes() + b"Packages=unreviewed\n", "exceeds bound"),
                (config, config.read_bytes().replace(
                    b"SourceDateEpoch=0", b"SourceDateEpoch=1"), "config differs"),
                (manifest, profile.canonical_bytes({**json.loads(manifest.read_bytes()),
                                                   "private_mode_approved": True}),
                 "(manifest differs|exceeds bound)")):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                self.rewrite(path, changed)
                with self.assertRaisesRegex(ValueError, expected):
                    self.verify()
                self.rewrite(path, original)
        tree = self.output / profile.ACCOUNT_TREE
        original = tree.read_bytes()
        self.rewrite(tree, b"X" + original[1:])
        with self.assertRaisesRegex(ValueError, "account tree differs"):
            self.verify()
        self.rewrite(tree, original)
        self.verify()

    def test_account_artifact_bytes_and_regeneration_are_rechecked(self):
        self.prepare()
        passwd = self.account_artifact / "etc/passwd"
        passwd.chmod(0o600)
        passwd.write_bytes(b"X" + passwd.read_bytes()[1:])
        passwd.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "account artifact bytes differ"):
            self.verify()
        with mock.patch.object(profile.accounts, "verify",
                               side_effect=ValueError("signed account source invalid")):
            with self.assertRaisesRegex(ValueError, "signed account source invalid"):
                self.verify()

    def test_unsafe_installed_account_modes_and_owner_are_rejected(self):
        for name, field, changed in (("passwd", "sysusers_generated_mode", 0o666),
                                     ("group", "sysusers_generated_mode", 0o600),
                                     ("shadow", "sysusers_generated_mode", 0o400),
                                     ("shadow", "expected_root_uid", 1)):
            row = next(row for row in self.account_receipt["outputs"]
                       if row["path"] == "etc/" + name)
            original = row[field]
            with self.subTest(name=name, field=field):
                row[field] = changed
                with self.assertRaisesRegex(ValueError, "install metadata differs"):
                    self.prepare()
            row[field] = original

    def test_project_sysusers_source_is_rechecked_and_not_redirected(self):
        project = self.workspace / "project.conf"
        project.write_bytes(profile.PROJECT_SYSUSERS.read_bytes())
        project.chmod(0o644)
        with mock.patch.object(profile, "PROJECT_SYSUSERS", project):
            self.prepare()
            self.verify()
            project.write_bytes(b"X" + project.read_bytes()[1:])
            with self.assertRaisesRegex(ValueError, "account tree differs"):
                self.verify()
        project.unlink()
        project.symlink_to(profile.PROJECT_SYSUSERS)
        with mock.patch.object(profile, "PROJECT_SYSUSERS", project):
            with self.assertRaises(OSError):
                self.verify()

    def test_symlink_or_extra_input_is_rejected(self):
        self.prepare()
        archive = self.output / profile.INPUT
        archive.parent.chmod(0o700)
        archive.unlink()
        archive.symlink_to(self.archive)
        archive.parent.chmod(0o500)
        with self.assertRaises(OSError):
            self.verify()
        archive.parent.chmod(0o700)
        archive.unlink()
        archive.write_bytes(self.archive.read_bytes())
        archive.chmod(0o400)
        archive.parent.chmod(0o500)
        (self.output / "mkosi.prepare").write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "unreviewed inputs"):
            self.verify()
        (self.output / "mkosi.prepare").unlink()
        tree = self.output / profile.ACCOUNT_TREE
        tree.unlink()
        tree.symlink_to(profile.PROJECT_SYSUSERS)
        with self.assertRaises(OSError):
            self.verify()

    def test_existing_output_and_unsafe_paths_are_rejected(self):
        self.output.mkdir()
        (self.output / "sentinel").write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual((self.output / "sentinel").read_text(), "preserve")
        with self.assertRaisesRegex(ValueError, "not canonical"):
            profile.checked_profile_path(self.workspace / "bad,name", self.workspace)

    def test_build_invocation_rechecks_source_before_and_after_mkosi(self):
        self.prepare()
        seen = []

        def synthetic_mkosi(argv, check):
            self.assertEqual(argv, ["/usr/bin/mkosi",
                                    f"--directory={self.output}", "build"])
            self.assertTrue(check)
            seen.append(argv)
            output = self.workspace / "profile-output" / profile.OUTPUT_NAME
            output.mkdir(parents=True)

        with mock.patch.object(profile.base_tree, "verify", return_value=self.source), \
                mock.patch.object(profile.subprocess, "run", side_effect=synthetic_mkosi):
            report = profile.build_root_directory(self.workspace, self.workspace,
                                                  self.artifact, self.account_artifact,
                                                  self.output,
                                                  self.workspace)
        self.assertEqual(len(seen), 1)
        self.assertTrue(report["root_directory_built"])
        self.assertFalse(report["post_mkosi_tree_audited"])
        self.assertFalse(report["disk_image_built"])
        self.assertFalse(report["private_mode_approved"])

        (self.workspace / "profile-output" / profile.OUTPUT_NAME).rename(
            self.workspace / "moved-output")
        bad = self.output / profile.INPUT
        self.rewrite(bad, b"tampered before invocation")
        with mock.patch.object(profile.base_tree, "verify", return_value=self.source), \
                mock.patch.object(profile.subprocess, "run") as mkosi:
            with self.assertRaisesRegex(ValueError, "archive differs"):
                profile.build_root_directory(self.workspace, self.workspace,
                                             self.artifact, self.account_artifact,
                                             self.output,
                                             self.workspace)
            mkosi.assert_not_called()

    def test_build_rejects_input_mutated_while_mkosi_runs(self):
        self.prepare()

        def mutate_during_build(argv, check):
            self.rewrite(self.output / profile.INPUT, b"changed during build")
            (self.workspace / "profile-output" / profile.OUTPUT_NAME).mkdir(parents=True)

        with mock.patch.object(profile.base_tree, "verify", return_value=self.source), \
                mock.patch.object(profile.subprocess, "run", side_effect=mutate_during_build):
            with self.assertRaisesRegex(ValueError, "archive differs"):
                profile.build_root_directory(self.workspace, self.workspace,
                                             self.artifact, self.account_artifact,
                                             self.output,
                                             self.workspace)


if __name__ == "__main__":
    unittest.main()
