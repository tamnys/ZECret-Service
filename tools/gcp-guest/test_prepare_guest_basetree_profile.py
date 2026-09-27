"""Synthetic negative tests for the non-bootable mkosi BaseTrees profile."""

import hashlib
import json
import os
from pathlib import Path
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
        self.source = {
            "archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "manifest_sha256": "a" * 64,
        }

    def prepare(self):
        with mock.patch.object(profile.base_tree, "verify", return_value=self.source):
            return profile.prepare_profile(self.workspace, self.workspace,
                                           self.artifact, self.output,
                                           self.workspace)

    def verify(self):
        with mock.patch.object(profile.base_tree, "verify", return_value=self.source):
            return profile.verify_profile(self.workspace, self.workspace,
                                          self.artifact, self.output,
                                          self.workspace)

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
        self.assertIn("Packages=\n", config)
        self.assertIn("WithNetwork=no\nCacheOnly=always\nIncremental=no\n", config)
        self.assertNotIn("FinalizeScripts=", config)
        self.assertNotIn("Initrds=", config)
        self.assertEqual({item.name for item in self.output.iterdir()},
                         {"input", profile.CONFIG, profile.MANIFEST})
        self.assertEqual((self.output / profile.INPUT).stat().st_mode & 0o777, 0o400)

    def test_source_authentication_and_snapshot_hash_fail_closed(self):
        with mock.patch.object(profile.base_tree, "verify",
                               side_effect=ValueError("signed guest closure invalid")):
            with self.assertRaisesRegex(ValueError, "signed guest closure invalid"):
                profile.prepare_profile(self.workspace, self.workspace,
                                        self.artifact, self.output,
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
                (manifest, profile.canonical_bytes({**json.loads(manifest.read_bytes()),
                                                   "private_mode_approved": True}),
                 "(manifest differs|exceeds bound)")):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                self.rewrite(path, changed)
                with self.assertRaisesRegex(ValueError, expected):
                    self.verify()
                self.rewrite(path, original)
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
                                                  self.artifact, self.output,
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
                                             self.artifact, self.output,
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
                                             self.artifact, self.output,
                                             self.workspace)


if __name__ == "__main__":
    unittest.main()
