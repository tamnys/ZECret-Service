"""Synthetic rejection tests for the signed guest payload data-only probe."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_stage_builder_toolchain import package
import stage_guest_payload as stage


class GuestPayloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gcp-guest-payload-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.metadata = self.root / "metadata"
        self.metadata.mkdir()
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.output = self.root / "payload-tree"

    def run_stage(self, named_packages):
        identities = []
        for name, data in named_packages:
            digest = hashlib.sha256(data).hexdigest()
            archive = self.archives / (digest + ".deb")
            if not archive.exists():
                archive.write_bytes(data)
            identities.append({"name": name, "version": "1",
                               "architecture": "amd64",
                               "filename": f"pool/main/{name}/{name}_1_amd64.deb",
                               "size": len(data), "sha256": digest,
                               "path": f"debs/{digest}.deb"})
        with mock.patch.object(stage.guest, "authenticated_packages", return_value=identities):
            return stage.stage(self.metadata, self.archives, self.output, self.root)

    def test_signed_identity_payloads_stage_as_inert_data(self):
        alpha = package([("directory", "./usr/", None, 0o755),
                         ("directory", "./usr/bin/", None, 0o755),
                         ("file", "./usr/bin/zebra", b"inert ELF placeholder", 0o4755)])
        beta = package([("directory", "./usr/", None, 0o755),
                        ("directory", "./usr/lib/", None, 0o755),
                        ("symlink", "./usr/lib/zebra", "../bin/zebra", 0o777)])
        report = self.run_stage([("alpha", alpha), ("beta", beta)])
        self.assertEqual(report["status"], stage.STATUS)
        self.assertTrue(report["signed_snapshot_rechecked"])
        self.assertTrue(report["archive_bytes_checked"])
        self.assertTrue(report["payload_tree_staged"])
        for field in ("installed_closure_checked", "package_scripts_executed",
                      "runtime_execution_verified", "image_built", "private_mode_approved"):
            self.assertFalse(report[field])
        self.assertEqual((self.output / "usr/bin/zebra").read_bytes(),
                         b"inert ELF placeholder")
        self.assertEqual(stat.S_IMODE((self.output / "usr/bin/zebra").stat().st_mode), 0o755)
        self.assertEqual((self.output / "usr/lib/zebra").readlink(), Path("../bin/zebra"))
        inventory = (self.output / stage.MANIFEST).read_bytes()
        manifest = json.loads(inventory)
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(inventory).hexdigest())
        self.assertEqual(manifest["package_count"], 2)
        self.assertFalse(manifest["package_scripts_executed"])
        self.assertFalse(manifest["installed_closure_checked"])
        self.assertEqual(manifest["entries"][0]["packages"], ["alpha", "beta"])

    def test_authentication_failure_cannot_create_output(self):
        with mock.patch.object(stage.guest, "authenticated_packages",
                               side_effect=ValueError("bad signed snapshot")):
            with self.assertRaisesRegex(ValueError, "bad signed snapshot"):
                stage.stage(self.metadata, self.archives, self.output, self.root)
        self.assertFalse(self.output.exists())

    def test_audit_lists_all_unsupported_types_and_hardlink_targets(self):
        data = package([
            ("directory", "./usr/", None, 0o755),
            ("directory", "./usr/bin/", None, 0o755),
            ("file", "./usr/bin/busybox", b"inert", 0o755),
            ("hardlink", "./usr/bin/gzip", "./usr/bin/busybox", 0o755),
            ("hardlink", "./usr/bin/escape", "../../outside", 0o755),
            ("special", "./usr/device", None, 0o644),
        ])
        digest = hashlib.sha256(data).hexdigest()
        (self.archives / (digest + ".deb")).write_bytes(data)
        identity = {"name": "alpha", "version": "1", "architecture": "amd64",
                    "filename": "pool/main/a/alpha_1_amd64.deb", "size": len(data),
                    "sha256": digest, "path": f"debs/{digest}.deb"}
        with mock.patch.object(stage.guest, "authenticated_packages", return_value=[identity]):
            report = stage.audit_unsupported_members(self.metadata, self.archives)
        self.assertEqual(report["unsupported_count"], 3)
        self.assertEqual(report["status"],
                         "diagnostic-unsupported-guest-payload-members-found")
        self.assertEqual([item["path"] for item in report["unsupported_members"]],
                         ["./usr/bin/gzip", "./usr/bin/escape", "./usr/device"])
        self.assertEqual(report["unsupported_members"][0]["canonical_target_path"],
                         "usr/bin/busybox")
        self.assertTrue(report["unsupported_members"][0]["target_is_regular_in_package"])
        self.assertFalse(report["unsupported_members"][1]["target_is_regular_in_package"])
        self.assertEqual(report["unsupported_members"][2]["tar_type_hex"], "33")
        self.assertFalse(report["payload_tree_staged"])
        self.assertFalse(report["private_mode_approved"])
        self.assertFalse(self.output.exists())

    def test_rejects_unsafe_paths_links_and_special_members_before_output(self):
        directory = [("directory", "./usr/", None, 0o755)]
        cases = [
            ("traversal", ("file", "./usr/../../outside", b"bad", 0o644)),
            ("absolute", ("file", "/outside", b"bad", 0o644)),
            ("hardlink", ("hardlink", "./usr/hard", "target", 0o644)),
            ("special", ("special", "./usr/device", None, 0o644)),
            ("escaping symlink", ("symlink", "./usr/link", "../../outside", 0o777)),
            ("inventory collision", ("file", "./" + stage.MANIFEST, b"bad", 0o644)),
        ]
        for label, bad in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError) as failure:
                    self.run_stage([("alpha", package(directory + [bad]))])
                if label == "hardlink":
                    self.assertIn("alpha payload member './usr/hard' tar type b'1'",
                                  str(failure.exception))
                self.assertFalse(self.output.exists())

    def test_rejects_cross_package_collision_and_symlink_parent(self):
        alpha = package([("directory", "./usr/", None, 0o755),
                         ("file", "./usr/item", b"alpha", 0o644)])
        beta = package([("directory", "./usr/", None, 0o755),
                        ("file", "./usr/item", b"beta", 0o644)])
        with self.assertRaisesRegex(ValueError, "collision"):
            self.run_stage([("alpha", alpha), ("beta", beta)])
        self.assertFalse(self.output.exists())
        alpha = package([("directory", "./usr/", None, 0o755),
                         ("symlink", "./usr/redirect", "/tmp", 0o777)])
        beta = package([("directory", "./usr/", None, 0o755),
                        ("file", "./usr/redirect/escape", b"bad", 0o644)])
        with self.assertRaisesRegex(ValueError, "symlink parent"):
            self.run_stage([("alpha", alpha), ("beta", beta)])
        self.assertFalse(self.output.exists())

    def test_rejects_tampered_archive_and_existing_output(self):
        data = package([("directory", "./usr/", None, 0o755),
                        ("file", "./usr/tool", b"safe", 0o755)])
        self.output.mkdir()
        (self.output / "owned").write_text("keep")
        with self.assertRaises(FileExistsError):
            self.run_stage([("alpha", data)])
        self.assertEqual((self.output / "owned").read_text(), "keep")
        self.output.rename(self.root / "owned-output")
        digest = hashlib.sha256(data).hexdigest()
        (self.archives / (digest + ".deb")).write_bytes(data + b"tampered")
        with self.assertRaisesRegex(ValueError, "size differs"):
            self.run_stage([("alpha", data)])
        self.assertFalse(self.output.exists())

    def test_casefold_collision_rejected_on_case_insensitive_workspace(self):
        data = package([("directory", "./usr/", None, 0o755),
                        ("file", "./usr/PAM", b"upper", 0o644),
                        ("file", "./usr/pam", b"lower", 0o644)])
        with mock.patch.object(stage.builder, "case_sensitive_directory", return_value=False):
            with self.assertRaisesRegex(ValueError, "case-sensitive workspace"):
                self.run_stage([("alpha", data)])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
