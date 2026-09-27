"""Synthetic mkosi manifest tests; neither an image build nor boot evidence."""

import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

import prepare


spec = importlib.util.spec_from_file_location("verify_package_closure", Path(__file__).with_name("verify-package-closure.py"))
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


class PackageClosureTests(unittest.TestCase):
    def setUp(self):
        cache = prepare.ROOT / ".codex-tmp"
        cache.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gcp-package-closure-synthetic-", dir=cache)
        self.root = Path(self.temporary.name)
        self.packages = []
        for name in sorted(prepare.INITRD_PACKAGES | {"systemd-boot-efi", "systemd-resolved", "e2fsprogs", prepare.KERNEL_PACKAGE}):
            version = prepare.KERNEL_PACKAGE_VERSION if name == prepare.KERNEL_PACKAGE else "1.0~synthetic"
            self.packages.append({"name": name, "version": version, "architecture": "amd64", "filename": "synthetic", "size": 1, "sha256": "00" * 32, "path": "synthetic"})
        package_bytes = json.dumps(self.packages).encode()
        self.lock = {
            "schema_version": 5,
            "mkosi_source_commit": prepare.SOURCE_COMMIT,
            "source_date_epoch": 1,
            "kernel_version": prepare.KERNEL_VERSION,
            "snapshot": "synthetic",
            "artifacts": {role: {"path": role, "sha256": "00" * 32} for role in prepare.ROLES},
            "runtime": {},
        }
        self.lock["artifacts"]["package_manifest"]["sha256"] = hashlib.sha256(package_bytes).hexdigest()
        self.paths = {
            "lock": self.root / "inputs.lock.json",
            "package": self.root / "package_manifest",
            "root": self.root / "zrpc-gcp.manifest",
            "initrd": self.root / "initrd.manifest",
        }
        self.paths["package"].write_bytes(package_bytes)
        self.root_manifest = self.mkosi(self.packages)
        self.initrd_manifest = self.mkosi([entry for entry in self.packages if entry["name"] in prepare.INITRD_PACKAGES])
        self.write()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def mkosi(packages):
        return {
            "manifest_version": 1,
            "config": {"name": "image", "distribution": "debian", "architecture": "x86-64", "release": "trixie"},
            "packages": [{"type": "deb", "name": entry["name"], "version": entry["version"], "architecture": entry["architecture"]} for entry in packages],
        }

    def write(self):
        self.paths["lock"].write_text(json.dumps(self.lock))
        self.paths["root"].write_text(json.dumps(self.root_manifest))
        self.paths["initrd"].write_text(json.dumps(self.initrd_manifest))

    def verify(self):
        return closure.verify(self.paths["lock"], self.paths["package"], self.paths["root"], self.paths["initrd"])

    def test_matching_lists_remain_diagnostic_only(self):
        report = self.verify()
        self.assertEqual(report["status"], "diagnostic_supplied_package_lists_match_only")
        self.assertEqual(report["root_package_count"], len(self.packages))
        self.assertEqual(report["initrd_package_count"], len(prepare.INITRD_PACKAGES))
        for field in ("archive_signature_checked_here", "image_bytes_checked", "boot_verified", "private_mode_approved"):
            self.assertFalse(report[field])

        # The initrd can install dependencies beyond its five explicit seeds,
        # but every such package still has to match the locked archive list.
        dependency = next(entry for entry in self.packages if entry["name"] == "e2fsprogs")
        self.initrd_manifest["packages"].append(self.mkosi([dependency])["packages"][0])
        self.write()
        self.assertEqual(self.verify()["initrd_package_count"], len(prepare.INITRD_PACKAGES) + 1)

    def test_cli_never_reports_private_mode_approval(self):
        arguments = [
            "--lock", str(self.paths["lock"]),
            "--package-manifest", str(self.paths["package"]),
            "--root-manifest", str(self.paths["root"]),
            "--initrd-manifest", str(self.paths["initrd"]),
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(closure.main(arguments), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "diagnostic_supplied_package_lists_match_only")
        self.assertFalse(report["private_mode_approved"])

        self.root_manifest["packages"].pop()
        self.write()
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(closure.main(arguments), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["private_mode_approved"])

    def test_root_rejects_missing_extra_wrong_version_and_duplicates(self):
        for change in (
            lambda rows: rows.pop(),
            lambda rows: rows.append({"type": "deb", "name": "unlocked", "version": "1", "architecture": "amd64"}),
            lambda rows: rows[0].update(version="wrong"),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(architecture="arm64"),
        ):
            with self.subTest(change=change):
                original = copy.deepcopy(self.root_manifest)
                change(self.root_manifest["packages"])
                self.write()
                with self.assertRaises(ValueError):
                    self.verify()
                self.root_manifest = original

    def test_initrd_rejects_missing_seed_unlocked_package_and_duplicate(self):
        for change in (
            lambda rows: rows.pop(),
            lambda rows: rows.append({"type": "deb", "name": "unlocked", "version": "1", "architecture": "amd64"}),
            lambda rows: rows[0].update(version="wrong"),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
        ):
            with self.subTest(change=change):
                original = copy.deepcopy(self.initrd_manifest)
                change(self.initrd_manifest["packages"])
                self.write()
                with self.assertRaises(ValueError):
                    self.verify()
                self.initrd_manifest = original

    def test_wrong_mkosi_schema_platform_and_lock_binding_fail(self):
        for change in (
            lambda: self.root_manifest.update(manifest_version=2),
            lambda: self.root_manifest["config"].update(distribution="other"),
            lambda: self.initrd_manifest["config"].update(architecture="arm64"),
            lambda: self.lock["artifacts"]["package_manifest"].update(sha256="00" * 32),
        ):
            with self.subTest(change=change):
                root, initrd, lock = copy.deepcopy((self.root_manifest, self.initrd_manifest, self.lock))
                change()
                self.write()
                with self.assertRaises(ValueError):
                    self.verify()
                self.root_manifest, self.initrd_manifest, self.lock = root, initrd, lock

    def test_duplicate_json_fields_are_rejected(self):
        self.paths["root"].write_text('{"manifest_version":1,"manifest_version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
