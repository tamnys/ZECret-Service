"""Focused fail-closed checks for the package-backed initrd runner."""

import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "package_initrd_runner", HERE / "package_initrd_runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class PackageInitrdRunnerTest(unittest.TestCase):
    def test_production_config_uses_signed_package_versions_and_inherited_settings(self):
        static = b"[Output]\nFormat=cpio\nOutput=initrd\nManifestFormat=json\nCompressOutput=zstd\n"
        prepare = types.SimpleNamespace(
            validate_boot_profile=lambda: None,
            PROFILE=Path("/reviewed/deploy/gcp/guest"),
            INITRD_PACKAGES={"systemd", "udev"},
        )
        source = types.SimpleNamespace(
            guest=types.SimpleNamespace(prepare=prepare, SNAPSHOT="https://snapshot.debian.org/archive/debian/20260918T000000Z/"),
            rust_inputs=types.SimpleNamespace(regular_bytes=lambda path: static),
            source_git_output=lambda args: static,
            _BOUND_REVISION="a" * 40,
        )
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch) / "profile"
            data, static_hash = runner.config_bytes(source, profile, 1789199741, [
                {"name": "systemd", "version": "257.9-1"},
                {"name": "udev", "version": "257.9-1"},
            ])
        self.assertEqual(static_hash, runner.sha256(static))
        self.assertTrue(data.startswith(static))
        self.assertIn(b"Distribution=debian\nRelease=trixie\nArchitecture=x86-64", data)
        self.assertIn(b"Packages=systemd=257.9-1,udev=257.9-1", data)
        self.assertIn(b"CacheOnly=always\nIncremental=no", data)
        self.assertNotIn(b"BaseTrees=", data)
        with self.assertRaisesRegex(ValueError, "misses production initrd package"):
            runner.config_bytes(source, profile, 1789199741,
                                [{"name": "systemd", "version": "257.9-1"}])

    def test_installed_manifest_rejects_package_outside_signed_closure(self):
        source = types.SimpleNamespace(guest=types.SimpleNamespace(
            prepare=types.SimpleNamespace(unique_object=dict,
                                          INITRD_PACKAGES={"systemd"})))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "initrd.manifest"
            manifest = {"manifest_version": 1,
                        "config": {"distribution": "debian", "release": "trixie",
                                   "architecture": "x86-64", "name": "initrd"},
                        "packages": [{"type": "deb", "name": "systemd",
                                      "version": "257.9-1", "architecture": "amd64"}]}
            path.write_text(json.dumps(manifest))
            digest, count = runner.installed_manifest(path, [
                {"name": "systemd", "version": "257.9-1", "architecture": "amd64"}], source)
            self.assertEqual(digest, runner.sha256(path.read_bytes()))
            self.assertEqual(count, 1)
            manifest["packages"][0]["version"] = "257.10-1"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "unlocked package"):
                runner.installed_manifest(path, [
                    {"name": "systemd", "version": "257.9-1", "architecture": "amd64"}], source)

    def test_no_route_rejects_parent_namespace_and_non_loopback_route(self):
        with mock.patch.object(runner.sys, "platform", "linux"), mock.patch.object(
                runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                runner.os, "readlink", side_effect=["net:[1]", "mnt:[2]"]):
            with self.assertRaisesRegex(ValueError, "not separated"):
                runner.no_route("net:[1]", "mnt:[3]")
        with mock.patch.object(runner.sys, "platform", "linux"), mock.patch.object(
                runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]), mock.patch.object(
                runner.socket, "if_nameindex", return_value=[(1, "lo")]), mock.patch.object(
                runner.Path, "read_text", side_effect=["Iface\neth0 00000000 0 0 0 0 0 0 0 0 0\n", ""]):
            with self.assertRaisesRegex(ValueError, "non-loopback route"):
                runner.no_route("net:[1]", "mnt:[2]")


if __name__ == "__main__":
    unittest.main()
