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
            guest=types.SimpleNamespace(
                prepare=prepare,
                SNAPSHOT="https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                SIGNED_RELEASE_EPOCH=1789199741,
            ),
            rust_inputs=types.SimpleNamespace(regular_bytes=lambda path: static),
            source_git_output=lambda args: static,
            _BOUND_REVISION="a" * 40,
        )
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch) / "profile"
            data, static_hash = runner.config_bytes(source, profile, [
                {"name": "systemd", "version": "257.9-1"},
                {"name": "udev", "version": "257.9-1"},
            ])
        self.assertEqual(static_hash, runner.sha256(static))
        self.assertTrue(data.startswith(static))
        self.assertIn(b"Distribution=debian\nRelease=trixie\nArchitecture=x86-64", data)
        self.assertIn(b"Packages=systemd=257.9-1,udev=257.9-1", data)
        self.assertIn(b"SourceDateEpoch=1789199741", data)
        self.assertIn(b"CacheOnly=always\nIncremental=no", data)
        self.assertNotIn(b"BaseTrees=", data)
        with self.assertRaisesRegex(ValueError, "misses production initrd package"):
            runner.config_bytes(source, profile,
                                [{"name": "systemd", "version": "257.9-1"}])

    def test_installed_manifest_rejects_package_outside_signed_closure(self):
        source = types.SimpleNamespace(guest=types.SimpleNamespace(
            prepare=types.SimpleNamespace(unique_object=dict,
                                          INITRD_PACKAGES={"systemd"})))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "initrd.manifest"
            manifest = {"manifest_version": 1,
                        "config": {"distribution": "debian", "release": "trixie",
                                   "architecture": "x86-64", "name": "image"},
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
            manifest["packages"][0]["version"] = "257.9-1"
            manifest["config"]["name"] = "initrd"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "manifest is unsupported"):
                runner.installed_manifest(path, [
                    {"name": "systemd", "version": "257.9-1", "architecture": "amd64"}], source)

    def test_loopback_check_rejects_parent_namespace_and_non_loopback_route(self):
        with mock.patch.object(runner.sys, "platform", "linux"), mock.patch.object(
                runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                runner.os, "readlink", side_effect=["net:[1]", "mnt:[2]"]):
            with self.assertRaisesRegex(ValueError, "do not differ"):
                runner.check_loopback_only_ip_state("net:[1]", "mnt:[3]")
        with mock.patch.object(runner.sys, "platform", "linux"), mock.patch.object(
                runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]), mock.patch.object(
                runner.socket, "if_nameindex", return_value=[(1, "lo")]), mock.patch.object(
                runner.Path, "read_text", side_effect=["Iface\neth0 00000000 0 0 0 0 0 0 0 0 0\n", ""]):
            with self.assertRaisesRegex(ValueError, "non-loopback route"):
                runner.check_loopback_only_ip_state("net:[1]", "mnt:[2]")

    def test_fresh_mkosi_cache_and_work_directories_reject_reuse(self):
        with tempfile.TemporaryDirectory() as scratch:
            profile = Path(scratch) / "profile"
            runner.fresh_sibling(profile, "-package-cache")
            cache = Path(scratch) / "profile-package-cache"
            self.assertEqual(cache.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(cache.iterdir()), [])
            with self.assertRaises(FileExistsError):
                runner.fresh_sibling(profile, "-package-cache")
            (Path(scratch) / "profile-work").symlink_to(cache)
            with self.assertRaises(FileExistsError):
                runner.fresh_sibling(profile, "-work")

    def test_loopback_observation_does_not_claim_egress_exclusion(self):
        with (mock.patch.object(runner.sys, "platform", "linux"),
              mock.patch.object(runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")),
              mock.patch.object(runner.os, "readlink", side_effect=["net:[4]", "mnt:[5]"]),
              mock.patch.object(runner.socket, "if_nameindex", return_value=[(1, "lo")]),
              mock.patch.object(runner.Path, "read_text", side_effect=["Iface\n", ""])):
            observed = runner.check_loopback_only_ip_state("net:[1]", "mnt:[2]")
        self.assertTrue(observed["loopback_only_ip_state_observed"])
        self.assertFalse(observed["outer_namespace_separation_verified"])
        self.assertFalse(observed["builder_mounts_verified"])
        self.assertFalse(observed["network_egress_excluded"])


if __name__ == "__main__":
    unittest.main()
