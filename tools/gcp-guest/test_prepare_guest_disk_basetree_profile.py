"""Synthetic negative tests for the no-boot BaseTrees disk profile."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import prepare_guest_disk_basetree_profile as disk


class DiskProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-disk-profile-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.source = self.workspace / "source-profile"
        self.source.mkdir()
        (self.source / disk.INPUT).mkdir()
        self.profile = self.workspace / "disk-profile"
        self.source_report = {
            "profile_manifest_sha256": "a" * 64,
            "base_tree_sha256": hashlib.sha256(b"signed-source-base-tree").hexdigest(),
        }
        input_bytes = {
            "guest-root.tar": b"signed-source-base-tree",
            "account-tree.tar": b"signed-source-accounts",
            "source-overlay.tar": b"committed-rootfs-and-boot-overrides",
        }
        self.inputs = {}
        for name, data in input_bytes.items():
            location = (self.source / disk.INPUT / name if name == "guest-root.tar"
                        else self.source / name)
            location.write_bytes(data)
            location.chmod(0o400)
            self.inputs[name] = {"sha256": hashlib.sha256(data).hexdigest(),
                                 "bytes": len(data)}
        self.repart = {
            "10-root.conf": b"[Partition]\nType=root-x86-64\nVerity=data\n",
            "20-root-verity.conf": b"[Partition]\nType=root-x86-64-verity\nVerity=hash\n",
        }
        patches = (
            mock.patch.object(disk, "source_identity", return_value=self.source_report),
            mock.patch.object(disk, "source_inputs", return_value=self.inputs),
            mock.patch.object(disk, "repart_bytes", return_value=self.repart),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def invoke(self, action):
        args = (self.workspace, self.workspace, self.workspace,
                self.workspace, self.source, self.profile,
                self.workspace)
        if action is disk.build_disk:
            return action(*args, self.workspace, "net:[42]", self.workspace,
                          "user:[42]", "pid:[42]")
        return action(*args)

    @staticmethod
    def rewrite(path, data):
        path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(0o400)

    def test_profile_uses_authenticated_inputs_no_packages_and_no_boot(self):
        prepared = self.invoke(disk.prepare_profile)
        self.assertEqual(prepared, self.invoke(disk.verify_profile))
        config = (self.profile / disk.CONFIG).read_text()
        for required in ("Distribution=custom\n", "Format=disk\n",
                         "RepartOffline=yes\n", "Bootable=no\n", "Packages=\n",
                         "WithNetwork=no\n", "SourceDateEpoch=0\n"):
            self.assertIn(required, config)
        for forbidden in ("Initrds=", "SecureBoot=yes", "PackageDirectories=",
                          "Bootloader=uki", "Format=directory"):
            self.assertNotIn(forbidden, config)
        self.assertEqual({entry.name for entry in (self.profile / disk.REPART).iterdir()},
                         set(disk.REPART_NAMES))
        self.assertEqual({entry.name for entry in (self.profile / disk.INPUT).iterdir()},
                         set(disk.INPUT_NAMES))
        for field in ("package_install_configured", "package_scripts_executed",
                      "runtime_binaries_included", "esp_included", "uki_included",
                      "boot_verified", "disk_image_built", "private_mode_approved"):
            self.assertFalse(prepared[field])
        manifest = json.loads((self.profile / disk.MANIFEST).read_text())
        self.assertFalse(manifest["signed_snapshot_rechecked"])

    def test_rejects_mutable_config_repart_and_extra_mkosi_hook(self):
        self.invoke(disk.prepare_profile)
        for path, replacement in (
            (self.profile / disk.CONFIG, b"[Output]\nFormat=disk\n"),
            (self.profile / disk.REPART / "10-root.conf", b"Verity=off\n"),
            (self.profile / disk.INPUT / "source-overlay.tar", b"wrong"),
        ):
            original = path.read_bytes()
            self.rewrite(path, replacement)
            with self.assertRaises(ValueError):
                self.invoke(disk.verify_profile)
            self.rewrite(path, original)
        hook = self.profile / "mkosi.postinst"
        hook.write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaises(ValueError):
            self.invoke(disk.verify_profile)

    def test_rejects_source_identity_change_and_existing_output(self):
        self.invoke(disk.prepare_profile)
        self.source_report["profile_manifest_sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            self.invoke(disk.verify_profile)
        self.source_report["profile_manifest_sha256"] = "a" * 64
        output = self.workspace / "disk-profile-output"
        output.mkdir()
        (output / disk.OUTPUT).write_bytes(b"untrusted prior image")
        with mock.patch.object(disk.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                self.invoke(disk.build_disk)
            run.assert_not_called()

    def test_build_receipt_remains_nonaccepting(self):
        self.invoke(disk.prepare_profile)

        def fake_mkosi(command, check):
            self.assertEqual(command[0], "/usr/bin/mkosi")
            self.assertTrue(check)
            output = self.workspace / "disk-profile-output"
            output.mkdir()
            (output / disk.OUTPUT).write_bytes(b"synthetic unbootable raw bytes")

        execution = {"status": "synthetic-guard-only",
                     "complete_builder_toolchain": False,
                     "private_mode_approved": False}
        with (mock.patch.object(disk, "verify_execution_context",
                                return_value=execution),
              mock.patch.object(disk.subprocess, "run", side_effect=fake_mkosi)):
            report = self.invoke(disk.build_disk)
        self.assertEqual(report["status"], disk.BUILT_STATUS)
        self.assertTrue(report["disk_image_built"])
        self.assertFalse(report["gpt_checked"])
        self.assertFalse(report["verity_userspace_verified"])
        self.assertFalse(report["production_image_built"])
        self.assertFalse(report["private_mode_approved"])

    def test_build_rejects_unverified_builder_before_mkosi(self):
        self.invoke(disk.prepare_profile)
        with (mock.patch.object(disk, "verify_execution_context",
                                side_effect=ValueError("builder unverified")),
              mock.patch.object(disk.subprocess, "run") as run):
            with self.assertRaisesRegex(ValueError, "builder unverified"):
                self.invoke(disk.build_disk)
            run.assert_not_called()

    def test_builder_guard_rejects_same_namespace_and_network_route(self):
        namespaces = {
            "/proc/self/ns/net": "net:[43]",
            "/proc/self/ns/user": "user:[43]",
            "/proc/self/ns/pid": "pid:[43]",
            "/proc/1/ns/pid": "pid:[43]",
        }
        original_read_text = Path.read_text

        def namespace_readlink(path):
            return namespaces[path]

        def routes(path, *args, **kwargs):
            if str(path) == "/proc/self/uid_map":
                return "0 0 1\n"
            if str(path) == "/proc/self/gid_map":
                return "0 0 1\n42 42 1\n"
            if str(path) == "/proc/self/setgroups":
                return "deny\n"
            if str(path) == "/proc/net/route":
                return "Iface Destination\neth0 route\n"
            if str(path) == "/proc/net/ipv6_route":
                return ""
            return original_read_text(path, *args, **kwargs)

        with (mock.patch.object(disk.platform, "system", return_value="Linux"),
              mock.patch.object(disk.platform, "machine", return_value="x86_64"),
              mock.patch.object(disk.os, "readlink", side_effect=namespace_readlink),
              mock.patch.object(disk.builder_closure, "verify") as verify):
            with self.assertRaisesRegex(ValueError, "outer no-route"):
                disk.verify_execution_context(self.workspace, self.workspace,
                                              "net:[43]", self.workspace,
                                              "user:[42]", "pid:[42]")
            verify.assert_not_called()
        with (mock.patch.object(disk.platform, "system", return_value="Linux"),
              mock.patch.object(disk.platform, "machine", return_value="x86_64"),
              mock.patch.object(disk.os, "readlink", side_effect=namespace_readlink),
              mock.patch.object(disk.os, "geteuid", return_value=0),
              mock.patch.object(disk.socket, "if_nameindex", return_value=[(1, "lo")]),
              mock.patch.object(Path, "read_text", autospec=True,
                                side_effect=routes),
              mock.patch.object(disk.builder_closure, "verify") as verify):
            with self.assertRaisesRegex(ValueError, "non-loopback route"):
                disk.verify_execution_context(self.workspace, self.workspace,
                                              "net:[42]", self.workspace,
                                              "user:[42]", "pid:[42]")
            verify.assert_not_called()

        def broad_mapping(path, *args, **kwargs):
            if str(path) in {"/proc/self/uid_map", "/proc/self/gid_map"}:
                return "0 0 4294967295\n"
            return routes(path, *args, **kwargs)

        with (mock.patch.object(disk.platform, "system", return_value="Linux"),
              mock.patch.object(disk.platform, "machine", return_value="x86_64"),
              mock.patch.object(disk.os, "readlink", side_effect=namespace_readlink),
              mock.patch.object(disk.os, "geteuid", return_value=0),
              mock.patch.object(disk.socket, "if_nameindex", return_value=[(1, "lo")]),
              mock.patch.object(Path, "read_text", autospec=True,
                                side_effect=broad_mapping),
              mock.patch.object(disk.builder_closure, "verify") as verify):
            with self.assertRaisesRegex(ValueError, "outer no-route"):
                disk.verify_execution_context(self.workspace, self.workspace,
                                              "net:[42]", self.workspace,
                                              "user:[42]", "pid:[42]")
            verify.assert_not_called()

        def missing_guest_group(path, *args, **kwargs):
            if str(path) == "/proc/self/gid_map":
                return "0 0 1\n"
            return routes(path, *args, **kwargs)

        with (mock.patch.object(disk.platform, "system", return_value="Linux"),
              mock.patch.object(disk.platform, "machine", return_value="x86_64"),
              mock.patch.object(disk.os, "readlink", side_effect=namespace_readlink),
              mock.patch.object(disk.os, "geteuid", return_value=0),
              mock.patch.object(disk.socket, "if_nameindex", return_value=[(1, "lo")]),
              mock.patch.object(Path, "read_text", autospec=True,
                                side_effect=missing_guest_group),
              mock.patch.object(disk.builder_closure, "verify") as verify):
            with self.assertRaisesRegex(ValueError, "outer no-route"):
                disk.verify_execution_context(self.workspace, self.workspace,
                                              "net:[42]", self.workspace,
                                              "user:[42]", "pid:[42]")
            verify.assert_not_called()

        def loopback_routes(path, *args, **kwargs):
            if str(path) in {"/proc/self/uid_map", "/proc/self/gid_map",
                             "/proc/self/setgroups"}:
                return routes(path, *args, **kwargs)
            if str(path) == "/proc/net/route":
                return ""  # Native no-route namespace can expose no IPv4 header.
            if str(path) == "/proc/net/ipv6_route":
                return "00000000 lo\n"
            return original_read_text(path, *args, **kwargs)

        with (mock.patch.object(disk.platform, "system", return_value="Linux"),
              mock.patch.object(disk.platform, "machine", return_value="x86_64"),
              mock.patch.object(disk.os, "readlink", side_effect=namespace_readlink),
              mock.patch.object(disk.os, "geteuid", return_value=0),
              mock.patch.object(disk.socket, "if_nameindex", return_value=[(1, "lo")]),
              mock.patch.object(Path, "read_text", autospec=True,
                                side_effect=loopback_routes),
              mock.patch.object(disk.builder_closure, "verify",
                                side_effect=ValueError("signed closure sentinel")) as verify):
            with self.assertRaisesRegex(ValueError, "signed closure sentinel"):
                disk.verify_execution_context(self.workspace, self.workspace,
                                              "net:[42]", self.workspace,
                                              "user:[42]", "pid:[42]")
            verify.assert_called_once()

    def test_staged_builder_rejects_mutated_or_extra_payload(self):
        staged = self.workspace / "staged"
        (staged / "usr" / "bin").mkdir(parents=True)
        program = staged / "usr" / "bin" / "mkosi"
        program.write_bytes(b"signed synthetic payload")
        program.chmod(0o755)
        expected = {
            "usr": {"kind": "directory", "staged_mode": 0o755},
            "usr/bin": {"kind": "directory", "staged_mode": 0o755},
            "usr/bin/mkosi": {"kind": "file", "staged_mode": 0o755,
                              "size": program.stat().st_size,
                              "sha256": hashlib.sha256(program.read_bytes()).hexdigest()},
        }
        self.assertEqual(disk.inspect_staged_builder(staged, expected), 3)
        program.write_bytes(b"substituted payload")
        with self.assertRaisesRegex(ValueError, "staged builder file"):
            disk.inspect_staged_builder(staged, expected)
        program.write_bytes(b"signed synthetic payload")
        (staged / "usr" / "bin" / "unreviewed").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "unreviewed file"):
            disk.inspect_staged_builder(staged, expected)


if __name__ == "__main__":
    unittest.main()
