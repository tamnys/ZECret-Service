"""Synthetic package-to-raw-ext4 identity checks; no image is approved."""

import hashlib
import io
import lzma
from pathlib import Path
import tarfile
import unittest
from unittest import mock

import inspect_raw_package_components as components


def ar_member(name, data):
    header = (f"{name}/".ljust(16) + "0".ljust(12) + "0".ljust(6)
              + "0".ljust(6) + "100644".ljust(8) + str(len(data)).ljust(10)
              + "`\n").encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def package(files):
    """Make a small inert .deb payload with canonical parent directories."""
    parents = {"usr", "etc"}
    for _, path, _, _ in files:
        parts = path.split("/")
        parents.update("/".join(parts[:index]) for index in range(1, len(parts)))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as tar:
        root = tarfile.TarInfo("./")
        root.type, root.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(root)
        for path in sorted(parents, key=lambda value: (value.count("/"), value)):
            member = tarfile.TarInfo("./" + path + "/")
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(member)
        for kind, path, data, mode in files:
            member = tarfile.TarInfo("./" + path)
            member.mode = mode
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                tar.addfile(member)
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = data
                tar.addfile(member)
            else:
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
    return (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
            + ar_member("control.tar.xz", lzma.compress(b"inert control"))
            + ar_member("data.tar.xz", output.getvalue()))


def authenticated(named):
    return [({"name": name}, package(files)) for name, files in sorted(named.items())]


def baseline():
    return {
        "base-files": [
            ("file", "etc/passwd", b"Debian account", 0o644),
            ("file", "etc/pam.d/login", b"signed PAM policy", 0o644),
            ("directory", "etc/empty-policy", b"", 0o755),
            ("file", "usr/share/doc/base-files/README", b"documentation", 0o644),
        ],
        "mount": [
            ("file", "usr/bin/mount", b"signed mount ELF", 0o4755),
            ("file", "usr/bin/umount", b"removed helper", 0o755),
        ],
        "systemd": [
            ("file", "usr/lib/systemd/systemd", b"signed init", 0o755),
            ("file", "usr/lib/systemd/systemd-networkd", b"signed networkd", 0o755),
            ("file", "usr/lib/systemd/systemd-journald", b"signed journald", 0o755),
            ("file", "usr/lib/systemd/systemd-logind", b"signed logind", 0o755),
            ("file", "usr/lib/systemd/system/systemd-networkd.service", b"signed unit", 0o644),
            ("directory", "usr/lib/systemd/system/multi-user.target.wants", b"", 0o755),
            ("file", "usr/lib/x86_64-linux-gnu/libsystemd.so.0", b"signed library", 0o644),
            ("file", "usr/share/dbus-1/system-services/org.freedesktop.systemd1.service",
             b"signed activation policy", 0o644),
        ],
        "systemd-resolved": [
            ("file", "usr/lib/systemd/systemd-resolved", b"signed resolved", 0o755),
            ("file", "usr/lib/systemd/system/systemd-resolved.service", b"signed unit", 0o644),
        ],
        "udev": [
            ("file", "usr/bin/udevadm", b"signed udevadm", 0o755),
            ("symlink", "usr/lib/systemd/systemd-udevd", "../../bin/udevadm", 0o777),
        ],
        components.prepare.KERNEL_PACKAGE: [
            ("file", "boot/vmlinuz-" + components.prepare.KERNEL_VERSION,
             b"signed kernel image", 0o644),
            ("directory", "usr/lib/modules/" + components.prepare.KERNEL_VERSION,
             b"", 0o755),
        ],
    }


class PackageComponentsTests(unittest.TestCase):
    def setUp(self):
        self.named = baseline()
        self.authenticated = authenticated(self.named)
        self.overlay = {"etc/passwd": {"type": "file", "mode": 0o644,
                                        "sha256": hashlib.sha256(b"overlay").hexdigest(),
                                        "size": 7}}
        self.workspace = Path("/synthetic/workspace")
        module_root = "usr/lib/modules/" + components.prepare.KERNEL_VERSION
        def regular(data, mode):
            return {"type": "regular", "mode": mode, "uid": 0, "gid": 0,
                    "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.generated_entries = {
            module_root + "/vmlinuz": regular(b"signed kernel image", 0o644),
            module_root + "/modules.dep": regular(b"signed depmod text", 0o644),
            module_root + "/modules.dep.bin": regular(b"signed depmod binary", 0o644),
        }
        patcher = mock.patch.object(components.generated, "expected_entries",
                                    return_value=self.generated_entries)
        self.generated = patcher.start()
        self.addCleanup(patcher.stop)
        self.plan = components.expected_components(
            self.authenticated, self.overlay, self.workspace)
        self.actual = {}
        for path, expected in self.plan["entries"].items():
            self.actual[path] = {"type": expected["type"], "mode": expected["mode"],
                                 "uid": expected["uid"], "gid": expected["gid"],
                                 "size": expected.get("size", 4096),
                                 "link": expected.get("target")}
        self.digests = {path: expected["sha256"]
                        for path, expected in self.plan["entries"].items()
                        if expected["type"] == "regular"}
        self.inventory = {
            path: {**entry, "type": "file" if entry["type"] == "regular"
                   else entry["type"]}
            for path, entry in self.actual.items()
        }
        self.inventory["etc/passwd"] = {"type": "file", "mode": 0o644}
        self.inventory["usr/share/doc/base-files/README"] = {
            "type": "file", "mode": 0o644}

    def inspect(self, *, read_link=None):
        return components.inspect_components(
            self.plan, self.overlay, self.inventory, self.actual.get,
            lambda path, size: self.digests[path], read_link)

    def test_signed_payload_derives_code_runtime_policy_parents_and_exceptions(self):
        expected = self.plan["entries"]
        for path in ("usr/lib/systemd/systemd", "usr/lib/systemd/systemd-networkd",
                     "usr/lib/systemd/systemd-journald", "usr/lib/systemd/systemd-logind",
                     "usr/lib/systemd/systemd-resolved", "usr/bin/udevadm",
                     "usr/lib/systemd/systemd-udevd",
                     "usr/lib/x86_64-linux-gnu/libsystemd.so.0",
                     "usr/share/dbus-1/system-services/org.freedesktop.systemd1.service",
                     "etc/pam.d/login", "etc/empty-policy", "usr/lib", "usr/lib/systemd",
                     "usr/lib/systemd/system/multi-user.target.wants"):
            self.assertIn(path, expected)
        self.assertNotIn("usr/share/doc/base-files/README", expected)
        self.assertNotIn("etc/passwd", expected)
        self.assertNotIn("usr/bin/umount", expected)
        self.assertEqual(self.plan["overlaid"], ("etc/passwd",))
        self.assertEqual(expected["usr/bin/mount"]["mode"], 0o555)
        self.assertEqual(expected["usr/lib/systemd/systemd-udevd"]["target"],
                         "../../bin/udevadm")
        report = self.inspect()
        self.assertEqual(report["components_checked"]["removed"],
                         len(components.REVIEWED_REMOVALS))
        self.assertEqual(report["overlaid_package_paths"], ("etc/passwd",))

    def test_public_entrypoint_uses_authenticated_closure(self):
        self.generated.reset_mock()
        with mock.patch.object(components.preflight, "authenticated_archives",
                               return_value=self.authenticated) as checked:
            report = components.inspect_authenticated_components(
                "signed-metadata", "hashed-archives", self.overlay, self.inventory,
                self.actual.get,
                lambda path, size: self.digests[path], workspace=self.workspace)
        checked.assert_called_once_with("signed-metadata", "hashed-archives")
        self.generated.assert_called_once()
        payloads, rows, overlay, workspace = self.generated.call_args.args
        self.assertIn(components.prepare.KERNEL_PACKAGE, payloads)
        self.assertEqual(next(row for row in rows if row["path"] ==
                              "boot/vmlinuz-" + components.prepare.KERNEL_VERSION)["packages"],
                         [components.prepare.KERNEL_PACKAGE])
        self.assertIs(overlay, self.overlay)
        self.assertIs(workspace, self.workspace)
        self.assertGreater(report["components_checked"]["regular"], 0)

    def test_generated_kernel_metadata_and_bytes_are_compared(self):
        path = "usr/lib/modules/" + components.prepare.KERNEL_VERSION + "/modules.dep.bin"
        self.assertEqual(self.plan["entries"][path], self.generated_entries[path])
        self.assertGreater(self.inspect()["components_checked"]["regular"], 0)
        self.actual[path]["mode"] = 0o600
        with self.assertRaisesRegex(ValueError, "type, mode, or owner differs"):
            self.inspect()
        self.actual[path]["mode"] = 0o644
        self.digests[path] = "0" * 64
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            self.inspect()

    def test_generated_kernel_cannot_replace_source_or_escape_parents(self):
        self.generated.return_value = {
            "usr/lib/systemd/systemd": self.generated_entries[
                "usr/lib/modules/" + components.prepare.KERNEL_VERSION + "/vmlinuz"]}
        with self.assertRaisesRegex(ValueError, "generated kernel path collides"):
            components.expected_components(self.authenticated, self.overlay,
                                           self.workspace)
        self.generated.return_value = {
            "usr/lib/unplanned/modules.dep": self.generated_entries[
                "usr/lib/modules/" + components.prepare.KERNEL_VERSION + "/modules.dep"]}
        with self.assertRaisesRegex(ValueError, "generated kernel parent"):
            components.expected_components(self.authenticated, self.overlay,
                                           self.workspace)

    def test_raw_file_metadata_bytes_and_parent_redirection_reject(self):
        path = "usr/lib/systemd/systemd-networkd"
        for field, value, message in (
            ("type", "symlink", "type, mode, or owner"),
            ("mode", 0o777, "type, mode, or owner"),
            ("uid", 1, "type, mode, or owner"),
            ("gid", 1, "type, mode, or owner"),
            ("size", 1, "size differs"),
        ):
            with self.subTest(field=field):
                original = self.actual[path][field]
                self.actual[path][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.inspect()
                self.actual[path][field] = original
        self.digests[path] = "0" * 64
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            self.inspect()
        self.digests[path] = self.plan["entries"][path]["sha256"]
        self.actual["usr/lib"]["type"] = "symlink"
        with self.assertRaisesRegex(ValueError, "type, mode, or owner"):
            self.inspect()

    def test_directory_size_is_not_required_from_raw_inventory(self):
        self.actual["usr/lib"]["size"] = None
        self.assertGreater(self.inspect()["components_checked"]["directory"], 0)

    def test_extra_component_and_unit_activation_paths_reject(self):
        extras = (
            "usr/lib/systemd/system/multi-user.target.wants/evil.service",
            "etc/systemd/system/evil.service",
            "run/systemd/system/evil.service",
            "usr/local/bin/payload",
            "opt/payload",
        )
        for path in extras:
            with self.subTest(path=path):
                self.inventory[path] = {"type": "file", "mode": 0o644}
                with self.assertRaisesRegex(ValueError,
                                            "unplanned security-sensitive raw rootfs entries"):
                    self.inspect()
                del self.inventory[path]
        self.inventory["usr/lib/systemd/system/multi-user.target.wants/evil.service"] = {
            "type": "symlink", "mode": 0o777}
        with self.assertRaisesRegex(ValueError, "unplanned security-sensitive"):
            self.inspect()

    def test_unplanned_diagnostic_reports_all_paths(self):
        self.inventory["opt"] = {"type": "directory", "mode": 0o755}
        self.inventory["etc/opt"] = {"type": "directory", "mode": 0o755}
        with self.assertRaisesRegex(ValueError,
                                    "unplanned security-sensitive raw rootfs entries") as error:
            self.inspect()
        self.assertIn("'etc/opt'", str(error.exception))
        self.assertIn("'opt'", str(error.exception))

    def test_package_manager_metadata_cannot_survive_raw_sealing(self):
        for path in ("var/lib/dpkg", "var/lib/dpkg/info/apt.postinst",
                     "var/lib/apt", "var/cache/apt"):
            with self.subTest(path=path):
                self.inventory[path] = {"type": "directory", "mode": 0o755}
                with self.assertRaisesRegex(ValueError, "package-manager metadata remains"):
                    self.inspect()
                del self.inventory[path]

    def test_removed_alternative_frontend_cannot_survive(self):
        self.actual["etc/alternatives"] = {"type": "directory"}
        with self.assertRaisesRegex(ValueError, "removed package path remains"):
            self.inspect()

    def test_ldconfig_cache_and_boot_unit_cannot_survive(self):
        for relative in components.prepare.REMOVED_LDCONFIG_PATHS:
            path = relative.removeprefix("/")
            with self.subTest(path=path):
                self.assertIn(path, self.plan["removed"])
                self.actual[path] = {"type": "regular"}
                with self.assertRaisesRegex(ValueError, "removed package path remains"):
                    self.inspect()
                del self.actual[path]

    def test_executable_outside_component_prefix_rejects_but_inert_data_does_not(self):
        path = "var/cache/payload"
        self.inventory[path] = {"type": "file", "mode": 0o755}
        with self.assertRaisesRegex(ValueError, "unplanned security-sensitive"):
            self.inspect()
        self.inventory[path]["mode"] = 0o644
        self.inspect()

    def test_source_overlay_may_account_for_extra_sensitive_path(self):
        path = "etc/zrpc-added.conf"
        self.overlay[path] = {"type": "file", "mode": 0o644,
                              "sha256": hashlib.sha256(b"source").hexdigest(),
                              "size": 6}
        self.inventory[path] = {"type": "file", "mode": 0o644}
        self.inspect()
        del self.overlay[path]
        with self.assertRaisesRegex(ValueError, "unplanned security-sensitive"):
            self.inspect()

    def test_matching_source_overlay_directory_keeps_package_identity(self):
        path = "etc/empty-policy"
        overlay = {**self.overlay, path: {"type": "directory", "mode": 0o755}}
        plan = components.expected_components(self.authenticated, overlay, self.workspace)
        self.assertIn(path, plan["entries"])
        self.assertNotIn(path, plan["overlaid"])
        overlay[path] = {"type": "directory", "mode": 0o700}
        with self.assertRaisesRegex(ValueError, "unreviewed source overlay"):
            components.expected_components(self.authenticated, overlay, self.workspace)

    def test_complete_inventory_and_signed_empty_directory_identity_required(self):
        del self.inventory["etc/empty-policy"]
        with self.assertRaisesRegex(ValueError, "raw inventory is missing"):
            self.inspect()
        self.inventory["etc/empty-policy"] = {"type": "directory", "mode": 0o755}
        self.actual["etc/empty-policy"]["type"] = "symlink"
        with self.assertRaisesRegex(ValueError, "type, mode, or owner"):
            self.inspect()
        self.actual["etc/empty-policy"]["type"] = "directory"
        self.inventory["usr/local"] = {"type": "symlink", "mode": 0o777}
        with self.assertRaisesRegex(ValueError, "unplanned security-sensitive"):
            self.inspect()

    def test_missing_critical_and_removed_path_present_reject(self):
        modified = baseline()
        modified["systemd"] = [item for item in modified["systemd"]
                               if item[1] != "usr/lib/systemd/systemd-networkd"]
        with self.assertRaisesRegex(ValueError, "critical package"):
            components.expected_components(authenticated(modified), self.overlay,
                                           self.workspace)
        self.actual["usr/bin/umount"] = {"type": "regular"}
        with self.assertRaisesRegex(ValueError, "removed package path remains"):
            self.inspect()

    def test_unreviewed_overlay_and_mode_transform_reject(self):
        overlay = {**self.overlay, "usr/lib/systemd/systemd": {"type": "file"}}
        with self.assertRaisesRegex(ValueError, "unreviewed source overlay"):
            components.expected_components(self.authenticated, overlay, self.workspace)
        changed = baseline()
        changed["mount"] = [(kind, path, data, 0o755 if path == "usr/bin/mount" else mode)
                            for kind, path, data, mode in changed["mount"]]
        with self.assertRaisesRegex(ValueError, "mount helper differs"):
            components.expected_components(authenticated(changed), self.overlay,
                                           self.workspace)
        changed = baseline()
        changed["systemd"].append(("file", "usr/lib/systemd/privileged",
                                   b"unexpected SUID", 0o4755))
        with self.assertRaisesRegex(ValueError, "unreviewed package component mode"):
            components.expected_components(authenticated(changed), self.overlay,
                                           self.workspace)
        with mock.patch.object(components.prepare, "ROOT_REMOVE_FILES", ("/usr/bin/umount",)):
            with self.assertRaisesRegex(ValueError, "RemoveFiles differs"):
                components.expected_components(self.authenticated, self.overlay,
                                               self.workspace)

    def test_symlink_target_size_and_long_link_reader_reject(self):
        path = "usr/lib/systemd/systemd-udevd"
        self.actual[path]["link"] = "../../bin/wrong"
        with self.assertRaisesRegex(ValueError, "symlink target differs"):
            self.inspect()
        self.actual[path]["link"] = None
        with self.assertRaisesRegex(ValueError, "target was not read"):
            self.inspect()
        self.inspect(read_link=lambda name, size: "../../bin/udevadm")
        self.actual[path]["size"] += 1
        with self.assertRaisesRegex(ValueError, "symlink size differs"):
            self.inspect(read_link=lambda name, size: "../../bin/udevadm")


if __name__ == "__main__":
    unittest.main()
