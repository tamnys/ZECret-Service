"""Synthetic rootfs inspector negatives; no fixture is a boot or release."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import inspect_raw_rootfs as rootfs


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RawRootfsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-raw-rootfs-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.entries = {}
        for relative in sorted(rootfs.REQUIRED_FILES):
            parent = Path(relative).parent
            for ancestor in reversed((parent, *parent.parents)):
                if ancestor == Path("."):
                    continue
                path = self.stage / "rootfs" / ancestor
                path.mkdir(parents=True, exist_ok=True)
                self.entries["rootfs/" + ancestor.as_posix()] = {
                    "type": "directory", "mode": path.stat().st_mode & 0o777}
            path = self.stage / "rootfs" / relative
            data = ("approved " + relative + "\n").encode()
            path.write_bytes(data)
            path.chmod(0o555 if relative.startswith("usr/lib/zrpc/") else 0o644)
            self.entries["rootfs/" + relative] = {
                "type": "file", "mode": path.stat().st_mode & 0o777,
                "sha256": digest(data)}
        self.entries["rootfs"] = {"type": "directory",
                                  "mode": (self.stage / "rootfs").stat().st_mode & 0o777}
        link = self.stage / "rootfs/etc/systemd/system/default.target"
        link.parent.mkdir(parents=True)
        self.entries["rootfs/etc/systemd"] = {
            "type": "directory", "mode": link.parent.parent.stat().st_mode & 0o777}
        self.entries["rootfs/etc/systemd/system"] = {
            "type": "directory", "mode": link.parent.stat().st_mode & 0o777}
        link.symlink_to("/usr/lib/systemd/system/zrpc.target")
        self.entries["rootfs/etc/systemd/system/default.target"] = {
            "type": "symlink", "target": "/usr/lib/systemd/system/zrpc.target"}
        self.manifest = {"status": "staged-unbuilt-unapproved",
                         "image_built": False, "private_mode_approved": False,
                         "entries": self.entries}

    def test_all_staged_overlay_entries_are_selected(self):
        selected = rootfs.checked_overlay(self.manifest, self.stage)
        self.assertEqual(len(selected), len(self.entries) - 1)
        self.assertEqual(selected["etc/systemd/system/default.target"]["target"],
                         "/usr/lib/systemd/system/zrpc.target")
        self.assertEqual(selected["usr/lib/zrpc/zebrad"]["sha256"],
                         self.entries["rootfs/usr/lib/zrpc/zebrad"]["sha256"])
        self.assertFalse(self.manifest["private_mode_approved"])

    def test_staged_change_missing_critical_and_redirect_reject(self):
        changed = self.stage / "rootfs/etc/zrpc/zebra.toml"
        changed.write_bytes(b"changed settings\n")
        with self.assertRaisesRegex(ValueError, "staged rootfs file bytes differ"):
            rootfs.checked_overlay(self.manifest, self.stage)
        changed.write_bytes(b"approved etc/zrpc/zebra.toml\n")
        absent = self.entries.pop("rootfs/usr/lib/zrpc/zebrad")
        with self.assertRaisesRegex(ValueError, "critical staged rootfs"):
            rootfs.checked_overlay(self.manifest, self.stage)
        self.entries["rootfs/usr/lib/zrpc/zebrad"] = absent
        symlink = self.stage / "rootfs/etc/systemd/system/default.target"
        symlink.unlink()
        symlink.symlink_to("/dev/null")
        with self.assertRaisesRegex(ValueError, "staged rootfs symlink differs"):
            rootfs.checked_overlay(self.manifest, self.stage)

    def test_inode_parser_requires_pinned_reader_and_unambiguous_type(self):
        record = (b"Inode: 20   Type: regular    Mode:  0555   Flags: 0x80000\n"
                  b"User: 0   Group: 0   Project: 0   Size: 9\n")
        with mock.patch.object(rootfs.subprocess, "run", return_value=
                types.SimpleNamespace(returncode=0, stderr=rootfs.READER_BANNER,
                                      stdout=record)):
            parsed = rootfs.run_stat(Path("/synthetic/debugfs"), self.root, "usr/lib/zrpc/zebrad")
        self.assertEqual(parsed["type"], "regular")
        self.assertEqual((parsed["mode"], parsed["size"]), (0o555, 9))
        for stderr, stdout in ((rootfs.READER_BANNER + b"error\n", record),
                               (rootfs.READER_BANNER, record + record)):
            with mock.patch.object(rootfs.subprocess, "run", return_value=
                    types.SimpleNamespace(returncode=0, stderr=stderr, stdout=stdout)):
                with self.assertRaises(ValueError):
                    rootfs.run_stat(Path("/synthetic/debugfs"), self.root,
                                    "usr/lib/zrpc/zebrad")

    def test_changed_raw_bytes_or_symlink_fail_before_diagnostic_result(self):
        selected = rootfs.checked_overlay(self.manifest, self.stage)
        image = self.root / "copied-root.img"
        image.write_bytes(b"synthetic ext4 placeholder")
        file = "etc/zrpc/zebra.toml"
        expected = selected[file]
        poisoned = b"X" * expected["size"]
        fake = self.root / "debugfs"
        fake.write_text("#!/usr/bin/python3\n"
                        "import sys\n"
                        "sys.stderr.buffer.write(b'debugfs 1.47.2 (1-Jan-2025)\\n')\n"
                        f"sys.stdout.buffer.write({poisoned!r})\n")
        fake.chmod(0o755)
        self.assertNotEqual(rootfs.run_cat(fake, image, file,
                                           expected["size"], self.root),
                            expected["sha256"])
        critical = {name: selected[name] for name in ("etc", "etc/zrpc", file)}
        with mock.patch.object(rootfs, "run_stat", side_effect=lambda _r, _i, name, **_kw: {
                "type": "regular" if critical[name]["type"] == "file" else "directory",
                "mode": critical[name].get("mode", 0o777),
                "size": critical[name].get("size", 0),
                "link": None}):
            with self.assertRaisesRegex(ValueError, "raw rootfs file bytes differ"):
                rootfs.inspect_entries(fake, image, critical, self.root)
        with mock.patch.object(rootfs, "run_stat", side_effect=lambda _r, _i, name, **_kw: {
                "type": "symlink" if name == "etc" else
                        "regular" if selected[name]["type"] == "file" else
                        "directory" if selected[name]["type"] == "directory" else "symlink",
                "mode": selected[name].get("mode", 0o777),
                "size": selected[name].get("size", 0),
                "link": selected[name].get("target")}), \
                mock.patch.object(rootfs, "run_cat", side_effect=AssertionError(
                    "redirected parent must reject before extraction")):
            with self.assertRaisesRegex(ValueError, "raw rootfs entry type differs"):
                rootfs.inspect_entries(fake, image, selected, self.root)
        link = "etc/systemd/system/default.target"
        with mock.patch.object(rootfs, "run_stat", return_value={
                "type": "symlink", "mode": 0o777, "size": 9, "link": "/dev/null"}):
            with self.assertRaisesRegex(ValueError, "raw rootfs symlink target differs"):
                rootfs.inspect_entries(fake, image, {link: selected[link]}, self.root)

    def test_mismatched_verity_evidence_rejects_before_partition_read(self):
        layout = {"status": "diagnostic-gpt-only-unapproved",
                  "raw_disk_sha256": "a" * 64, "raw_disk_bytes": 8192}
        verified = {"status": "diagnostic-raw-root-verity-unapproved",
                    "raw_disk_sha256": "a" * 64, "raw_disk_bytes": 8192,
                    "verity_userspace_verified": False, "private_mode_approved": False}
        with mock.patch.object(rootfs.verity, "partition_images", side_effect=AssertionError(
                "unverified root must not be inspected")):
            with self.assertRaisesRegex(ValueError, "matching verified disk reports"):
                rootfs.inspect(self.root / "disk.raw", "a" * 64, 8192, 512,
                               layout, verified, self.root / "InRelease",
                               self.root / "Packages.xz", self.root / "archives",
                               self.stage, self.manifest, self.root)

    def test_installed_reader_must_match_authenticated_package_member(self):
        signed = b"\x7fELFsource-bound-debugfs"
        installed = self.root / "debugfs"
        installed.write_bytes(signed)
        installed.chmod(0o755)
        real_fstat = os.fstat

        def root_owned(fd):
            observed = real_fstat(fd)
            return types.SimpleNamespace(**{key: getattr(observed, key) for key in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns")}, st_uid=0)

        with mock.patch.object(rootfs, "READER", installed), \
                mock.patch.object(rootfs.os, "fstat", side_effect=root_owned):
            # The real tempfile is user-owned; only change ownership in the
            # test's fstat view, without changing the production reader check.
            self.assertEqual(rootfs.checked_reader(signed), digest(signed))
            installed.write_bytes(b"X" * len(signed))
            with self.assertRaisesRegex(ValueError, "installed debugfs differs"):
                rootfs.checked_reader(signed)

    def test_reader_package_rejects_changed_signed_index(self):
        entry = {"name": "e2fsprogs", "version": "reviewed", "architecture": "amd64",
                 "filename": "pool/e2fsprogs.deb", "size": 42, "sha256": "c" * 64}
        lock = {"schema_version": 1, "status": "apt-resolved-candidate-unbuilt-unapproved",
                "snapshot": "https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                "inrelease_sha256": "a" * 64, "signed_release_date_epoch": 123,
                "packages_index_sha256": "b" * 64, "packages": [entry]}
        lock_bytes = json.dumps(lock).encode()
        binary = b"\x7fELFsource-bound-debugfs"
        with mock.patch.object(rootfs.verity.debian_snapshot, "bounded_regular_bytes",
                               return_value=lock_bytes), \
                mock.patch.object(rootfs.verity.closure, "LOCK_BYTES", len(lock_bytes)), \
                mock.patch.object(rootfs.verity.closure, "LOCK_SHA256", digest(lock_bytes)), \
                mock.patch.object(rootfs.verity.debian_snapshot, "require_snapshot_age"), \
                mock.patch.object(rootfs.verity.debian_snapshot, "authenticated_index_bytes",
                                  return_value=(123, ("b" * 64, 5), b"index")) as index, \
                mock.patch.object(rootfs.verity.debian_snapshot, "package_records",
                                  return_value={("e2fsprogs", "reviewed", "amd64"): {"signed": True}}), \
                mock.patch.object(rootfs.verity.closure, "indexed_archive",
                                  return_value=b"signed-package") as archive, \
                mock.patch.object(rootfs.verity.esp, "regular_member_from_deb",
                                  return_value=binary):
            self.assertEqual(rootfs.signed_reader_bytes(
                self.root / "InRelease", self.root / "Packages.xz", self.root / "archives"),
                (binary, "c" * 64))
            self.assertEqual(archive.call_args.args[:2], (entry, {"signed": True}))
            index.return_value = (123, ("0" * 64, 5), b"index")
            with self.assertRaisesRegex(ValueError, "signed debugfs index differs"):
                rootfs.signed_reader_bytes(self.root / "InRelease",
                                           self.root / "Packages.xz", self.root / "archives")


if __name__ == "__main__":
    unittest.main()
