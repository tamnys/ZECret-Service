"""Synthetic, non-root tests for the build-only mount ELF finalizer."""

import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "sanitize_mount", Path(__file__).with_name("sanitize-mount.py"))
sanitize_mount = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sanitize_mount)


class MountFinalizerTests(unittest.TestCase):
    def setUp(self):
        workspace = Path(__file__).parents[2] / ".codex-tmp"
        workspace.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="mount-finalizer-", dir=workspace)
        self.root = Path(self.temporary.name)
        self.mount = self.root / "usr/bin/mount"
        self.mount.parent.mkdir(parents=True)
        self.elf = b"\x7fELF\x02\x01" + b"synthetic mount executable"
        self.mount.write_bytes(self.elf)
        self.mount.chmod(0o755)
        self.digest = hashlib.sha256(self.elf).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def as_root_owned(self):
        actual = sanitize_mount.os.fstat

        def owner_mapping(fd):
            info = actual(fd)
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_mode=info.st_mode, st_size=info.st_size,
                                   st_mtime_ns=info.st_mtime_ns,
                                   st_ctime_ns=info.st_ctime_ns,
                                   st_nlink=info.st_nlink, st_uid=0, st_gid=0)

        return mock.patch.object(sanitize_mount.os, "fstat", side_effect=owner_mapping)

    def test_exact_helper_becomes_non_privileged(self):
        with self.as_root_owned():
            sanitize_mount.sanitize(self.root, self.digest, len(self.elf))
        self.assertEqual(self.mount.stat().st_mode & 0o7777, 0o555)
        self.assertEqual(self.mount.read_bytes(), self.elf)

    def test_tamper_link_and_mutable_mode_fail_before_sealing(self):
        with self.as_root_owned():
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                sanitize_mount.sanitize(self.root, "0" * 64, len(self.elf))
        self.assertEqual(self.mount.stat().st_mode & 0o7777, 0o755)

        self.mount.chmod(0o777)
        with self.as_root_owned():
            with self.assertRaisesRegex(ValueError, "metadata differs"):
                sanitize_mount.sanitize(self.root, self.digest, len(self.elf))
        self.mount.chmod(0o755)

        alias = self.root / "mount-alias"
        self.mount.rename(alias)
        self.mount.symlink_to(alias)
        with self.assertRaises(OSError):
            sanitize_mount.sanitize(self.root, self.digest, len(self.elf))

    def test_missing_staged_identity_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "identity or build root absent"):
            sanitize_mount.sanitize(self.root)


if __name__ == "__main__":
    unittest.main()
