"""Synthetic finalizer checks; these do not build or approve a guest image."""

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seal_shadow = load("seal_shadow", "seal-shadow.py")
prepare = load("prepare_accounts", "prepare.py")
inspector = load("inspector_accounts", "inspect_raw_rootfs.py")


class SealShadowTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-seal-shadow-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "root"
        etc = self.root / "etc"
        etc.mkdir(parents=True)
        source = ROOT / "deploy/gcp/guest/rootfs/etc"
        for name in seal_shadow.ACCOUNT_FILES:
            shutil.copyfile(source / name, etc / name)
        (etc / "shadow").chmod(0o400)

    @staticmethod
    def owned_fstat(uid=0):
        actual_fstat = os.fstat

        def observed(fd):
            info = actual_fstat(fd)
            values = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns")}
            return types.SimpleNamespace(**values, st_uid=uid, st_gid=0)

        return observed

    def test_reviewed_source_and_staged_pins_match_final_inspector(self):
        for name, (size, expected_hash, stage_mode) in seal_shadow.ACCOUNT_FILES.items():
            source = ROOT / "deploy/gcp/guest/rootfs/etc" / name
            self.assertEqual((len(source.read_bytes()), hashlib.sha256(source.read_bytes()).hexdigest()),
                             (size, expected_hash))
            self.assertEqual(prepare.ACCOUNT_OUTPUTS[name][:2], (size, expected_hash))
            self.assertEqual(prepare.ACCOUNT_OUTPUTS[name][3], stage_mode)
            self.assertEqual(inspector.ACCOUNT_FILES["etc/" + name][:3],
                             (size, expected_hash, stage_mode))

    def test_exact_root_owned_files_are_sealed(self):
        with mock.patch.object(seal_shadow.os, "fstat", side_effect=self.owned_fstat()):
            seal_shadow.seal(self.root)
        self.assertEqual((self.root / "etc/shadow").stat().st_mode & 0o777, 0)

    def test_changed_bytes_mode_owner_and_redirect_reject_before_sealing(self):
        shadow = self.root / "etc/shadow"
        group = self.root / "etc/group"
        original = group.read_bytes()
        group.write_bytes(b"X" + original[1:])
        with mock.patch.object(seal_shadow.os, "fstat", side_effect=self.owned_fstat()):
            with self.assertRaisesRegex(ValueError, "reviewed account bytes differ: group"):
                seal_shadow.seal(self.root)
        self.assertEqual(shadow.stat().st_mode & 0o777, 0o400)
        group.write_bytes(original)

        shadow.chmod(0o644)
        with mock.patch.object(seal_shadow.os, "fstat", side_effect=self.owned_fstat()):
            with self.assertRaisesRegex(ValueError, "reviewed account metadata differs: shadow"):
                seal_shadow.seal(self.root)
        shadow.chmod(0o400)

        with mock.patch.object(seal_shadow.os, "fstat", side_effect=self.owned_fstat(1000)):
            with self.assertRaisesRegex(ValueError, "reviewed account metadata differs: passwd"):
                seal_shadow.seal(self.root)
        self.assertEqual(shadow.stat().st_mode & 0o777, 0o400)

        target = self.root / "shadow-target"
        shadow.rename(target)
        shadow.symlink_to(target)
        with mock.patch.object(seal_shadow.os, "fstat", side_effect=self.owned_fstat()):
            with self.assertRaises(OSError):
                seal_shadow.seal(self.root)

    def test_requires_explicit_build_root(self):
        with self.assertRaisesRegex(ValueError, "explicit non-root build tree"):
            seal_shadow.seal(Path("/"))
        with self.assertRaisesRegex(ValueError, "explicit non-root build tree"):
            seal_shadow.seal(Path("relative"))
        with mock.patch.object(seal_shadow.os, "geteuid", return_value=1):
            self.assertEqual(seal_shadow.main(), 1)


if __name__ == "__main__":
    unittest.main()
