"""Offline checks for the public snapshot image-input boundary."""

import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from deploy.phala import snapshot_package


class SnapshotPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.wheel = Path(temporary.name) / "zstandard.whl"

    def wheel_bytes(self, extra_name=None):
        body = io.BytesIO()
        with zipfile.ZipFile(body, "w") as package:
            for name in (
                    "zstandard/__init__.py",
                    "zstandard/backend_c.cpython-313-x86_64-linux-gnu.so",
                    "zstandard-0.25.0.dist-info/WHEEL"):
                package.writestr(name, b"fixture")
            if extra_name is not None:
                package.writestr(extra_name, b"unsafe")
        return body.getvalue()

    def identity(self, body):
        return {
            "wheel_size_bytes": len(body),
            "wheel_sha256": hashlib.sha256(body).hexdigest(),
        }

    def test_reviewed_decision_remains_unsigned_and_non_accepting(self):
        lock, content = snapshot_package.reviewed_lock()
        self.assertEqual(hashlib.sha256(content).hexdigest(), snapshot_package.LOCK_SHA256)
        self.assertFalse(lock["manifest_signed"])
        self.assertFalse(lock["private_mode_approved"])
        self.assertEqual(lock["archive_extraction_path"], "state/v28/testnet")
        self.assertEqual(lock["database_format_major_version"], 28)

    def test_wheel_requires_exact_bytes_and_safe_members(self):
        body = self.wheel_bytes()
        self.wheel.write_bytes(body)
        self.assertEqual(snapshot_package._checked_wheel(self.wheel, self.identity(body)), body)
        with self.assertRaisesRegex(ValueError, "pinned wheel"):
            snapshot_package._checked_wheel(self.wheel, self.identity(body + b"changed"))
        bad = self.wheel_bytes("../outside")
        self.wheel.write_bytes(bad)
        with self.assertRaisesRegex(ValueError, "unsafe members"):
            snapshot_package._checked_wheel(self.wheel, self.identity(bad))

    def test_symlinked_wheel_is_rejected(self):
        target = self.wheel.with_name("target.whl")
        target.write_bytes(self.wheel_bytes())
        self.wheel.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            snapshot_package._checked_wheel(self.wheel, self.identity(target.read_bytes()))


if __name__ == "__main__":
    unittest.main()
