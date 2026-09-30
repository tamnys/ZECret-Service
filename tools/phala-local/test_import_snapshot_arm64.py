import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SOURCE = Path(__file__).with_name("import_snapshot_arm64.py")
SPEC = importlib.util.spec_from_file_location("import_snapshot_arm64", SOURCE)
local = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local)


class LocalSnapshotImportTests(unittest.TestCase):
    def test_lock_cannot_approve_private_or_cloud_use(self):
        original = local.load_lock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            for field in ("private_mode_approved", "cloud_deployment_approved"):
                changed = {**original, field: True}
                data = (json.dumps(changed) + "\n").encode()
                path.write_bytes(data)
                with patch.object(local, "LOCK", path), patch.object(
                        local, "LOCK_SHA256", hashlib.sha256(data).hexdigest()):
                    with self.assertRaisesRegex(ValueError, "malformed or approving"):
                        local.load_lock()

    def test_work_directory_symlink_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").mkdir()
            (root / "workspace").mkdir()
            (root / "workspace/link").symlink_to(root / "outside")
            with patch.object(local, "WORKSPACE", root / "workspace"):
                with self.assertRaisesRegex(ValueError, "regular directory"):
                    local.workspace_dir(str(root / "workspace/link"))

    def test_wheel_rejects_special_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "test.whl"
            link = zipfile.ZipInfo("zstandard/link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(link, "destination")
            with self.assertRaisesRegex(ValueError, "special file"):
                local.extract_wheel(wheel, root / "vendor")
            disguised_dir = zipfile.ZipInfo("zstandard/file")
            disguised_dir.external_attr = (stat.S_IFDIR | 0o755) << 16
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(disguised_dir, "not a directory")
            with self.assertRaisesRegex(ValueError, "special file"):
                local.extract_wheel(wheel, root / "vendor")
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("zstandard/__init__.py", b"first")
                archive.writestr("zstandard/__init__.py", b"second")
            (root / "vendor2").mkdir()
            with self.assertRaisesRegex(ValueError, "unsafe member"):
                local.extract_wheel(wheel, root / "vendor2")

    def test_known_advisory_blocks_wheel_use(self):
        for payload in (b'{"vulns":[{"id":"synthetic-advisory"}]}',
                        b'{"error":"unavailable"}'):
            with patch.object(local.urllib.request, "urlopen",
                              return_value=io.BytesIO(payload)):
                with self.assertRaisesRegex(ValueError, "advisory"):
                    local.require_no_known_advisories(
                        {"package": "zstandard", "version": "0.25.0"})


if __name__ == "__main__":
    unittest.main()
