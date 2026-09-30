"""Synthetic, offline checks for the selected public Testnet snapshot import."""

from contextlib import nullcontext
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "phala_snapshot_import", HERE / "image/snapshot_import.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class ArchiveResponse(io.BytesIO):
    status = 200

    def __init__(self, body, url):
        super().__init__(body)
        self.url = url
        self.headers = {"Content-Length": str(len(body))}

    def geturl(self):
        return self.url


class SnapshotImportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "cache"
        self.state.mkdir()
        self.url = "https://snapshots.zfnd.org/testnet/fixture.tar.zst"

    def archive(self, name="state/v28/testnet/chain.db", kind=tarfile.REGTYPE):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w") as package:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = 4 if kind == tarfile.REGTYPE else 0
            package.addfile(info, io.BytesIO(b"test") if info.size else None)
        return body.getvalue()

    def value(self, body):
        return {
            "archive_url": self.url,
            "archive_size_bytes": len(body),
            "archive_sha256": hashlib.sha256(body).hexdigest(),
        }

    def import_body(self, body, value=None, opener=None):
        value = value or self.value(body)
        opener = opener or (lambda _request: ArchiveResponse(body, self.url))
        with patch.object(snapshot, "_lock", return_value=value):
            snapshot.ensure_snapshot(
                state=self.state, opener=opener,
                decompressor=lambda source: nullcontext(source))

    def test_selected_lock_is_exact_and_non_accepting(self):
        lock = snapshot._lock(HERE / "snapshot.lock.json", snapshot.LOCK_SHA256)
        self.assertEqual(lock["network"], "testnet")
        self.assertFalse(lock["manifest_signed"])
        self.assertFalse(lock["private_mode_approved"])
        self.assertEqual(lock["database_format_major_version"], 28)
        self.assertEqual(lock["archive_sha256"],
                         "e1702bb220a337f94496e1f65b683b63f22334fdc500c5421dd118e593358636")
        with self.assertRaisesRegex(ValueError, "reviewed decision"):
            snapshot._lock(HERE / "snapshot.lock.json", "0" * 64)

    def test_success_is_reused_without_fetching_again(self):
        body = self.archive()
        self.import_body(body)
        self.assertEqual((self.state / "state/v28/testnet/chain.db").read_bytes(), b"test")
        marker = json.loads((self.state / "state" / snapshot.MARKER).read_text())
        self.assertEqual(marker["archive_sha256"], hashlib.sha256(body).hexdigest())
        self.assertFalse((self.state / snapshot.ARCHIVE).exists())
        self.import_body(body, opener=lambda _request: self.fail("snapshot was fetched again"))

    def test_wrong_checksum_never_publishes_state(self):
        body = self.archive()
        value = self.value(body)
        value["archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "selected checksum"):
            self.import_body(body, value=value)
        self.assertFalse((self.state / "state").exists())
        self.assertFalse((self.state / "state" / snapshot.MARKER).exists())

    def test_unsafe_archive_members_fail_closed(self):
        for name, kind in (("state/v28/testnet/../../escape", tarfile.REGTYPE),
                           ("state/v28/testnet/link", tarfile.SYMTYPE)):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    self.state = Path(directory) / "cache"
                    self.state.mkdir()
                    with self.assertRaisesRegex(ValueError, "unsafe|link or special"):
                        self.import_body(self.archive(name, kind))
                    self.assertFalse((self.state / "state").exists())
                    self.assertFalse((self.state / "state" / snapshot.MARKER).exists())

    def test_incomplete_generated_download_is_retried(self):
        (self.state / snapshot.ARCHIVE).write_bytes(b"interrupted")
        (self.state / snapshot.STAGING).mkdir()
        (self.state / snapshot.STAGING / "partial").write_bytes(b"interrupted")
        self.import_body(self.archive())
        self.assertFalse((self.state / snapshot.ARCHIVE).exists())
        self.assertFalse((self.state / snapshot.STAGING).exists())
        self.assertTrue((self.state / "state" / snapshot.MARKER).is_file())

    def test_published_state_survives_interrupted_temp_cleanup(self):
        body = self.archive()
        self.import_body(body)
        (self.state / snapshot.ARCHIVE).write_bytes(b"leftover archive")
        (self.state / snapshot.STAGING).mkdir()
        (self.state / snapshot.STAGING / "partial").write_bytes(b"leftover staging")
        self.import_body(body, opener=lambda _request: self.fail("downloaded again"))
        self.assertEqual((self.state / "state/v28/testnet/chain.db").read_bytes(), b"test")
        self.assertFalse((self.state / snapshot.ARCHIVE).exists())
        self.assertFalse((self.state / snapshot.STAGING).exists())

    def test_changed_import_marker_refuses_reuse(self):
        body = self.archive()
        self.import_body(body)
        (self.state / "state" / snapshot.MARKER).write_bytes(b"forged")
        with self.assertRaisesRegex(ValueError, "state or import marker"):
            self.import_body(body, opener=lambda _request: self.fail("downloaded again"))

    def test_unmarked_state_refuses_download(self):
        (self.state / "state").mkdir()
        with self.assertRaisesRegex(ValueError, "state or import marker"):
            self.import_body(self.archive(), opener=lambda _request: self.fail("downloaded"))

    def test_symlinked_generated_archive_refuses_download(self):
        target = self.state / "unrelated"
        target.write_bytes(b"preserve")
        (self.state / snapshot.ARCHIVE).symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.import_body(self.archive(), opener=lambda _request: self.fail("downloaded"))
        self.assertEqual(target.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
