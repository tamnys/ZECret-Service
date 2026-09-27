"""Synthetic import-media tests. No boot, cloud, or hardware acceptance."""

import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gcp_import_archive as archive


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class ImportArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = os.environ.get("CODEX_TMP_DIR")
        if not base:
            raise RuntimeError("managed workspace scratch required")
        cls.scratch = tempfile.TemporaryDirectory(dir=base)
        cls.root = Path(cls.scratch.name)
        cls.raw = cls.root / "disk.raw"
        with cls.raw.open("wb") as output:
            output.truncate(archive.GIB)
        cls.package = cls.root / "reviewed.tar.gz"
        cls.receipt = archive.pack(cls.raw, cls.package)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def check(self, path, *, raw_sha=None, raw_size=None):
        return archive.verify(path, sha256(path), raw_sha or self.receipt["raw_disk_sha256"],
                              raw_size or self.receipt["raw_disk_bytes"])

    def make_tar(self, name, members, *, format="oldgnu"):
        target = self.root / name
        command = [archive.GNU_TAR, f"--format={format}", "--sparse", "--create",
                   "--gzip", f"--file={target}", f"--directory={self.root}"] + members
        subprocess.run(command, check=True, capture_output=True)
        return target

    def test_canonical_oldgnu_archive_binds_the_logical_disk(self):
        self.assertTrue(self.receipt["oldgnu_single_member_checked"])
        self.assertFalse(self.receipt["private_mode_approved"])
        self.assertFalse(self.receipt["toolchain_reviewed"])
        self.assertFalse(self.receipt["workspace_volume_override_used"])
        self.assertEqual(len(self.receipt["gnu_tar_sha256"]), 64)
        self.assertEqual(len(self.receipt["gnu_gzip_sha256"]), 64)
        self.assertEqual(len(self.receipt["python_executable_sha256"]), 64)
        self.assertEqual(self.check(self.package)["raw_disk_bytes"], archive.GIB)

    def test_same_raw_disk_packs_to_identical_archive_bytes(self):
        repeated = self.root / "repeated.tar.gz"
        second = archive.pack(self.raw, repeated)
        self.assertEqual(second["raw_disk_sha256"], self.receipt["raw_disk_sha256"])
        self.assertEqual(second["archive_sha256"], self.receipt["archive_sha256"])
        self.assertEqual(repeated.read_bytes(), self.package.read_bytes())

    def test_non_workspace_paths_require_visible_override(self):
        outside = self.root / "override.tar.gz"
        with mock.patch.object(archive, "WORKSPACE_ROOT", self.root / "unrelated"):
            with self.assertRaisesRegex(ValueError, "explicit --allow-non-workspace-paths"):
                archive.pack(self.raw, outside)
            receipt = archive.pack(self.raw, outside, allow_non_workspace_paths=True)
        self.assertTrue(receipt["workspace_volume_override_used"])
        self.assertFalse(receipt["toolchain_reviewed"])

    def test_inherited_path_cannot_select_the_archive_compressor(self):
        fake = self.root / "gzip"
        marker = self.root / "fake-gzip-ran"
        fake.write_text(f"#!/bin/sh\nprintf ran > '{marker}'\nexec /usr/bin/gzip \"$@\"\n")
        fake.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(self.root)}):
            output = self.root / "path-poisoned.tar.gz"
            receipt = archive.pack(self.raw, output)
        self.assertFalse(marker.exists())
        self.assertEqual(receipt["raw_disk_sha256"], self.receipt["raw_disk_sha256"])

    def test_changed_compressor_is_rejected_before_archive_publication(self):
        output = self.root / "changed-compressor.tar.gz"
        original_hash = archive._hash
        gzip_hashes = 0

        def changed_on_recheck(stream):
            nonlocal gzip_hashes
            result = original_hash(stream)
            if result == self.receipt["gnu_gzip_sha256"]:
                gzip_hashes += 1
                if gzip_hashes == 2:
                    return "0" * 64
            return result

        with mock.patch.object(archive, "_hash", side_effect=changed_on_recheck):
            with self.assertRaisesRegex(ValueError, "GNU gzip changed"):
                archive.pack(self.raw, output)
        self.assertEqual(gzip_hashes, 2)
        self.assertFalse(output.exists())

    def test_rejects_changed_archive_or_raw_disk_identity(self):
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            archive.verify(self.package, "0" * 64, self.receipt["raw_disk_sha256"], archive.GIB)
        with self.assertRaisesRegex(ValueError, "logical bytes"):
            self.check(self.package, raw_sha="0" * 64)
        with self.assertRaisesRegex(ValueError, "whole GiB"):
            self.check(self.package, raw_size=archive.GIB + 512)
        with self.assertRaisesRegex(ValueError, "at most 2048 GiB"):
            self.check(self.package, raw_size=2049 * archive.GIB)

    def test_rejects_wrong_name_second_member_and_links(self):
        (self.root / "other.raw").write_bytes(b"other")
        wrong = self.make_tar("wrong-name.tar.gz", ["other.raw"])
        with self.assertRaisesRegex(ValueError, "only a regular disk.raw"):
            self.check(wrong)
        extra = self.make_tar("extra-member.tar.gz", ["disk.raw", "other.raw"])
        with self.assertRaisesRegex(ValueError, "additional TAR member"):
            self.check(extra)
        link_dir = self.root / "link"
        link_dir.mkdir()
        (link_dir / "disk.raw").symlink_to(self.raw)
        linked = self.root / "linked.tar.gz"
        subprocess.run([archive.GNU_TAR, "--format=oldgnu", "--create", "--gzip",
                        f"--file={linked}", f"--directory={link_dir}", "disk.raw"],
                       check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "only a regular disk.raw"):
            self.check(linked)

    def test_rejects_pax_and_hidden_trailing_content(self):
        pax = self.make_tar("pax.tar.gz", ["disk.raw"], format="pax")
        with self.assertRaisesRegex(ValueError, "not GNU oldgnu"):
            self.check(pax)
        altered = self.root / "appended.tar.gz"
        altered.write_bytes(gzip.compress(gzip.decompress(self.package.read_bytes()) + b"X" * 512))
        with self.assertRaisesRegex(ValueError, "nonzero content"):
            self.check(altered)
        concatenated = self.root / "two-gzip-members.tar.gz"
        concatenated.write_bytes(self.package.read_bytes() + gzip.compress(b"\0" * 512))
        with self.assertRaisesRegex(ValueError, "gzip member"):
            self.check(concatenated)

    def test_rejects_sparse_header_size_disagreeing_with_extents(self):
        directory = self.root / "nonzero-sparse"
        directory.mkdir()
        raw = directory / "disk.raw"
        with raw.open("wb") as output:
            output.truncate(archive.GIB)
            output.seek(0)
            output.write(b"X" * 512)
            output.seek(1024 * 1024)
            output.write(b"Y" * 512)
        original = directory / "original.tar.gz"
        receipt = archive.pack(raw, original)
        data = bytearray(gzip.decompress(original.read_bytes()))
        size = tarfile.TarInfo.frombuf(data[:512], tarfile.ENCODING,
                                        "surrogateescape").size
        self.assertGreaterEqual(size, 512)
        data[124:136] = f"{size - 512:011o}\0".encode()
        data[148:156] = b" " * 8
        data[148:156] = f"{sum(data[:512]):06o}\0 ".encode()
        altered = directory / "mismatched-sparse.tar.gz"
        altered.write_bytes(gzip.compress(data, mtime=0))
        with self.assertRaisesRegex(ValueError, "stored size differs"):
            archive.verify(altered, sha256(altered), receipt["raw_disk_sha256"], archive.GIB)

    def test_rejects_corruption_output_overwrite_and_non_gib_input(self):
        corrupt = self.root / "corrupt.tar.gz"
        data = bytearray(self.package.read_bytes())
        data[-1] ^= 1
        corrupt.write_bytes(data)
        with self.assertRaises((gzip.BadGzipFile, OSError, tarfile.ReadError, zlib.error)):
            self.check(corrupt)
        with self.assertRaisesRegex(ValueError, "new file"):
            archive.pack(self.raw, self.package)
        small = self.root / "small" / "disk.raw"
        small.parent.mkdir()
        small.write_bytes(b"synthetic")
        with self.assertRaisesRegex(ValueError, "whole GiB"):
            archive.pack(small, self.root / "small.tar.gz")
        redirected = self.root / "redirected" / "disk.raw"
        redirected.parent.mkdir()
        redirected.symlink_to(self.raw)
        with self.assertRaises(OSError):
            archive.pack(redirected, self.root / "redirected.tar.gz")


if __name__ == "__main__":
    unittest.main()
