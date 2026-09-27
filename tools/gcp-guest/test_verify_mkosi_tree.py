"""Synthetic archive rejection tests; mocked membership is not trust evidence."""

import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import verify_mkosi_tree as tree


ENTRIES = [
    ("sub", "directory", None, 0o755),
    ("sub/source.py", "file", b"print('synthetic')\n", 0o644),
    ("entry", "symlink", "sub/source.py", 0o777),
]


def write_archive(path, entries, *, debian=False, comment=tree.COMMIT):
    headers = {} if debian else {"comment": comment}
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT, pax_headers=headers) as archive:
        if debian:
            info = tarfile.TarInfo(tree.DEBIAN_ROOT)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for name, kind, value, mode in entries:
            info = tarfile.TarInfo(f"{tree.DEBIAN_ROOT}/{name}" if debian else name)
            info.mode = mode
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "file":
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = value
                archive.addfile(info)
            else:
                raise AssertionError(kind)


class ArchiveComparisonTests(unittest.TestCase):
    def setUp(self):
        cache = tree.source.ROOT / ".codex-tmp"
        cache.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gcp-mkosi-tree-synthetic-", dir=cache)
        self.root = Path(self.temporary.name)
        self.debian = self.root / "orig.tar"
        self.upstream = self.root / "git.tar"
        write_archive(self.debian, ENTRIES, debian=True)
        write_archive(self.upstream, ENTRIES)

    def tearDown(self):
        self.temporary.cleanup()

    def compare_synthetic(self):
        with self.upstream.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        return tree.compare(self.debian, self.upstream, git_digest=digest,
                            git_size=self.upstream.stat().st_size)

    def test_matching_tree_includes_directory_file_symlink_and_modes(self):
        self.assertEqual(self.compare_synthetic(), len(ENTRIES))

    def test_content_mode_symlink_and_path_changes_are_rejected(self):
        cases = [
            ([ENTRIES[0], ("sub/source.py", "file", b"different", 0o644), ENTRIES[2]], "metadata or content differs"),
            ([ENTRIES[0], ("sub/source.py", "file", ENTRIES[1][2], 0o755), ENTRIES[2]], "metadata or content differs"),
            ([ENTRIES[0], ENTRIES[1], ("entry", "symlink", "sub/other.py", 0o777)], "metadata or content differs"),
            (ENTRIES[:-1], "paths differ"),
        ]
        for entries, error in cases:
            with self.subTest(error=error, entries=entries):
                write_archive(self.upstream, entries)
                with self.assertRaisesRegex(ValueError, error):
                    self.compare_synthetic()

    def test_wrong_pinned_bytes_or_commit_marker_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "pinned exact-commit bytes"):
            tree.compare(self.debian, self.upstream)
        write_archive(self.upstream, ENTRIES, comment="0" * 40)
        with self.assertRaisesRegex(ValueError, "commit marker differs"):
            self.compare_synthetic()

    def test_duplicate_traversal_symlink_escape_and_special_entry_are_rejected(self):
        cases = [
            (ENTRIES + [ENTRIES[1]], "duplicate archive path"),
            (ENTRIES + [("../escape", "file", b"x", 0o644)], "traversing archive path"),
            (ENTRIES[:-1] + [("entry", "symlink", "../escape", 0o777)], "traversing archive symlink"),
            (ENTRIES[:-1] + [("entry", "hardlink", "sub/source.py", 0o644)], "special or hardlink"),
        ]
        for entries, error in cases:
            with self.subTest(error=error):
                write_archive(self.upstream, entries)
                with self.assertRaisesRegex(ValueError, error):
                    self.compare_synthetic()

    def test_debian_archive_malformed_entries_are_rejected_too(self):
        write_archive(self.debian, ENTRIES + [("sub/source.py", "file", b"x", 0o644)], debian=True)
        with self.assertRaisesRegex(ValueError, "duplicate archive path"):
            self.compare_synthetic()
        write_archive(self.debian, ENTRIES + [("../escape", "file", b"x", 0o644)], debian=True)
        with self.assertRaisesRegex(ValueError, "traversing archive path"):
            self.compare_synthetic()

    def test_membership_and_bundled_commit_must_pass_before_source_only_result(self):
        identities = self.root / "identities.json"
        identities.write_text(json.dumps({"mkosi_source": {"commit": tree.COMMIT}}))
        shutil.copyfile(self.debian, self.root / "mkosi_25.3.orig.tar.gz")
        membership = {"status": "source-membership-verified-toolchain-unreviewed",
                      "image_built": False, "private_mode_approved": False}
        with mock.patch.object(tree.source, "verify", return_value=membership), mock.patch.object(tree, "compare", return_value=3):
            report = tree.verify(self.root / "InRelease", self.root / "Sources.xz", self.root,
                                 self.upstream, identities)
            self.assertEqual(report["status"], "source-tree-matched-toolchain-unreviewed")
            self.assertFalse(report["image_built"])
            self.assertFalse(report["private_mode_approved"])
        identities.write_text(json.dumps({"mkosi_source": {"commit": "0" * 40}}))
        with self.assertRaisesRegex(ValueError, "Git commit differs"):
            tree.verify(self.root / "InRelease", self.root / "Sources.xz", self.root,
                        self.upstream, identities)
        identities.write_text(json.dumps({"mkosi_source": {"commit": tree.COMMIT}}))
        with mock.patch.object(tree.source, "verify", return_value={"status": "simulation",
                                                                "image_built": False,
                                                                "private_mode_approved": False}):
            with self.assertRaisesRegex(ValueError, "membership was not established"):
                tree.verify(self.root / "InRelease", self.root / "Sources.xz", self.root,
                            self.upstream, identities)


if __name__ == "__main__":
    unittest.main()
