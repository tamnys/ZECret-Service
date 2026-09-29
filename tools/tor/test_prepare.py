from __future__ import annotations

import io
from datetime import datetime, timezone
import tarfile
import tempfile
from pathlib import Path
import unittest

import prepare


class TorPreparationTests(unittest.TestCase):
    def test_release_hold_uses_observed_signature_timestamp(self) -> None:
        with self.assertRaisesRegex(ValueError, "release hold"):
            prepare.require_release_age(datetime(2026, 9, 28, tzinfo=timezone.utc))
        prepare.require_release_age(datetime(2026, 9, 29, tzinfo=timezone.utc))

    def test_rejects_archive_traversal_and_links(self) -> None:
        for name, kind in [("../escape", tarfile.REGTYPE), ("tor/link", tarfile.SYMTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "bad.tar.gz"
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.size = 1 if kind == tarfile.REGTYPE else 0
                    archive.addfile(member, io.BytesIO(b"x") if kind == tarfile.REGTYPE else None)
                with tarfile.open(path, "r:gz") as archive:
                    with self.assertRaises(ValueError):
                        prepare.checked_members(archive)

    def test_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bundle"
            path.write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                prepare.require_hash(path, "0" * 64)

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "tor"
            output.mkdir()
            marker = output / "marker"
            marker.write_text("keep")
            with self.assertRaisesRegex(ValueError, "already exists"):
                prepare.stage(output, None, None)
            self.assertEqual(marker.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
