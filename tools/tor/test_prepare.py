from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import prepare


class TorPreparationTests(unittest.TestCase):
    def test_release_hold_uses_package_publication_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "release hold"):
            prepare.require_release_age(datetime(2026, 9, 30, 19, 26, 41, tzinfo=timezone.utc))
        prepare.require_release_age(datetime(2026, 9, 30, 19, 26, 42, tzinfo=timezone.utc))

    def test_committed_signature_and_package_index_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prepare.verify_metadata(Path(temporary))

    def test_modified_package_index_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bad_index = Path(temporary) / "Packages.gz"
            bad_index.write_bytes(b"modified")
            with mock.patch.object(prepare, "PACKAGES", bad_index):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    prepare.verify_metadata(Path(temporary))

    def test_operator_stage_cannot_fetch_inside_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "tor"
            with mock.patch.object(prepare, "urlopen") as download:
                with self.assertRaisesRegex(ValueError, "release hold"):
                    prepare.stage(output, None)
            download.assert_not_called()
            self.assertFalse(output.exists())

    def test_version_accepts_release_or_git_suffix_only(self) -> None:
        prepare.require_tor_version("Tor version 0.4.9.13.\n", 0)
        prepare.require_tor_version("Tor version 0.4.9.13 (git-abcdef).\n", 0)
        with self.assertRaisesRegex(ValueError, "pinned version"):
            prepare.require_tor_version("Tor version 0.4.9.12.\n", 0)
        with self.assertRaisesRegex(ValueError, "pinned version"):
            prepare.require_tor_version("Tor version 0.4.9.13.1.\n", 0)


if __name__ == "__main__":
    unittest.main()
