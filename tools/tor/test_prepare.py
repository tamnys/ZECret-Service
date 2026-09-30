from __future__ import annotations

from datetime import datetime, timezone
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import prepare


class TorPreparationTests(unittest.TestCase):
    @staticmethod
    def package_tar(entries: list[tuple[str, bytes | None]]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, contents in entries:
                member = tarfile.TarInfo(name)
                if contents is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../../outside"
                    archive.addfile(member)
                else:
                    member.size = len(contents)
                    archive.addfile(member, io.BytesIO(contents))
        return output.getvalue()

    def test_single_regular_executable_is_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            archive_bytes = self.package_tar([
                ("./etc/tor/torrc", b"ignored"), ("./usr/bin/tor", b"tor-executable")
            ])
            def write_tar(_args, *, stdout, **_kwargs):
                stdout.write(archive_bytes)
                return SimpleNamespace(returncode=0)
            executable = scratch / "tor"
            with mock.patch.object(prepare.subprocess, "run", side_effect=write_tar):
                prepare.extract_tor_binary(scratch / "package.deb", scratch, executable)
            self.assertEqual(executable.read_bytes(), b"tor-executable")

    def test_duplicate_or_linked_executable_is_rejected(self) -> None:
        for entries in (
            [("./usr/bin/tor", b"one"), ("usr/bin/tor", b"two")],
            [("./usr/bin/tor", None)],
        ):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                scratch = Path(temporary)
                archive_bytes = self.package_tar(entries)
                def write_tar(_args, *, stdout, **_kwargs):
                    stdout.write(archive_bytes)
                    return SimpleNamespace(returncode=0)
                with mock.patch.object(prepare.subprocess, "run", side_effect=write_tar):
                    with self.assertRaisesRegex(ValueError, "unique regular Tor executable"):
                        prepare.extract_tor_binary(
                            scratch / "package.deb", scratch, scratch / "tor"
                        )

    def test_release_hold_uses_package_publication_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "release hold"):
            prepare.require_release_age(datetime(2026, 9, 30, 19, 26, 41, tzinfo=timezone.utc))
        self.assertFalse(prepare.require_release_age(datetime(2026, 9, 30, 19, 26, 42, tzinfo=timezone.utc)))

    def test_local_exception_is_limited_to_exact_reviewed_lock(self) -> None:
        before_hold = datetime(2026, 9, 30, 19, 26, 41, tzinfo=timezone.utc)
        self.assertTrue(prepare.require_release_age(
            before_hold, allow_v04913_local_hold_exception=True
        ))
        with tempfile.TemporaryDirectory() as temporary:
            modified_lock = Path(temporary) / "package.lock.json"
            modified_lock.write_bytes(prepare.LOCK_FILE.read_bytes() + b"\n")
            with mock.patch.object(prepare, "LOCK_FILE", modified_lock):
                with self.assertRaisesRegex(ValueError, "reviewed Tor lock"):
                    prepare.require_release_age(
                        before_hold, allow_v04913_local_hold_exception=True
                    )

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

    def test_local_exception_keeps_signed_metadata_required_before_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "tor"
            bad_release = Path(temporary) / "InRelease"
            bad_release.write_bytes(b"modified")
            with (mock.patch.object(prepare, "INRELEASE", bad_release),
                  mock.patch.object(prepare, "urlopen") as download):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    prepare.stage(output, None, allow_v04913_local_hold_exception=True)
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
