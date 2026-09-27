"""Synthetic parser tests; signature verification is mocked, not acceptance evidence."""

from datetime import datetime, timezone
import hashlib
import json
import lzma
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import verify_mkosi_source as source


def sha(data):
    return hashlib.sha256(data).hexdigest()


class SourceMembershipTests(unittest.TestCase):
    def setUp(self):
        cache = source.ROOT / ".codex-tmp"
        cache.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="gcp-mkosi-source-synthetic-", dir=cache)
        self.root = Path(self.temporary.name)
        self.files = {}
        entries = []
        metadata = {}
        for name, key in source.SOURCE_FILES.items():
            data = ("SYNTHETIC_" + name).encode()
            path = self.root / name
            path.write_bytes(data)
            self.files[name] = path
            metadata[key] = sha(data)
            entries.append(f" {sha(data)} {len(data)} {name}")
        self.stanza = (
            "Package: mkosi\nVersion: 25.3-7\nDirectory: pool/main/m/mkosi\n"
            "Checksums-Sha256:\n" + "\n".join(entries) + "\n\n"
        )
        self.sources = self.root / "Sources.xz"
        self.sources.write_bytes(lzma.compress(self.stanza.encode()))
        self.inrelease = self.root / "InRelease"
        self.write_release()
        metadata["trixie_snapshot_candidate"] = {
            "inrelease_sha256": source.digest(self.inrelease),
            "signed_release_date_epoch": int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()),
            "main_source_sources_xz_sha256": source.digest(self.sources),
            "main_source_sources_xz_size": self.sources.stat().st_size,
        }
        self.identities = self.root / "input-identities.json"
        self.identity_data = {
            "mkosi_source": {"distribution_package_version": source.SOURCE_VERSION},
            "downloaded_metadata": metadata,
        }
        self.write_identities()

    def tearDown(self):
        self.temporary.cleanup()

    def write_release(self):
        data = (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            "Origin: Debian\nCodename: trixie\nArchitectures: amd64\n"
            "Components: main\nDate: Wed, 01 Jan 2020 00:00:00 UTC\n"
            "SHA256:\n"
            f" {source.digest(self.sources)} {self.sources.stat().st_size} main/source/Sources.xz\n"
            "-----BEGIN PGP SIGNATURE-----\nSYNTHETIC\n"
        )
        self.inrelease.write_text(data)

    def write_identities(self):
        self.identities.write_text(json.dumps(self.identity_data))

    def verify_synthetic(self):
        with mock.patch.object(source.debian_snapshot, "verify_signature"):
            return source.verify(self.inrelease, self.sources, self.files, self.identities)

    def test_signed_index_binds_all_three_source_archives(self):
        report = self.verify_synthetic()
        self.assertEqual(report["status"], "source-membership-verified-toolchain-unreviewed")
        self.assertFalse(report["image_built"])
        self.assertFalse(report["private_mode_approved"])

    def test_changed_index_or_source_file_is_rejected(self):
        self.sources.write_bytes(self.sources.read_bytes() + b"TAMPER")
        with self.assertRaisesRegex(ValueError, "Sources index differs"):
            self.verify_synthetic()
        self.sources.write_bytes(lzma.compress(self.stanza.encode()))
        self.files["mkosi_25.3.orig.tar.gz"].write_bytes(b"TAMPER")
        with self.assertRaisesRegex(ValueError, "source file differs"):
            self.verify_synthetic()

    def test_missing_signed_source_entry_or_wrong_source_directory_is_rejected(self):
        self.inrelease.write_text(self.inrelease.read_text().replace("main/source/Sources.xz", "main/source/Other.xz"))
        self.identity_data["downloaded_metadata"]["trixie_snapshot_candidate"]["inrelease_sha256"] = source.digest(self.inrelease)
        self.write_identities()
        with self.assertRaisesRegex(ValueError, "required Debian index not signed"):
            self.verify_synthetic()
        self.sources.write_bytes(lzma.compress(self.stanza.replace(source.SOURCE_DIRECTORY, "pool/other").encode()))
        self.write_release()
        self.identity_data["downloaded_metadata"]["trixie_snapshot_candidate"].update(
            inrelease_sha256=source.digest(self.inrelease),
            main_source_sources_xz_sha256=source.digest(self.sources),
            main_source_sources_xz_size=self.sources.stat().st_size,
        )
        self.write_identities()
        with self.assertRaisesRegex(ValueError, "source directory differs"):
            self.verify_synthetic()

    def test_duplicate_record_and_checksum_are_rejected(self):
        for modified, error in (
            (self.stanza + self.stanza, "duplicate mkosi source record"),
            (self.stanza.replace("Checksums-Sha256:\n", "Checksums-Sha256:\n" + self.stanza.split("Checksums-Sha256:\n", 1)[1].splitlines()[0] + "\n"), "duplicate mkosi source checksum"),
        ):
            self.sources.write_bytes(lzma.compress(modified.encode()))
            self.write_release()
            self.identity_data["downloaded_metadata"]["trixie_snapshot_candidate"].update(
                inrelease_sha256=source.digest(self.inrelease),
                main_source_sources_xz_sha256=source.digest(self.sources),
                main_source_sources_xz_size=self.sources.stat().st_size,
            )
            self.write_identities()
            with self.assertRaisesRegex(ValueError, error):
                self.verify_synthetic()


if __name__ == "__main__":
    unittest.main()
