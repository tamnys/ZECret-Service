"""Focused refusal tests for signed-snapshot builder archive acquisition."""

from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import fetch_builder_closure as fetcher


class Response(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class FetchBuilderClosureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="gcp-builder-fetch-synthetic-", dir=os.environ.get("CODEX_TMP_DIR"),
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archives = self.root / "debs"
        self.archives.mkdir()
        self.inrelease = self.root / "InRelease"
        self.inrelease.write_bytes(b"synthetic InRelease")
        self.index = self.root / "Packages.xz"
        self.index.write_bytes(b"synthetic index")
        self.good_archive = b"!<arch>\nsynthetic archive data"
        self.package = {
            "name": "example", "version": "1.0", "architecture": "amd64",
            "filename": "pool/main/e/example/example_1.0_amd64.deb",
            "size": len(self.good_archive),
            "sha256": hashlib.sha256(self.good_archive).hexdigest(),
        }
        self.lock = {
            "schema_version": 1,
            "status": "apt-resolved-candidate-unbuilt-unapproved",
            "snapshot": "https://snapshot.debian.org/archive/debian/20260918T000000Z/",
            "inrelease_sha256": "11" * 32,
            "packages_index_sha256": "22" * 32,
            "signed_release_date_epoch": 1789199741,
            "direct_lock_sha256": "33" * 32,
            "resolver": {},
            "packages": [self.package],
        }
        self.lock_path = self.root / "builder-lock.json"
        self.write_lock()
        self.records = {("example", "1.0", "amd64"): {
            "Filename": self.package["filename"], "Size": str(self.package["size"]),
            "SHA256": self.package["sha256"],
        }}

    def write_lock(self):
        self.lock_bytes = json.dumps(self.lock).encode()
        self.lock_path.write_bytes(self.lock_bytes)

    def authenticated(self):
        stack = ExitStack()
        stack.enter_context(mock.patch.object(fetcher.closure, "LOCK_BYTES", len(self.lock_bytes)))
        stack.enter_context(mock.patch.object(
            fetcher.closure, "LOCK_SHA256", hashlib.sha256(self.lock_bytes).hexdigest(),
        ))
        stack.enter_context(mock.patch.object(
            fetcher.debian_snapshot, "authenticated_index_bytes",
            return_value=(1789199741, ("22" * 32, len(b"synthetic index")), b"synthetic index"),
        ))
        stack.enter_context(mock.patch.object(
            fetcher.debian_snapshot, "package_records", return_value=self.records,
        ))
        return stack

    def fetch(self, opener):
        return fetcher.fetch(self.inrelease, self.index, self.archives,
                             lock_path=self.lock_path, open_url=opener)

    def test_downloads_exact_archive_then_reuses_without_network(self):
        urls = []

        def open_url(request):
            urls.append(request.full_url)
            return Response(self.good_archive, request.full_url)

        with self.authenticated():
            report = self.fetch(open_url)
            self.assertEqual((report["downloaded_count"], report["reused_count"]), (1, 0))
            self.assertFalse(report["complete_builder_toolchain"])
            self.assertEqual(urls, [self.lock["snapshot"] + self.package["filename"]])
            self.assertEqual((self.archives / (self.package["sha256"] + ".deb")).read_bytes(),
                             self.good_archive)
            report = self.fetch(lambda _: self.fail("cached archive triggered network"))
            self.assertEqual((report["downloaded_count"], report["reused_count"]), (0, 1))

    def test_corrupt_existing_archive_is_not_replaced(self):
        target = self.archives / (self.package["sha256"] + ".deb")
        target.write_bytes(b"corrupt")
        with self.authenticated():
            with self.assertRaisesRegex(ValueError, "existing builder archive"):
                self.fetch(lambda _: self.fail("corrupt cache triggered network"))
        self.assertEqual(target.read_bytes(), b"corrupt")

    def test_bad_download_is_not_published(self):
        with self.authenticated():
            with self.assertRaisesRegex(ValueError, "downloaded builder archive"):
                self.fetch(lambda request: Response(b"!<arch>\n" + b"x" * (len(self.good_archive) - 8),
                                                    request.full_url))
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_signed_index_disagreement_fails_before_network(self):
        self.records[("example", "1.0", "amd64")]["SHA256"] = "00" * 32
        with self.authenticated():
            with self.assertRaisesRegex(ValueError, "differs from signed index"):
                self.fetch(lambda _: self.fail("unsigned package triggered network"))
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_changed_source_reviewed_lock_fails_before_network(self):
        with self.authenticated():
            changed = bytearray(self.lock_bytes)
            changed[-2] ^= 1
            self.lock_path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "source-reviewed candidate"):
                self.fetch(lambda _: self.fail("changed lock triggered network"))
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_redirect_to_other_origin_is_rejected(self):
        with self.authenticated():
            with self.assertRaisesRegex(ValueError, "redirect escaped"):
                self.fetch(lambda _: Response(self.good_archive, "https://example.invalid/file.deb"))
        self.assertEqual(list(self.archives.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
