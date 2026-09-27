"""Synthetic refusal tests; no package execution, image, or TDX evidence."""

from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import fetch_guest_closure as fetcher


class Response(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class GuestFetchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="gcp-guest-fetch-synthetic-", dir=os.environ.get("CODEX_TMP_DIR"),
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.metadata = self.root / "metadata"
        self.metadata.mkdir()
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.inrelease = b"synthetic signed metadata"
        self.index = b"synthetic package index"
        (self.metadata / "InRelease").write_bytes(self.inrelease)
        (self.metadata / "Packages.xz").write_bytes(self.index)
        self.archive = b"!<arch>\nsynthetic package"
        self.package = {
            "name": "example", "version": "1.0", "architecture": "amd64",
            "filename": "pool/main/e/example/example_1.0_amd64.deb",
            "size": len(self.archive), "sha256": hashlib.sha256(self.archive).hexdigest(),
        }
        self.package["path"] = f'debs/{self.package["sha256"]}.deb'
        self.manifest = self.root / "package-closure.json"
        self.write_manifest()
        self.records = {
            ("example", "1.0", "amd64"): {
                "Filename": self.package["filename"],
                "Size": str(self.package["size"]),
                "SHA256": self.package["sha256"],
            },
        }

    def write_manifest(self):
        data = json.dumps([self.package], sort_keys=True).encode()
        self.manifest.write_bytes(data)
        self.manifest_bytes = len(data)
        self.manifest_sha256 = hashlib.sha256(data).hexdigest()

    def overrides(self):
        stack = ExitStack()
        signed_epoch = fetcher.SIGNED_RELEASE_EPOCH
        stack.enter_context(mock.patch.object(
            fetcher, "INRELEASE_SHA256", hashlib.sha256(self.inrelease).hexdigest(),
        ))
        stack.enter_context(mock.patch.object(
            fetcher, "PACKAGES_SHA256", hashlib.sha256(self.index).hexdigest(),
        ))
        stack.enter_context(mock.patch.object(fetcher, "PACKAGES_SIZE", len(self.index)))
        def authenticate(inrelease, index, expected_sha256):
            self.assertEqual(inrelease.read_bytes(), self.inrelease)
            self.assertEqual(index.read_bytes(), self.index)
            self.assertEqual(expected_sha256, hashlib.sha256(self.inrelease).hexdigest())
            return (signed_epoch,
                    (hashlib.sha256(self.index).hexdigest(), len(self.index)),
                    self.index)

        stack.enter_context(mock.patch.object(
            fetcher.debian_snapshot, "authenticated_index_bytes",
            side_effect=authenticate,
        ))
        stack.enter_context(mock.patch.object(
            fetcher.debian_snapshot, "package_records", return_value=self.records,
        ))
        return stack

    def fetch_metadata(self, opener):
        return fetcher.fetch_metadata(
            self.metadata, open_url=opener, manifest_path=self.manifest,
            manifest_sha256=self.manifest_sha256,
            manifest_bytes=self.manifest_bytes,
        )

    def prefetch(self, opener):
        return fetcher.prefetch_archives(
            self.archives, open_url=opener,
            manifest_path=self.manifest, manifest_sha256=self.manifest_sha256,
            manifest_bytes=self.manifest_bytes,
        )

    def verify_cached(self):
        return fetcher.verify_cached_archives(
            self.metadata, self.archives,
            manifest_path=self.manifest, manifest_sha256=self.manifest_sha256,
            manifest_bytes=self.manifest_bytes,
        )

    def test_committed_guest_manifest_matches_source_identity(self):
        data, packages = fetcher.reviewed_manifest()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         fetcher.prepare.PACKAGE_CLOSURE_SHA256)
        self.assertIn(fetcher.prepare.KERNEL_PACKAGE,
                      {package["name"] for package in packages})

    def test_checked_metadata_download_is_explicitly_signature_unchecked(self):
        (self.metadata / "InRelease").unlink()
        (self.metadata / "Packages.xz").unlink()
        expected = {
            fetcher.SNAPSHOT + "dists/trixie/InRelease": self.inrelease,
            fetcher.SNAPSHOT + "dists/trixie/main/binary-amd64/Packages.xz": self.index,
        }
        with self.overrides():
            report = self.fetch_metadata(
                lambda request: Response(expected[request.full_url], request.full_url),
            )
            self.assertEqual((report["downloaded_count"], report["reused_count"]), (2, 0))
            self.assertFalse(report["signed_snapshot_rechecked"])
            self.assertFalse(report["image_built"])
            self.assertFalse(report["private_mode_approved"])
            report = self.fetch_metadata(
                lambda _: self.fail("cached metadata unexpectedly used network"),
            )
            self.assertEqual((report["downloaded_count"], report["reused_count"]), (0, 2))

    def test_source_pin_drift_fails_before_network(self):
        with self.overrides():
            changed = bytearray(self.manifest.read_bytes())
            changed[-2] ^= 1
            self.manifest.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "source-reviewed candidate"):
                self.fetch_metadata(lambda _: self.fail("changed manifest used network"))
            with self.assertRaisesRegex(ValueError, "source-reviewed candidate"):
                self.prefetch(lambda _: self.fail("changed manifest used network"))
            with self.assertRaisesRegex(ValueError, "source-reviewed candidate"):
                self.verify_cached()
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_signed_index_disagreement_fails_offline(self):
        self.records[("example", "1.0", "amd64")]["SHA256"] = "00" * 32
        with self.overrides():
            with self.assertRaisesRegex(ValueError, "differs from signed Debian index"):
                self.verify_cached()
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_offline_index_membership_cannot_approve_archive_or_image(self):
        with self.overrides():
            report = fetcher.verify_index(
                self.metadata, manifest_path=self.manifest,
                manifest_sha256=self.manifest_sha256,
                manifest_bytes=self.manifest_bytes,
            )
        self.assertEqual(report["package_count"], 1)
        self.assertTrue(report["signed_snapshot_rechecked"])
        for key in ("archive_bytes_checked", "installed_closure_checked",
                    "package_scripts_executed", "image_built", "private_mode_approved"):
            self.assertFalse(report[key])
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_bad_signed_metadata_identity_fails_before_archive_network(self):
        with self.overrides():
            with mock.patch.object(fetcher, "SIGNED_RELEASE_EPOCH", 1):
                with self.assertRaisesRegex(ValueError, "signed guest snapshot differs"):
                    self.verify_cached()
        self.assertEqual(list(self.archives.iterdir()), [])

    def test_exact_archive_is_prefetched_then_verified_offline(self):
        urls = []

        def opener(request):
            urls.append(request.full_url)
            return Response(self.archive, request.full_url)

        with self.overrides():
            report = self.prefetch(opener)
            self.assertEqual((report["downloaded_count"], report["reused_count"]), (1, 0))
            self.assertFalse(report["signed_snapshot_rechecked"])
            self.assertTrue(report["archive_hashes_matched_source_lock"])
            for key in ("installed_closure_checked", "package_scripts_executed",
                        "image_built", "private_mode_approved"):
                self.assertFalse(report[key])
            self.assertEqual(urls, [fetcher.SNAPSHOT + self.package["filename"]])
            self.assertEqual((self.archives / (self.package["sha256"] + ".deb")).read_bytes(),
                             self.archive)
            report = self.verify_cached()
            self.assertTrue(report["signed_snapshot_rechecked"])
            self.assertTrue(report["archive_bytes_checked"])
            for key in ("installed_closure_checked", "package_scripts_executed",
                        "image_built", "private_mode_approved"):
                self.assertFalse(report[key])
            report = self.prefetch(
                lambda _: self.fail("cached archive unexpectedly used network"),
            )
            self.assertEqual((report["downloaded_count"], report["reused_count"]), (0, 1))

    def test_bad_download_and_redirect_publish_no_archive(self):
        with self.overrides():
            with self.assertRaisesRegex(ValueError, "downloaded builder archive"):
                self.prefetch(lambda request: Response(
                    b"!<arch>\n" + b"x" * (len(self.archive) - 8), request.full_url,
                ))
            self.assertEqual(list(self.archives.iterdir()), [])
            with self.assertRaisesRegex(ValueError, "redirect escaped"):
                self.prefetch(lambda _: Response(
                    self.archive, "https://example.invalid/archive.deb",
                ))
            self.assertEqual(list(self.archives.iterdir()), [])

    def test_corrupt_cache_is_never_replaced(self):
        target = self.archives / (self.package["sha256"] + ".deb")
        target.write_bytes(b"corrupt")
        with self.overrides():
            with self.assertRaisesRegex(ValueError, "existing builder archive"):
                self.prefetch(lambda _: self.fail("corrupt cache used network"))
            with self.assertRaisesRegex(ValueError, "existing builder archive"):
                self.verify_cached()
        self.assertEqual(target.read_bytes(), b"corrupt")

    def test_missing_cached_archive_fails_without_network(self):
        with self.overrides():
            with self.assertRaisesRegex(ValueError, "absent from offline cache"):
                self.verify_cached()
        self.assertEqual(list(self.archives.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
