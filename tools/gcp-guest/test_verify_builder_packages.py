"""Synthetic direct builder archive tests; no Debian signature or image build."""

from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_builder_packages as builder


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class DirectBuilderPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="gcp-builder-packages-synthetic-",
            dir=os.environ.get("CODEX_TMP_DIR"),
        )
        self.root = Path(self.temporary.name)
        self.archives = self.root / "debs"
        self.archives.mkdir()
        self.lock_path = self.root / "lock.json"
        self.identities_path = self.root / "identities.json"
        self.inrelease = self.root / "InRelease"
        self.index = self.root / "Packages.xz"
        self.packages = []
        stanzas = []
        for name in sorted(builder.DIRECT_PACKAGES):
            content = b"!<arch>\n" + name.encode()
            digest = sha256(content)
            (self.archives / f"{digest}.deb").write_bytes(content)
            package = {
                "name": name, "version": "1.0", "architecture": "all" if name in {"mkosi", "systemd-ukify"} else "amd64",
                "filename": f"pool/main/{name}/{name}_1.0.deb", "size": len(content), "sha256": digest,
            }
            self.packages.append(package)
            stanzas.append("\n".join(f"{field}: {package[key]}" for field, key in (
                ("Package", "name"), ("Version", "version"), ("Architecture", "architecture"),
                ("Filename", "filename"), ("Size", "size"), ("SHA256", "sha256"),
            )))
        self.index.write_bytes(lzma.compress(("\n\n".join(stanzas) + "\n\n").encode()))
        epoch = int(datetime(2026, 9, 17, tzinfo=timezone.utc).timestamp())
        self.inrelease.write_text(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            "Origin: Debian\nCodename: trixie\nDate: Thu, 17 Sep 2026 00:00:00 +0000\n"
            "Architectures: amd64\nComponents: main\nSHA256:\n"
            f" {sha256(self.index.read_bytes())} {self.index.stat().st_size} main/binary-amd64/Packages.xz\n"
            "-----BEGIN PGP SIGNATURE-----\nsynthetic\n"
        )
        self.lock = {"schema_version": 1, "status": "candidate-unbuilt-unapproved",
                     "snapshot": "https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                     "packages": self.packages}
        self.identities = {
            "mkosi_source": {"distribution_package_version": "25.3-7"},
            "downloaded_metadata": {"trixie_snapshot_candidate": {
                "url": self.lock["snapshot"], "inrelease_sha256": sha256(self.inrelease.read_bytes()),
                "main_binary_amd64_packages_xz_sha256": sha256(self.index.read_bytes()),
                "main_binary_amd64_packages_xz_size": self.index.stat().st_size,
                "signed_release_date_epoch": epoch,
            }},
        }
        self.write_metadata()

    def tearDown(self):
        self.temporary.cleanup()

    def write_metadata(self):
        self.lock_path.write_text(json.dumps(self.lock))
        self.identities_path.write_text(json.dumps(self.identities))

    def verify(self):
        with patch.object(builder.debian_snapshot, "verify_signature"):
            return builder.verify(self.inrelease, self.index, self.archives,
                                  lock_path=self.lock_path,
                                  identities_path=self.identities_path)

    def test_synthetic_archives_match_but_do_not_approve(self):
        report = self.verify()
        self.assertEqual(report["package_count"], len(builder.DIRECT_PACKAGES))
        self.assertEqual(report["status"], "direct-builder-archives-matched-signed-snapshot")
        self.assertFalse(report["complete_builder_toolchain"])
        self.assertFalse(report["image_built"])
        self.assertFalse(report["private_mode_approved"])

    def test_modified_or_missing_archive_rejected(self):
        archive = self.archives / f'{self.packages[0]["sha256"]}.deb'
        archive.write_bytes(b"!<arch>\n" + b"tampered")
        with self.assertRaisesRegex(ValueError, "local direct builder archive differs"):
            self.verify()
        archive.unlink()
        with self.assertRaisesRegex(ValueError, "local direct builder archive differs"):
            self.verify()

    def test_signed_index_and_reviewed_hash_must_both_match(self):
        self.index.write_bytes(self.index.read_bytes() + b"x")
        with self.assertRaisesRegex(ValueError, "package index differs"):
            self.verify()
        self.index.write_bytes(lzma.compress(b"Package: substituted\n\n"))
        self.identities["downloaded_metadata"]["trixie_snapshot_candidate"]["main_binary_amd64_packages_xz_sha256"] = sha256(self.index.read_bytes())
        self.identities["downloaded_metadata"]["trixie_snapshot_candidate"]["main_binary_amd64_packages_xz_size"] = self.index.stat().st_size
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, "package index differs"):
            self.verify()

    def test_wrong_package_choice_or_missing_direct_package_rejected(self):
        self.lock["packages"][0]["version"] = "2.0"
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, "differs from signed index"):
            self.verify()
        self.lock["packages"].pop()
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, "package set incomplete"):
            self.verify()

    def test_wrong_snapshot_and_bad_signature_rejected(self):
        self.lock["snapshot"] = "https://snapshot.debian.org/archive/debian/20260927T000000Z/"
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, "differs from reviewed source and snapshot"):
            self.verify()
        self.lock["snapshot"] = self.identities["downloaded_metadata"]["trixie_snapshot_candidate"]["url"]
        self.write_metadata()
        with patch.object(builder.debian_snapshot, "verify_signature", side_effect=ValueError("bad signature")):
            with self.assertRaisesRegex(ValueError, "bad signature"):
                builder.verify(self.inrelease, self.index, self.archives,
                               lock_path=self.lock_path, identities_path=self.identities_path)

    def test_redirected_archive_and_duplicate_json_rejected(self):
        archive = self.archives / f'{self.packages[0]["sha256"]}.deb'
        data = archive.read_bytes()
        archive.unlink()
        target = self.root / "outside.deb"
        target.write_bytes(data)
        archive.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "local direct builder archive differs"):
            self.verify()
        self.lock_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            self.verify()

    def test_replaced_inrelease_after_signature_cannot_change_release_fields(self):
        original = self.inrelease.read_text()
        replacement = original.replace("main/binary-amd64/Packages.xz", "main/source/Sources.xz")

        def replace_source(_sealed_path, **_kwargs):
            self.inrelease.write_text(replacement)

        with patch.object(builder.debian_snapshot, "verify_signature", side_effect=replace_source):
            report = builder.verify(self.inrelease, self.index, self.archives,
                                    lock_path=self.lock_path, identities_path=self.identities_path)
        self.assertEqual(report["package_count"], len(builder.DIRECT_PACKAGES))
        self.assertNotEqual(self.inrelease.read_text(), original)

    def test_replaced_index_before_parse_cannot_add_unsigned_package(self):
        full_index = self.index.read_bytes()
        paragraphs = lzma.decompress(full_index).decode().strip().split("\n\n")
        self.index.write_bytes(lzma.compress(("\n\n".join(paragraphs[1:]) + "\n\n").encode()))
        old_hash = self.identities["downloaded_metadata"]["trixie_snapshot_candidate"]["main_binary_amd64_packages_xz_sha256"]
        old_size = self.identities["downloaded_metadata"]["trixie_snapshot_candidate"]["main_binary_amd64_packages_xz_size"]
        new_hash = sha256(self.index.read_bytes())
        new_size = self.index.stat().st_size
        self.inrelease.write_text(self.inrelease.read_text().replace(
            f"{old_hash} {old_size} main/binary-amd64/Packages.xz",
            f"{new_hash} {new_size} main/binary-amd64/Packages.xz",
        ))
        snapshot = self.identities["downloaded_metadata"]["trixie_snapshot_candidate"]
        snapshot["inrelease_sha256"] = sha256(self.inrelease.read_bytes())
        snapshot["main_binary_amd64_packages_xz_sha256"] = new_hash
        snapshot["main_binary_amd64_packages_xz_size"] = new_size
        self.write_metadata()
        parse = builder.debian_snapshot.package_records

        def replace_source(source):
            self.index.write_bytes(full_index)
            return parse(source)

        with patch.object(builder.debian_snapshot, "verify_signature"), patch.object(
                builder.debian_snapshot, "package_records", side_effect=replace_source):
            with self.assertRaisesRegex(ValueError, "differs from signed index"):
                builder.verify(self.inrelease, self.index, self.archives,
                               lock_path=self.lock_path, identities_path=self.identities_path)


if __name__ == "__main__":
    unittest.main()
