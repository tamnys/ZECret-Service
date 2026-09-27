"""Synthetic failure tests; no upstream artifact or TDX image is exercised."""

import copy
from datetime import timedelta
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import verify_zebra_release as zebra


class ZebraArtifactTests(unittest.TestCase):
    def setUp(self):
        self.lock = zebra.load_lock()
        self.advisories = [{
            "ghsa_id": "GHSA-test-synthetic-0001",
            "updated_at": "2026-09-25T20:02:29Z",
            "published_at": "2026-09-25T20:02:29Z",
            "withdrawn_at": None,
            "vulnerabilities": [{
                "package": {"ecosystem": "rust", "name": "zebrad"},
                "vulnerable_version_range": ">= 6.4.0, < 6.4.2",
                "first_patched_version": None,
            }],
        }]
        count, digest = zebra.advisory_snapshot(self.advisories)
        self.lock["reviewed_advisory_count"] = count
        self.lock["reviewed_advisory_snapshot_sha256"] = digest
        self.release = {
            "id": self.lock["release_id"],
            "tag_name": self.lock["tag"],
            "target_commitish": self.lock["source_commit"],
            "published_at": self.lock["published_at"],
            "draft": False,
            "prerelease": False,
            "assets": [{
                "id": self.lock["asset"]["id"],
                "name": self.lock["asset"]["name"],
                "size": self.lock["asset"]["size"],
                "digest": "sha256:" + self.lock["asset"]["sha256"],
                "created_at": self.lock["asset"]["created_at"],
                "updated_at": self.lock["asset"]["updated_at"],
                "state": "uploaded",
            }],
        }
        self.tag_ref = {
            "ref": "refs/tags/" + self.lock["tag"],
            "object": {"type": "tag", "sha": self.lock["tag_object_sha"]},
        }
        self.tag_object = {
            "tag": self.lock["tag"],
            "sha": self.lock["tag_object_sha"],
            "object": {"type": "commit", "sha": self.lock["source_commit"]},
        }

    def metadata(self, now):
        return zebra.check_metadata(self.lock, self.release, self.tag_ref,
                                    self.tag_object, self.advisories, now)

    def test_age_hold_is_based_on_asset_creation(self):
        eligible = zebra.utc(self.lock["asset"]["created_at"]) + timedelta(days=7)
        self.assertEqual(self.metadata(eligible - timedelta(seconds=1))["status"],
                         "held-metadata-only-unapproved")
        self.assertEqual(self.metadata(eligible)["status"],
                         "age-eligible-metadata-only-unapproved")

    def test_upstream_replacement_and_new_advisory_block(self):
        now = zebra.utc(self.lock["asset"]["created_at"]) + timedelta(days=8)
        changes = [
            lambda: self.release["assets"][0].update(digest="sha256:" + "f" * 64),
            lambda: self.release["assets"][0].update(state="deleted"),
            lambda: self.release.update(target_commitish="f" * 40),
            lambda: self.tag_ref["object"].update(sha="f" * 40),
            lambda: self.advisories.append({**self.advisories[0],
                                            "ghsa_id": "GHSA-new-synthetic-0002"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                release = copy.deepcopy(self.release)
                tag_ref = copy.deepcopy(self.tag_ref)
                advisories = copy.deepcopy(self.advisories)
                change()
                with self.assertRaises(ValueError):
                    self.metadata(now)
                self.release, self.tag_ref, self.advisories = release, tag_ref, advisories

    def test_hold_precedes_any_archive_access(self):
        with tempfile.TemporaryDirectory(dir=zebra.ROOT) as root:
            output = Path(root) / "unused-output"
            with mock.patch.object(zebra, "live_preflight", return_value={
                    "status": "held-metadata-only-unapproved"}):
                with self.assertRaisesRegex(ValueError, "release hold"):
                    zebra.stage(self.lock, Path(root) / "missing-archive",
                                Path(root) / "missing-gh", output)
            self.assertFalse(output.exists())

    def test_attestation_must_match_pinned_source_and_subject(self):
        with tempfile.TemporaryDirectory(dir=zebra.ROOT) as root:
            verifier = Path(root) / "synthetic-gh"
            verifier.write_bytes(b"synthetic, never execute")
            self.lock["gh_verifier_executable_sha256"] = hashlib.sha256(
                verifier.read_bytes()).hexdigest()
            statement = {"predicateType": "https://slsa.dev/provenance/v1",
                         "subject": [{"name": self.lock["asset"]["name"],
                                      "digest": {"sha256": self.lock["asset"]["sha256"]}}]}
            response = mock.Mock(returncode=0, stdout=json.dumps([
                {"verificationResult": {"statement": statement}}]).encode())
            with mock.patch.object(zebra.subprocess, "run", return_value=response) as run:
                self.assertEqual(zebra.verify_gh(self.lock, verifier,
                                                 Path(root) / "archive"), 1)
            args = run.call_args.args[0]
            self.assertIn("--deny-self-hosted-runners", args)
            self.assertEqual(args[args.index("--signer-workflow") + 1],
                             self.lock["signer_workflow"])
            self.assertEqual(args[args.index("--source-digest") + 1],
                             self.lock["source_commit"])
            self.assertEqual(args[args.index("--source-ref") + 1],
                             "refs/tags/" + self.lock["tag"])
            statement["subject"][0]["digest"]["sha256"] = "f" * 64
            response.stdout = json.dumps([
                {"verificationResult": {"statement": statement}}]).encode()
            with mock.patch.object(zebra.subprocess, "run", return_value=response):
                with self.assertRaisesRegex(ValueError, "subject or predicate"):
                    zebra.verify_gh(self.lock, verifier, Path(root) / "archive")

    def test_archive_rejects_extra_members_links_and_non_x86_elf(self):
        with tempfile.TemporaryDirectory(dir=zebra.ROOT) as root:
            root = Path(root)
            good_header = bytearray(64)
            good_header[:6] = b"\x7fELF\x02\x01"
            good_header[16:18] = b"\x03\x00"
            good_header[18:20] = b"\x3e\x00"
            variants = [
                ("extra", dict(extra=b"unreviewed")),
                ("link", dict(link=True)),
                ("arm", dict(binary=bytes(good_header[:18] + b"\xb7\x00" + good_header[20:]))),
            ]
            for name, options in variants:
                with self.subTest(name=name):
                    archive = root / (name + ".tar.gz")
                    with tarfile.open(archive, "w:gz") as package:
                        for member_name in sorted(zebra.TAR_MEMBERS):
                            content = (bytes(good_header) if member_name == "zebrad"
                                       else b"synthetic public text")
                            if member_name == "zebrad":
                                content = options.get("binary", content)
                            member = tarfile.TarInfo(member_name)
                            if member_name == "zebrad" and options.get("link"):
                                member.type = tarfile.SYMTYPE
                                member.linkname = "README.md"
                                package.addfile(member)
                            else:
                                member.size = len(content)
                                package.addfile(member, io.BytesIO(content))
                        if "extra" in options:
                            member = tarfile.TarInfo("unexpected")
                            member.size = len(options["extra"])
                            package.addfile(member, io.BytesIO(options["extra"]))
                    with self.assertRaises(ValueError):
                        zebra.extract_zebrad(archive, root / (name + ".out"))


if __name__ == "__main__":
    unittest.main()
