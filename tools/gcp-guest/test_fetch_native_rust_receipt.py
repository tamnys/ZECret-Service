"""Fail-closed checks for the selected native Rust CI artifact handoff."""

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.request
import zipfile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fetch_native_rust_receipt", HERE / "fetch_native_rust_receipt.py")
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)
SHA = "a" * 40
DIGEST = "b" * 64
RUN_ID = 123


def fixtures():
    start = datetime(2026, 9, 28, tzinfo=timezone.utc)
    run = {"id": RUN_ID, "head_sha": SHA, "run_attempt": 2,
           "event": "workflow_dispatch", "status": "completed",
           "conclusion": "success",
           "path": ".github/workflows/gcp-native-cargo-gate.yml@refs/heads/test",
           "repository": {"full_name": "tamnys/ZECret-service", "id": 44},
           "run_started_at": start.isoformat(),
           "updated_at": (start + timedelta(minutes=5)).isoformat()}
    artifact = {"id": 456, "name": "native-rust-" + SHA,
                "expired": False, "digest": "sha256:" + DIGEST,
                "created_at": (start + timedelta(minutes=3)).isoformat(),
                "workflow_run": {"id": RUN_ID, "head_sha": SHA,
                                 "repository_id": 44}}
    return run, {"total_count": 1, "artifacts": [artifact]}


class NativeRustReceiptTest(unittest.TestCase):
    def select(self, run, listing):
        return receipt.select_artifact(
            run, listing, repository="tamnys/ZECret-service",
            revision=SHA, run_id=RUN_ID, attempt=2, digest=DIGEST)

    def test_select_exact_successful_attempt_and_digest(self):
        run, listing = fixtures()
        self.assertEqual(self.select(run, listing), 456)
        for key, wrong in (("head_sha", "c" * 40),
                           ("run_attempt", 1), ("event", "pull_request"),
                           ("conclusion", "failure"),
                           ("path", ".github/workflows/other.yml@main")):
            changed = dict(run, **{key: wrong})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(changed, listing)
        for key, wrong in (("digest", "sha256:" + "c" * 64),
                           ("expired", True),
                           ("created_at", "2026-09-27T23:59:00+00:00")):
            changed = dict(listing["artifacts"][0], **{key: wrong})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(run, {"total_count": 1, "artifacts": [changed]})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.select(run, {"total_count": 2, "artifacts": listing["artifacts"]})

    def test_no_token_on_cross_origin_redirect(self):
        request = urllib.request.Request(
            "https://api.github.com/repos/example/artifact",
            headers={"Authorization": "Bearer secret"})
        redirect = receipt.SafeRedirect().redirect_request(
            request, None, 302, "Found", {},
            "https://blob.core.windows.net/signed")
        self.assertNotIn("Authorization", redirect.headers)
        self.assertNotIn("Authorization", redirect.unredirected_hdrs)
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            receipt.SafeRedirect().redirect_request(
                request, None, 302, "Found", {}, "http://example.test/file")

    def test_gnu_tar_root_is_accepted_without_relaxing_member_paths(self):
        self.assertIsNone(receipt.safe_name("."))
        self.assertIsNone(receipt.safe_name("./"))
        with self.assertRaisesRegex(ValueError, "unsafe name"):
            receipt.safe_name("manifest.json")
        with self.assertRaisesRegex(ValueError, "escapes bundle"):
            receipt.safe_name("./../manifest.json")

    def test_only_regular_host_verifier_can_be_made_executable(self):
        with tempfile.TemporaryDirectory() as scratch:
            bundle = Path(scratch)
            artifacts = bundle / "artifacts"
            artifacts.mkdir()
            verifier = artifacts / "zrpc-uki-digest"
            verifier.write_bytes(b"checked native verifier")
            verifier.chmod(0o600)
            receipt.enable_verified_host_verifier(bundle)
            self.assertEqual(verifier.stat().st_mode & 0o777, 0o500)
            verifier.unlink()
            verifier.symlink_to(bundle / "elsewhere")
            with self.assertRaises(OSError):
                receipt.enable_verified_host_verifier(bundle)

    def test_reject_digest_change_and_tar_escape_before_exporter(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            tar_bytes = io.BytesIO()
            with tarfile.open(fileobj=tar_bytes, mode="w:") as tar:
                info = tarfile.TarInfo("./../escape")
                info.size = 4
                tar.addfile(info, io.BytesIO(b"evil"))
            archive = root / "artifact.zip"
            tar_name = f"native-rust-{SHA}.tar"
            with zipfile.ZipFile(archive, "w") as packed:
                packed.writestr(tar_name, tar_bytes.getvalue())
                packed.writestr(tar_name + ".sha256",
                                hashlib.sha256(tar_bytes.getvalue()).hexdigest()
                                + "  " + tar_name + "\n")
            actual = receipt.digest_file(archive)
            with self.assertRaisesRegex(ValueError, "pinned digest"):
                receipt.unpack_receipt(archive, root / "mismatch", SHA, DIGEST)
            with self.assertRaisesRegex(ValueError, "escapes bundle"):
                receipt.unpack_receipt(archive, root / "evil", SHA, actual)
            self.assertFalse((root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
