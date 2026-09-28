"""Offline comparison checks for two unapproved production disk candidates."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "verify_image_reproducibility", HERE / "verify_image_reproducibility.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def candidate(root, name, raw=b"the same candidate raw disk"):
    stage = root / name
    (stage / "artifacts").mkdir(parents=True)
    (stage / "output").mkdir()
    contents = {
        "inputs.lock.json": b'{"schema_version":6}',
        "candidate-manifest.json": b'{"status":"staged-unbuilt-unapproved"}',
        "artifacts/secure_boot_certificate": b"test certificate",
        "artifacts/zebra": b"test zebrad ELF",
        "output/zrpc-gcp.efi": b"test signed UKI placeholder",
        "output/zrpc-gcp.raw": raw,
    }
    for path, data in contents.items():
        (stage / path).write_bytes(data)
    report = {
        "schema_version": 1, "status": verifier.BUILT_STATUS,
        "source_commit": "a" * 40,
        "input_lock_sha256": digest(contents["inputs.lock.json"]),
        "candidate_manifest_sha256": digest(contents["candidate-manifest.json"]),
        "secure_boot_certificate_sha256": digest(
            contents["artifacts/secure_boot_certificate"]),
        "zebrad_elf_sha256": digest(contents["artifacts/zebra"]),
        "zebra_release_lock_sha256": "b" * 64,
        "reviewed_zebra_provenance_receipt_sha256": "c" * 64,
        "mkosi_package_sha256": "d" * 64,
        "uki_sha256": digest(contents["output/zrpc-gcp.efi"]),
        "raw_disk_sha256": digest(raw), "raw_disk_bytes": len(raw),
        "mkosi_executed": True, "image_built": True,
        "signed_uki_checked": True, "verity_userspace_verified": True,
        "gpt_roothash_matched": True,
        "boot_verified": False, "private_mode_approved": False,
        "zebra_attestation_independently_verified": False,
    }
    report_path = root / f"{name}.report.json"
    report_path.write_text(json.dumps(report))
    return stage, report_path, report


def save_report(path, report):
    path.write_text(json.dumps(report))


class VerifyImageReproducibilityTest(unittest.TestCase):
    def pair(self, root):
        first_stage, first_report, _ = candidate(root, "first")
        second_stage, second_report, _ = candidate(root, "second")
        return first_stage, first_report, second_stage, second_report

    def test_matching_distinct_raws_emit_only_unapproved_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.pair(Path(temporary))
            result = verifier.compare(*args)
            self.assertEqual(result["status"], verifier.MATCH_STATUS)
            self.assertEqual(result["raw_disk_sha256"], digest(
                b"the same candidate raw disk"))
            self.assertTrue(result["raw_bytes_compared"])
            self.assertTrue(result["distinct_stage_directories_checked"])
            self.assertTrue(result["distinct_report_files_checked"])
            self.assertTrue(result["distinct_raw_files_checked"])
            self.assertFalse(result["independent_builds_verified"])
            self.assertFalse(result["boot_verified"])
            self.assertFalse(result["private_mode_approved"])

    def test_matching_reports_cannot_hide_mismatched_build_identities(self):
        changes = {
            "source_commit": (None, "e" * 40),
            "mkosi_package_sha256": (None, "e" * 64),
            "zebra_release_lock_sha256": (None, "e" * 64),
            "reviewed_zebra_provenance_receipt_sha256": (None, "e" * 64),
            "input_lock_sha256": ("inputs.lock.json", b"changed lock"),
            "candidate_manifest_sha256": (
                "candidate-manifest.json", b"changed manifest"),
            "secure_boot_certificate_sha256": (
                "artifacts/secure_boot_certificate", b"changed public certificate"),
            "zebrad_elf_sha256": ("artifacts/zebra", b"changed zebrad ELF"),
            "uki_sha256": ("output/zrpc-gcp.efi", b"changed EFI"),
        }
        for field, (file_name, replacement) in changes.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                first_stage, first_report, second_stage, second_report = \
                    self.pair(Path(temporary))
                report = json.loads(second_report.read_text())
                if file_name is not None:
                    (second_stage / file_name).write_bytes(replacement)
                    report[field] = digest(replacement)
                else:
                    report[field] = replacement
                save_report(second_report, report)
                with self.assertRaisesRegex(ValueError, f"identity differs: {field}"):
                    verifier.compare(first_stage, first_report,
                                     second_stage, second_report)

    def test_changed_raw_with_fresh_receipt_is_nondeterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            first_stage, first_report, second_stage, second_report = \
                self.pair(Path(temporary))
            raw = b"a different candidate raw disk"
            (second_stage / "output/zrpc-gcp.raw").write_bytes(raw)
            report = json.loads(second_report.read_text())
            report["raw_disk_sha256"] = digest(raw)
            report["raw_disk_bytes"] = len(raw)
            save_report(second_report, report)
            with self.assertRaisesRegex(ValueError, "raw disk sizes differ"):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)
            raw = b"X" + b"the same candidate raw disk"[1:]
            (second_stage / "output/zrpc-gcp.raw").write_bytes(raw)
            report["raw_disk_sha256"] = digest(raw)
            report["raw_disk_bytes"] = len(raw)
            save_report(second_report, report)
            with self.assertRaisesRegex(ValueError, "candidate raw disk bytes differ"):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)

    def test_stale_raw_receipt_and_missing_or_incomplete_reports_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            first_stage, first_report, second_stage, second_report = \
                self.pair(Path(temporary))
            (second_stage / "output/zrpc-gcp.raw").write_bytes(b"changed raw")
            with self.assertRaisesRegex(ValueError, "differ from outer-runner report"):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)
            (second_stage / "output/zrpc-gcp.raw").write_bytes(
                b"the same candidate raw disk")
            report = json.loads(second_report.read_text())
            report["signed_uki_checked"] = False
            save_report(second_report, report)
            with self.assertRaisesRegex(ValueError, "lacks completed signed_uki_checked"):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)
            report["signed_uki_checked"] = True
            del report["mkosi_package_sha256"]
            save_report(second_report, report)
            with self.assertRaisesRegex(ValueError, "lacks mkosi_package_sha256"):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)
            second_report.unlink()
            with self.assertRaises(OSError):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)

    def test_stage_artifact_mutation_after_hash_check_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.pair(Path(temporary))
            original = verifier.compare_raws
            certificate = args[2] / "artifacts/secure_boot_certificate"

            def mutate_after_raw_compare(first, second):
                original(first, second)
                certificate.write_bytes(b"changed certificate")

            with mock.patch.object(verifier, "compare_raws", mutate_after_raw_compare):
                with self.assertRaisesRegex(ValueError, "changed during comparison"):
                    verifier.compare(*args)

    def test_stage_artifact_path_replacement_after_hash_check_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.pair(Path(temporary))
            original = verifier.compare_raws
            certificate = args[2] / "artifacts/secure_boot_certificate"

            def replace_after_raw_compare(first, second):
                original(first, second)
                data = certificate.read_bytes()
                certificate.rename(certificate.with_name("original-certificate"))
                certificate.write_bytes(data)

            with mock.patch.object(verifier, "compare_raws", replace_after_raw_compare):
                with self.assertRaisesRegex(ValueError, "changed during comparison"):
                    verifier.compare(*args)

    def test_same_stage_report_or_raw_inode_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            first_stage, first_report, second_stage, second_report = \
                self.pair(Path(temporary))
            with self.assertRaisesRegex(ValueError, "disjoint stage"):
                verifier.compare(first_stage, first_report,
                                 first_stage, second_report)
            with self.assertRaisesRegex(ValueError, "distinct outer-runner reports"):
                verifier.compare(first_stage, first_report,
                                 second_stage, first_report)
            second_raw = second_stage / "output/zrpc-gcp.raw"
            second_raw.unlink()
            os.link(first_stage / "output/zrpc-gcp.raw", second_raw)
            with self.assertRaisesRegex(ValueError, "one nonempty regular file"):
                verifier.compare(first_stage, first_report,
                                 second_stage, second_report)

    def test_cli_does_not_emit_success_report_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            first_stage, first_report, second_stage, second_report = \
                self.pair(Path(temporary))
            second_report.write_text('{"status":"blocked"}')
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = verifier.main(["compare", "--first-stage", str(first_stage),
                                      "--first-report", str(first_report),
                                      "--second-stage", str(second_stage),
                                      "--second-report", str(second_report)])
            self.assertEqual(code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(json.loads(stderr.getvalue())["status"], "blocked")

    def test_cli_emits_unapproved_report_on_exact_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            first_stage, first_report, second_stage, second_report = \
                self.pair(Path(temporary))
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = verifier.main(["compare", "--first-stage", str(first_stage),
                                      "--first-report", str(first_report),
                                      "--second-stage", str(second_stage),
                                      "--second-report", str(second_report)])
            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["status"], verifier.MATCH_STATUS)
            self.assertFalse(output["independent_builds_verified"])
            self.assertFalse(output["private_mode_approved"])


if __name__ == "__main__":
    unittest.main()
