"""Synthetic negative checks for the offline Phala readback comparator."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check_readback.py")


class ReadbackComparisonTests(unittest.TestCase):
    def run_comparison(self, candidate, readback):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "app-compose.json"
            path.write_bytes(json.dumps(candidate).encode())
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--candidate", str(path)],
                input=readback if isinstance(readback, bytes) else json.dumps(readback).encode(),
                capture_output=True, check=False,
            )
        return result.returncode, json.loads(result.stdout), result.stderr

    def test_exact_match_is_still_only_unverified_diagnostic(self):
        candidate = {"docker_compose_file": "{\"services\":{}}", "public_logs": False}
        code, report, stderr = self.run_comparison(candidate, candidate)
        self.assertEqual((code, stderr), (0, b""))
        self.assertTrue(report["exact_manifest_match"])
        self.assertEqual(report["readback_provenance"], "caller_supplied_unverified")
        self.assertFalse(report["private_accepted"])

    def test_provider_defaults_and_script_are_detected_without_printing_script(self):
        marker = "SYNTHETIC_PRIVATE_CONFIG_MARKER"
        candidate = {"docker_compose_file": "{}", "public_logs": False,
                     "public_sysinfo": False}
        readback = {**candidate, "public_logs": True, "public_sysinfo": True,
                    "pre_launch_script": marker, "no_instance_id": False}
        code, report, stderr = self.run_comparison(candidate, readback)
        self.assertEqual((code, stderr), (1, b""))
        self.assertFalse(report["exact_manifest_match"])
        self.assertEqual(report["field_status"]["public_logs"], "changed")
        self.assertEqual(report["field_status"]["pre_launch_script"], "added")
        self.assertNotIn(marker, json.dumps(report))
        self.assertEqual(report["readback_pre_launch_script"]["bytes"], len(marker))

    def test_same_json_with_different_bytes_is_not_exact(self):
        candidate = {"public_logs": False}
        code, report, stderr = self.run_comparison(candidate, b'{ "public_logs": false }')
        self.assertEqual((code, stderr), (1, b""))
        self.assertTrue(report["semantic_manifest_match"])
        self.assertFalse(report["exact_manifest_match"])

    def test_duplicate_and_oversized_response_fail_closed(self):
        candidate = {"public_logs": False}
        for response in (b'{"public_logs":false,"public_logs":true}',
                         b" " * (1_048_576 + 1)):
            code, report, stderr = self.run_comparison(candidate, response)
            self.assertEqual((code, stderr), (2, b""))
            self.assertFalse(report["private_accepted"])


if __name__ == "__main__":
    unittest.main()
