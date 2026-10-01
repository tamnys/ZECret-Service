"""Negative checks for the one-CVM operator update boundary."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).with_name("update_existing.py")
spec = importlib.util.spec_from_file_location("update_existing", SOURCE)
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


class ExistingUpdateTests(unittest.TestCase):
    def setUp(self):
        self.detail = {
            "id": update.CVM, "app_id": update.APP,
            "vm_uuid": update.VM_UUID, "status": "running",
        }
        self.compose = {
            "public_logs": False, "public_sysinfo": False,
            "pre_launch_script": "script",
            "docker_compose_file": '{"services":{}}',
        }
        self.expected_script = update.OFFICIAL_SCRIPT_SHA256
        update.OFFICIAL_SCRIPT_SHA256 = update.digest(b"script")

    def tearDown(self):
        update.OFFICIAL_SCRIPT_SHA256 = self.expected_script

    def test_requires_original_cvm_and_launch_before_mutation(self):
        expected = update.digest(self.compose["docker_compose_file"].encode())
        update.validate_current(self.detail, self.compose, expected)
        for key, changed in (("id", "cvm_other"), ("app_id", "other"),
                             ("vm_uuid", "other"), ("status", "updating")):
            wrong = dict(self.detail, **{key: changed})
            with self.subTest(key=key), self.assertRaises(ValueError):
                update.validate_current(wrong, self.compose, expected)
        for key, changed in (("public_logs", True),
                             ("public_sysinfo", True),
                             ("pre_launch_script", "different"),
                             ("docker_compose_file", "different")):
            wrong = dict(self.compose, **{key: changed})
            with self.subTest(key=key), self.assertRaises(ValueError):
                update.validate_current(self.detail, wrong, expected)

    def test_candidate_is_exact_published_digest_and_nonapproving(self):
        receipt, compose = update.checked_candidate()
        self.assertEqual(update.digest(compose),
                         receipt["docker_compose_file_sha256"])
        self.assertEqual(receipt["image_ref"], update.IMAGE)
        self.assertIs(receipt["private_accepted"], False)

    def test_duplicate_provider_fields_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            update.decode_json(b'{"status":"running","status":"deleted"}')

    def test_token_requires_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "token"
            secret.write_bytes(b"phak_synthetic\n")
            os.chmod(secret, 0o600)
            self.assertEqual(update.checked_token(secret), "phak_synthetic")
            os.chmod(secret, 0o644)
            with self.assertRaisesRegex(ValueError, "permissions"):
                update.checked_token(secret)
            link = Path(directory) / "link"
            link.symlink_to(secret)
            with self.assertRaises(OSError):
                update.checked_token(link)


if __name__ == "__main__":
    unittest.main()
