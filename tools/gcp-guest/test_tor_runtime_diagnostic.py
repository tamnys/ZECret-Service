import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tor_runtime_diagnostic as tor


class TorRuntimeDiagnosticTests(unittest.TestCase):
    def test_reviewed_builder_lock_contains_exact_gpgv_archive(self):
        self.assertEqual(tor.builder_gpgv_entry(), tor.GPGV)

    def test_signed_index_record_must_match_every_source_pin(self):
        key = (tor.TOR["name"], tor.TOR["version"], tor.TOR["architecture"])
        record = {"Filename": tor.TOR["filename"], "Size": str(tor.TOR["size"]),
                  "SHA256": tor.TOR["sha256"]}
        self.assertEqual(tor.signed_record({key: record}, tor.TOR), record)
        for changed in ("Filename", "Size", "SHA256"):
            wrong = dict(record)
            wrong[changed] = "changed"
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                tor.signed_record({key: wrong}, tor.TOR)
        with self.assertRaises(ValueError):
            tor.signed_record({}, tor.TOR)

    def test_executable_byte_pin_rejects_changed_content_and_size(self):
        data = b"reviewed fixture"
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(tor.require_pin(data, len(data), digest, "fixture"), data)
        with self.assertRaises(ValueError):
            tor.require_pin(data + b"!", len(data), digest, "fixture")
        with self.assertRaises(ValueError):
            tor.require_pin(b"changed fixture", len(data), digest, "fixture")


if __name__ == "__main__":
    unittest.main()
