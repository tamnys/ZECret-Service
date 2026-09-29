"""Synthetic rejection checks for the pinned mkosi clock-epoch expectation."""

import unittest
from unittest import mock

import fetch_guest_closure as guest
import inspect_raw_generated_usr as generated
import prepare


def source_rows():
    return [
        {"path": ".", "kind": "directory", "uid": 0, "gid": 0,
         "output_mode": 0o755},
        {"path": "usr", "kind": "directory", "uid": 0, "gid": 0,
         "output_mode": 0o755},
        {"path": "usr/lib", "kind": "directory", "uid": 0, "gid": 0,
         "output_mode": 0o755},
    ]


class GeneratedClockEpochTests(unittest.TestCase):
    def test_exact_empty_file_and_pinned_timestamp(self):
        entries = generated.expected_entries(source_rows(), {}, guest.SIGNED_RELEASE_EPOCH)
        self.assertEqual(entries, {generated.CLOCK_EPOCH: {
            "type": "regular", "mode": 0o644, "uid": 0, "gid": 0,
            "size": 0, "sha256": generated.EMPTY_SHA256,
            "mtime_ns": guest.SIGNED_RELEASE_EPOCH * 1_000_000_000,
        }})

    def test_unsigned_or_malformed_epoch_cannot_supply_expectation(self):
        for epoch in (0, guest.SIGNED_RELEASE_EPOCH + 1, True, "1789199741"):
            with self.subTest(epoch=epoch):
                with self.assertRaisesRegex(ValueError, "signed production source date"):
                    generated.expected_entries(source_rows(), {}, epoch)

    def test_package_or_overlay_cannot_replace_generated_clock(self):
        rows = source_rows()
        rows.append({"path": generated.CLOCK_EPOCH, "kind": "file"})
        with self.assertRaisesRegex(ValueError, "collides"):
            generated.expected_entries(rows, {}, guest.SIGNED_RELEASE_EPOCH)
        with self.assertRaisesRegex(ValueError, "collides"):
            generated.expected_entries(source_rows(),
                                       {generated.CLOCK_EPOCH: {"type": "file"}},
                                       guest.SIGNED_RELEASE_EPOCH)

    def test_parent_metadata_and_overlay_redirect_fail_closed(self):
        for field, value in (("kind", "symlink"), ("uid", 1),
                             ("output_mode", 0o777)):
            with self.subTest(field=field):
                rows = source_rows()
                rows[2][field] = value
                with self.assertRaisesRegex(ValueError, "parent differs"):
                    generated.expected_entries(rows, {}, guest.SIGNED_RELEASE_EPOCH)
        with self.assertRaisesRegex(ValueError, "redirected"):
            generated.expected_entries(source_rows(),
                                       {"usr/lib": {"type": "symlink", "target": "/tmp"}},
                                       guest.SIGNED_RELEASE_EPOCH)

    def test_source_rebase_and_ambiguous_source_fail_closed(self):
        with mock.patch.object(prepare, "SOURCE_COMMIT", "different"):
            with self.assertRaisesRegex(ValueError, "source re-review"):
                generated.expected_entries(source_rows(), {}, guest.SIGNED_RELEASE_EPOCH)
        rows = source_rows() + [dict(source_rows()[2])]
        with self.assertRaisesRegex(ValueError, "duplicate authenticated source path"):
            generated.expected_entries(rows, {}, guest.SIGNED_RELEASE_EPOCH)


if __name__ == "__main__":
    unittest.main()
