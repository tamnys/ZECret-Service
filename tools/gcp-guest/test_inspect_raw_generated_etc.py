"""Synthetic rejection checks for source-derived generated /etc entries."""

import unittest

import inspect_raw_generated_etc as generated


def source_rows():
    return [
        {"path": "etc", "kind": "directory", "uid": 0, "gid": 0,
         "output_mode": 0o755},
        {"path": generated.NSSWITCH_SOURCE, "kind": "file",
         "packages": ["libc-bin"], "uid": 0, "gid": 0,
         "source_mode": 0o644, "output_mode": 0o644,
         "size": generated.NSSWITCH_SIZE, "sha256": generated.NSSWITCH_SHA256},
        {"path": generated.TMPFILES_SOURCE, "kind": "file",
         "packages": ["systemd"], "uid": 0, "gid": 0,
         "source_mode": 0o644, "output_mode": 0o644,
         "size": generated.TMPFILES_SIZE, "sha256": generated.TMPFILES_SHA256},
    ]


class GeneratedEtcTests(unittest.TestCase):
    def test_exact_source_derived_entries(self):
        self.assertEqual(generated.expected_entries(source_rows(), {}), {
            generated.NSSWITCH_DESTINATION: {
                "type": "regular", "mode": 0o644, "uid": 0, "gid": 0,
                "size": 494, "sha256": generated.NSSWITCH_SHA256,
            },
            generated.MTAB_DESTINATION: {
                "type": "symlink", "mode": 0o777, "uid": 0, "gid": 0,
                "size": len(b"../proc/self/mounts"), "target": "../proc/self/mounts",
            },
        })

    def test_changed_or_missing_signed_source_rejects(self):
        for index, changes in ((1, {"sha256": "0" * 64}),
                               (1, {"size": 493}),
                               (1, {"packages": ["other"]}),
                               (1, {"uid": 1}),
                               (1, {"source_mode": 0o600}),
                               (2, {"sha256": "0" * 64}),
                               (2, {"packages": ["other"]}),
                               (2, {"kind": "symlink"})):
            with self.subTest(index=index, changes=changes):
                rows = source_rows()
                rows[index].update(changes)
                with self.assertRaisesRegex(ValueError, "package source differs"):
                    generated.expected_entries(rows, {})
        for absent in (generated.NSSWITCH_SOURCE, generated.TMPFILES_SOURCE):
            with self.subTest(absent=absent):
                rows = [row for row in source_rows() if row["path"] != absent]
                with self.assertRaisesRegex(ValueError, "package source differs"):
                    generated.expected_entries(rows, {})

    def test_source_or_overlay_cannot_replace_generated_entries(self):
        for path in (generated.NSSWITCH_DESTINATION, generated.MTAB_DESTINATION):
            with self.subTest(path=path):
                rows = source_rows() + [{"path": path, "kind": "file"}]
                with self.assertRaisesRegex(ValueError, "collides"):
                    generated.expected_entries(rows, {})
                with self.assertRaisesRegex(ValueError, "collides"):
                    generated.expected_entries(source_rows(), {path: {"type": "file"}})
        for path in (generated.NSSWITCH_SOURCE, generated.TMPFILES_SOURCE):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "package source differs"):
                    generated.expected_entries(source_rows(), {path: {"type": "file"}})

    def test_parent_redirection_and_ambiguous_source_reject(self):
        rows = source_rows()
        rows[0]["output_mode"] = 0o777
        with self.assertRaisesRegex(ValueError, "parent differs"):
            generated.expected_entries(rows, {})
        with self.assertRaisesRegex(ValueError, "parent is redirected"):
            generated.expected_entries(source_rows(),
                                       {"etc": {"type": "symlink", "target": "/tmp"}})
        with self.assertRaisesRegex(ValueError, "duplicate authenticated"):
            generated.expected_entries(source_rows() + [dict(source_rows()[1])], {})
        with self.assertRaisesRegex(ValueError, "overlay required"):
            generated.expected_entries(source_rows(), None)


if __name__ == "__main__":
    unittest.main()
