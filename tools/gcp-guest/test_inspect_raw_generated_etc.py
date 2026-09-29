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


def credential_rows():
    return source_rows() + [
        {"path": generated.CREDSTORE_SOURCE, "kind": "file",
         "packages": ["systemd"], "uid": 0, "gid": 0,
         "source_mode": 0o644, "output_mode": 0o644,
         "size": generated.CREDSTORE_SOURCE_SIZE,
         "sha256": generated.CREDSTORE_SOURCE_SHA256},
        *({"path": path, "kind": "directory", "packages": ["systemd"],
           "uid": 0, "gid": 0,
           "source_mode": generated.CREDSTORE_ARCHIVE_MODE,
           "output_mode": generated.CREDSTORE_ARCHIVE_MODE}
          for path in generated.CREDSTORE_DIRECTORIES),
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

    def test_credential_store_modes_require_exact_signed_package_source(self):
        self.assertEqual(generated.credential_store_modes(credential_rows(), {}), {
            "etc/credstore": 0o700,
            "etc/credstore.encrypted": 0o700,
        })
        for changes in ({"sha256": "0" * 64}, {"size": 473},
                        {"packages": ["other"]}, {"uid": 1},
                        {"kind": "symlink"}, {"source_mode": 0o600},
                        {"output_mode": 0o600}):
            with self.subTest(config=changes):
                rows = credential_rows()
                rows[3].update(changes)
                with self.assertRaisesRegex(ValueError, "package source differs"):
                    generated.credential_store_modes(rows, {})
        for path in generated.CREDSTORE_DIRECTORIES:
            for changes in ({"kind": "file"}, {"packages": ["other"]},
                            {"uid": 1}, {"gid": 1},
                            {"source_mode": 0o700},
                            {"output_mode": 0o700}):
                with self.subTest(directory=path, changes=changes):
                    rows = credential_rows()
                    next(row for row in rows if row["path"] == path).update(changes)
                    with self.assertRaisesRegex(ValueError, "directory differs"):
                        generated.credential_store_modes(rows, {})

    def test_credential_store_missing_collision_or_malformed_source_rejects(self):
        for path in (generated.CREDSTORE_SOURCE,
                     *generated.CREDSTORE_DIRECTORIES):
            with self.subTest(path=path):
                rows = [row for row in credential_rows() if row["path"] != path]
                with self.assertRaises(ValueError):
                    generated.credential_store_modes(rows, {})
                with self.assertRaises(ValueError):
                    generated.credential_store_modes(credential_rows(),
                                                     {path: {"type": "directory"}})
        with self.assertRaisesRegex(ValueError, "duplicate authenticated"):
            rows = credential_rows()
            generated.credential_store_modes(rows + [dict(rows[-1])], {})
        with self.assertRaisesRegex(ValueError, "source row is malformed"):
            generated.credential_store_modes(credential_rows() + [{"path": 1}], {})
        with self.assertRaisesRegex(ValueError, "overlay required"):
            generated.credential_store_modes(credential_rows(), None)
        with self.assertRaisesRegex(ValueError, "parent is redirected"):
            generated.credential_store_modes(
                credential_rows(), {"etc": {"type": "symlink", "mode": 0o755}})
        with self.assertRaisesRegex(ValueError, "parent is redirected"):
            generated.credential_store_modes(credential_rows(), {"etc": None})


if __name__ == "__main__":
    unittest.main()
