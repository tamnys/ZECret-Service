"""Synthetic suffix tests; only a native signed-package replay can validate mkosi output."""

import ctypes
import ctypes.util
import hashlib
import io
from pathlib import Path
import stat
import types
import unittest

import inspect_final_initrd as final
import prepare_initrd_basetree_profile as source


FILE = "usr/lib/modules/test-kernel/kernel/drivers/md/dm-verity.ko.xz"
METADATA = "usr/lib/modules/test-kernel/modules.dep"
CONTENTS = {FILE: b"reviewed module bytes", METADATA: b"reviewed depmod bytes"}
IDENTITIES = {name: (len(data), hashlib.sha256(data).hexdigest(), 0o644)
              for name, data in CONTENTS.items()}
SOURCE = types.SimpleNamespace(exact=source.exact, padded=source.padded)


def newc_member(name, data=b"", mode=stat.S_IFREG | 0o644, nlink=1, uid=0,
                declared_size=None):
    encoded = name.encode() + b"\0"
    fields = (1, mode, uid, 0, nlink, 0,
              len(data) if declared_size is None else declared_size,
              0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    assert len(header) == 110
    body = header + encoded
    body += b"\0" * (-len(body) % 4)
    body += data
    return body + b"\0" * (-len(data) % 4)


def archive(extra=(), omit=(), trailer=True):
    directories = sorted({p.as_posix() for name in CONTENTS for p in Path(name).parents
                          if p.as_posix() not in {".", "usr", "usr/lib"}},
                         key=lambda name: (name.count("/"), name))
    data = b"".join(newc_member(name, mode=stat.S_IFDIR | 0o755)
                    for name in directories if name not in omit)
    data += b"".join(newc_member(name, payload) for name, payload in CONTENTS.items()
                     if name not in omit)
    data += b"".join(extra)
    if trailer:
        data += newc_member("TRAILER!!!", mode=0)
        data += b"\0" * (-len(data) % 512)
    return data


class FinalInitrdTests(unittest.TestCase):
    def parse(self, data):
        return final.parse_cpio(io.BytesIO(data), IDENTITIES, SOURCE)

    def test_exact_package_and_replayed_metadata_succeeds_without_approval(self):
        result = self.parse(archive())
        self.assertEqual(result["file_count"], 2)
        self.assertEqual(result["decompressed_bytes"] % 512, 0)
        self.assertIn("unapproved", final.STATUS)

    def test_later_init_unit_and_unknown_module_cannot_override_boot(self):
        for name in ("init", "usr/lib/systemd/system/zrpc.service",
                     "usr/lib/modules/test-kernel/kernel/drivers/md/dm-crypt.ko.xz"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unknown or overriding"):
                self.parse(archive(extra=(newc_member(name, b"poison"),)))

    def test_changed_module_metadata_and_missing_required_entries_reject(self):
        changed = archive(extra=(newc_member(FILE, b"replacement"),))
        with self.assertRaises(ValueError):
            self.parse(changed)
        for missing in (FILE, METADATA, "usr/lib/modules/test-kernel/kernel"):
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "omitted"):
                self.parse(archive(omit={missing}))
        altered = archive().replace(CONTENTS[METADATA], b"changed depmod bytes")
        with self.assertRaisesRegex(ValueError, "differs from signed package"):
            self.parse(altered)

    def test_truncation_padding_and_second_archive_reject(self):
        valid = archive()
        for data in (valid[:-1], valid[:30], valid + b"\0" * 512,
                     valid + archive(), valid[:-1] + b"\x01"):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.parse(data)
        with self.assertRaisesRegex(ValueError, "truncated"):
            self.parse(archive(trailer=False))

    def test_symlink_hardlink_writable_directory_and_oversize_reject(self):
        cases = (
            newc_member("init", b"target", stat.S_IFLNK | 0o777),
            newc_member(FILE, CONTENTS[FILE], nlink=2),
            newc_member("usr/lib/modules/test-kernel/kernel", mode=stat.S_IFDIR | 0o777),
            newc_member(FILE, CONTENTS[FILE], declared_size=2**32 - 1),
        )
        for member in cases:
            with self.subTest(member=member[:20]), self.assertRaises(ValueError):
                self.parse(archive(extra=(member,)))

    def test_complete_zstd_frame_rejects_skippable_and_appended_frames(self):
        library_name = ctypes.util.find_library("zstd")
        if library_name is None:
            self.skipTest("native libzstd is absent in this synthetic test container")
        library = ctypes.CDLL(library_name)
        library_path = Path(library._name)
        if not library_path.is_absolute():
            paths = (Path("/usr/lib/aarch64-linux-gnu") / library_name,
                     Path("/usr/lib/x86_64-linux-gnu") / library_name)
            library_path = next((path.resolve() for path in paths if path.exists()), None)
        if library_path is None:
            self.skipTest("native libzstd path is unavailable")
        library.ZSTD_compressBound.argtypes = (ctypes.c_size_t,)
        library.ZSTD_compressBound.restype = ctypes.c_size_t
        library.ZSTD_compress.argtypes = (ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
        library.ZSTD_compress.restype = ctypes.c_size_t
        payload = b"synthetic CPIO contents"
        destination = ctypes.create_string_buffer(library.ZSTD_compressBound(len(payload)))
        count = library.ZSTD_compress(destination, len(destination), payload, len(payload), 1)
        self.assertLess(count, len(destination))
        frame = destination.raw[:count]
        self.assertEqual(final.decompress_single_zstd_frame(
            frame, library_path, len(payload)), payload)
        for changed in (frame[:-1], frame + b"\0", frame + frame,
                        b"\x50\x2a\x4d\x18\0\0\0\0" + frame):
            with self.subTest(length=len(changed)), self.assertRaises(ValueError):
                final.decompress_single_zstd_frame(changed, library_path, len(payload))
        with self.assertRaisesRegex(ValueError, "exceeds reconstructed package size"):
            final.decompress_single_zstd_frame(frame, library_path, len(payload) - 1)


if __name__ == "__main__":
    unittest.main()
