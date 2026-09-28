"""Synthetic suffix tests; only a native signed-package replay can validate mkosi output."""

import ctypes
import ctypes.util
import hashlib
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import types
import unittest
from unittest import mock

import inspect_final_initrd as final
import prepare_initrd_basetree_profile as source


FILE = "usr/lib/modules/test-kernel/kernel/drivers/md/dm-verity.ko.xz"
METADATA = "usr/lib/modules/test-kernel/modules.dep"
CONTENTS = {FILE: b"reviewed module bytes", METADATA: b"reviewed depmod bytes"}
IDENTITIES = {name: (len(data), hashlib.sha256(data).hexdigest(), 0o644)
              for name, data in CONTENTS.items()}
SOURCE = types.SimpleNamespace(exact=source.exact, padded=source.padded)
KERNEL = "test-kernel"
BOOT_CONFIG = ("\n".join(
    f"{name}={next(iter(allowed))}" for name, allowed in sorted(final.BOOT_CONFIG.items())
    if name != "CONFIG_CONFIGFS_FS") + "\nCONFIG_CONFIGFS_FS=m\n").encode()
BUILTINS = ("\n".join(sorted(final.NVME_BUILTINS)) + "\n").encode()
BOOT_MODULES = {
    "usr/lib/modules/" + KERNEL + "/" + relative: (4, "a" * 64, 0o644)
    for relative in final.BOOT_MODULES.values()
}


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

    def test_boot_profile_requires_signed_modules_and_builtin_nvme(self):
        report = final.boot_driver_preflight(BOOT_CONFIG, BUILTINS, BOOT_MODULES, KERNEL)
        self.assertEqual(report["nvme_builtin"], True)
        self.assertEqual(report["ext4_builtin"], True)
        self.assertEqual(report["private_mode_approved"], False)
        self.assertIn("unapproved", report["status"])
        for missing in BOOT_MODULES:
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "module"):
                final.boot_driver_preflight(
                    BOOT_CONFIG, BUILTINS, {key: value for key, value in BOOT_MODULES.items()
                                            if key != missing}, KERNEL)
        for missing in final.NVME_BUILTINS:
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "NVMe"):
                final.boot_driver_preflight(BOOT_CONFIG, BUILTINS.replace(
                    (missing + "\n").encode(), b""), BOOT_MODULES, KERNEL)

    def test_root_ext4_must_be_builtin_before_initrd_mount(self):
        for replacement in (b"CONFIG_EXT4_FS=m", b"CONFIG_EXT4_FS=n"):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(
                    ValueError, "CONFIG_EXT4_FS"):
                final.boot_driver_preflight(
                    BOOT_CONFIG.replace(b"CONFIG_EXT4_FS=y", replacement),
                    BUILTINS, BOOT_MODULES, KERNEL)

    def test_boot_profile_rejects_missing_disabled_modular_and_ambiguous_options(self):
        for option, allowed in final.BOOT_CONFIG.items():
            value = "m" if option == "CONFIG_CONFIGFS_FS" else next(iter(allowed))
            original = f"{option}={value}".encode()
            with self.subTest(option=option, disabled=True), self.assertRaisesRegex(
                    ValueError, option):
                final.boot_driver_preflight(BOOT_CONFIG.replace(
                    original, f"{option}=n".encode()), BUILTINS, BOOT_MODULES, KERNEL)
            with self.subTest(option=option, missing=True), self.assertRaisesRegex(
                    ValueError, option):
                final.boot_driver_preflight(BOOT_CONFIG.replace(
                    original + b"\n", b""), BUILTINS, BOOT_MODULES, KERNEL)
        with self.assertRaisesRegex(ValueError, "CONFIG_BLK_DEV_NVME"):
            final.boot_driver_preflight(BOOT_CONFIG.replace(
                b"CONFIG_BLK_DEV_NVME=y", b"CONFIG_BLK_DEV_NVME=m"),
                BUILTINS, BOOT_MODULES, KERNEL)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            final.boot_driver_preflight(BOOT_CONFIG + b"CONFIG_GVE=m\n",
                                        BUILTINS, BOOT_MODULES, KERNEL)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            final.boot_driver_preflight(BOOT_CONFIG + b"# CONFIG_GVE is not set\n",
                                        BUILTINS, BOOT_MODULES, KERNEL)
        with self.assertRaisesRegex(ValueError, "ASCII"):
            final.boot_driver_preflight(BOOT_CONFIG + b"\xff", BUILTINS,
                                        BOOT_MODULES, KERNEL)

    def test_kernel_config_must_be_one_exact_regular_signed_package_member(self):
        def package(entries):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:xz") as archive:
                for name, contents, kind in entries:
                    member = tarfile.TarInfo(name)
                    member.mode = 0o644
                    member.type = kind
                    member.size = len(contents) if kind == tarfile.REGTYPE else 0
                    archive.addfile(member, io.BytesIO(contents) if kind == tarfile.REGTYPE
                                    else None)
            return output.getvalue()

        correct = ("./boot/config-" + KERNEL, BOOT_CONFIG, tarfile.REGTYPE)
        self.assertEqual(final.signed_kernel_config(package([correct]), KERNEL), BOOT_CONFIG)
        for entries in ([], [correct, correct],
                        [(correct[0], b"", tarfile.SYMTYPE)],
                        [("./boot/config-other", BOOT_CONFIG, tarfile.REGTYPE)]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                final.signed_kernel_config(package(entries), KERNEL)

    def test_final_initrd_inspection_cannot_report_success_without_boot_profile(self):
        base, suffix = b"base", b"suffix"
        names = {"kernel": "linux-image-test", "kmod": "kmod", "libkmod": "libkmod2"}
        entries = {
            label: {"name": name, "version": "1" if label == "kernel" else "34.2-2",
                    "architecture": "amd64", "sha256": "a" * 64}
            for label, name in names.items()
        }
        profile = types.SimpleNamespace(
            exact=source.exact,
            guest=types.SimpleNamespace(prepare=types.SimpleNamespace(
                KERNEL_PACKAGE=names["kernel"], KERNEL_PACKAGE_VERSION="1",
                KERNEL_VERSION=KERNEL)))

        def stage_modules(_payload, root, _version):
            path = root / "usr/lib/modules" / KERNEL / "modules.builtin"
            path.parent.mkdir(parents=True)
            path.write_bytes(BUILTINS)
            return {**BOOT_MODULES, "usr/lib/modules/" + KERNEL + "/modules.builtin":
                    (len(BUILTINS), final.sha256(BUILTINS), 0o644)}

        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "final.initrd"
            artifact.write_bytes(base + suffix)
            arguments = (final.sha256(base), len(base), artifact,
                         final.sha256(base + suffix), len(base + suffix),
                         artifact, entries["kernel"], artifact, entries["kmod"],
                         artifact, entries["libkmod"], artifact, directory, profile)
            with (mock.patch.object(final, "checked_package", return_value=b"signed package"),
                  mock.patch.object(final, "checked_depmod_tool", return_value=artifact),
                  mock.patch.object(final, "package_tree", side_effect=stage_modules),
                  mock.patch.object(final, "reconstructed_members",
                                    return_value=({"reviewed": (1, "b" * 64, 0o644)}, set())),
                  mock.patch.object(final, "signed_kernel_config", return_value=BOOT_CONFIG)
                  as config,
                  mock.patch.object(final, "decompress_single_zstd_frame", return_value=b"cpio"),
                  mock.patch.object(final, "parse_cpio", return_value={"file_count": 1})):
                report = final.inspect(*arguments)
                self.assertEqual(report["boot_driver_preflight"]["nvme_builtin"], True)
                self.assertEqual(report["boot_driver_preflight"]["ext4_builtin"], True)
                self.assertEqual(report["private_mode_approved"], False)
                config.return_value = BOOT_CONFIG.replace(
                    b"CONFIG_BLK_DEV_NVME=y", b"CONFIG_BLK_DEV_NVME=m")
                with self.assertRaisesRegex(ValueError, "CONFIG_BLK_DEV_NVME"):
                    final.inspect(*arguments)


if __name__ == "__main__":
    unittest.main()
