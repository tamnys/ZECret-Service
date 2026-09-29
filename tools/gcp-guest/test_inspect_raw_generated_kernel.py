"""Synthetic signed-kernel inputs for raw-root generated-file expectations."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import inspect_final_initrd as final_initrd
import inspect_raw_generated_kernel as generated
import prepare


VERSION = prepare.KERNEL_VERSION
MODULE_ROOT = "usr/lib/modules/" + VERSION
BOOT = "boot/vmlinuz-" + VERSION
TARGET = MODULE_ROOT + "/vmlinuz"
BOOT_BYTES = b"signed kernel image"
INDEX_BYTES = {"modules.dep": b"module dependencies\n",
               "modules.dep.bin": b"binary dependencies"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def signed_kernel_payload(boot_bytes=BOOT_BYTES):
    files = {BOOT: boot_bytes}
    files.update({MODULE_ROOT + "/" + name: name.encode()
                  for name in final_initrd.MODULES | final_initrd.PACKAGE_METADATA})
    directories = {"boot", "usr", "usr/lib", "usr/lib/modules"}
    for name in files:
        parts = name.split("/")
        directories.update("/".join(parts[:index])
                           for index in range(1, len(parts)))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        for name in sorted(directories, key=lambda item: (item.count("/"), item)):
            member = tarfile.TarInfo("./" + name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            archive.addfile(member)
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo("./" + name)
            member.mode = 0o644
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def source_rows():
    return [
        {"path": ".", "kind": "directory", "uid": 0, "gid": 0},
        {"path": BOOT, "kind": "file", "packages": [prepare.KERNEL_PACKAGE],
         "uid": 0, "gid": 0, "size": len(BOOT_BYTES),
         "sha256": sha256(BOOT_BYTES), "source_mode": 0o644,
         "output_mode": 0o644},
        {"path": MODULE_ROOT, "kind": "directory", "uid": 0, "gid": 0},
    ]


class GeneratedKernelTests(unittest.TestCase):
    def setUp(self):
        self.payloads = {prepare.KERNEL_PACKAGE: signed_kernel_payload(),
                         "kmod": b"signed kmod payload",
                         "libkmod2": b"signed libkmod payload"}
        self.rows = source_rows()
        self.workspace = tempfile.TemporaryDirectory(prefix="test-raw-kernel-")
        self.addCleanup(self.workspace.cleanup)

    def expected(self, overlay=None, *, replay=None):
        if replay is None:
            replay = self.replay
        with (mock.patch.object(generated.final_initrd, "checked_depmod_tool",
                                return_value=Path("/usr/sbin/depmod")) as tool,
              mock.patch.object(generated.final_initrd, "reconstructed_members",
                                side_effect=replay)):
            result = generated.expected_entries(
                self.payloads, self.rows, {} if overlay is None else overlay,
                self.workspace.name)
            tool.assert_called_once()
            return result

    def replay(self, root, signed, version, depmod):
        self.assertEqual(version, VERSION)
        self.assertEqual(depmod, Path("/usr/sbin/depmod"))
        self.assertEqual((root / TARGET).read_bytes(), BOOT_BYTES)
        self.assertEqual(signed[TARGET], (len(BOOT_BYTES), sha256(BOOT_BYTES), 0o644))
        self.assertIn(MODULE_ROOT + "/modules.builtin", signed)
        return ({MODULE_ROOT + "/" + name: (len(data), sha256(data), 0o644)
                 for name, data in INDEX_BYTES.items()}, set(INDEX_BYTES))

    def test_signed_boot_copy_and_replayed_indexes_supply_exact_rows(self):
        entries = self.expected()
        self.assertEqual(set(entries),
                         {TARGET, *(MODULE_ROOT + "/" + name for name in INDEX_BYTES)})
        self.assertEqual(entries[TARGET],
                         {"type": "regular", "mode": 0o644, "uid": 0, "gid": 0,
                          "size": len(BOOT_BYTES), "sha256": sha256(BOOT_BYTES)})
        for name, data in INDEX_BYTES.items():
            self.assertEqual(entries[MODULE_ROOT + "/" + name]["sha256"], sha256(data))

    def test_changed_signed_image_and_metadata_cannot_supply_expectations(self):
        self.rows[1]["sha256"] = sha256(b"different kernel")
        with self.assertRaisesRegex(ValueError, "boot member bytes differ"):
            self.expected()
        self.rows[1]["sha256"] = sha256(BOOT_BYTES)
        for field, value in (("packages", ["other-kernel"]), ("uid", 1),
                             ("source_mode", 0o666)):
            with self.subTest(field=field):
                previous = self.rows[1][field]
                self.rows[1][field] = value
                with self.assertRaisesRegex(ValueError, "boot image or module destination"):
                    self.expected()
                self.rows[1][field] = previous
        self.payloads[prepare.KERNEL_PACKAGE] = signed_kernel_payload(b"evil kernel image!!")
        with self.assertRaisesRegex(ValueError, "boot member bytes differ"):
            self.expected()

    def test_depmod_configuration_and_kernel_overlay_fail_closed(self):
        self.rows.append({"path": "etc/depmod.d/custom.conf", "kind": "file"})
        with self.assertRaisesRegex(ValueError, "depmod replay has configuration"):
            self.expected()
        self.rows.pop()
        with self.assertRaisesRegex(ValueError, "depmod replay has configuration"):
            self.expected({"usr/lib/depmod.d/custom.conf": {"type": "file"}})
        with self.assertRaisesRegex(ValueError, "source overlay supplies a kernel module"):
            self.expected({TARGET: {"type": "file"}})

    def test_replay_failure_and_unreviewed_index_fail_closed(self):
        def cannot_replay(*_args):
            raise ValueError("native depmod output differs")

        with self.assertRaisesRegex(ValueError, "native-root depmod replay unresolved"):
            self.expected(replay=cannot_replay)

        def unreviewed(_root, _signed, _version, _depmod):
            return ({MODULE_ROOT + "/../payload": (1, sha256(b"x"), 0o644)},
                    {"modules.dep", "modules.dep.bin", "../payload"})

        with self.assertRaisesRegex(ValueError, "unreviewed index"):
            self.expected(replay=unreviewed)

        def writable(_root, _signed, _version, _depmod):
            return ({MODULE_ROOT + "/modules.dep": (1, sha256(b"x"), 0o666),
                     MODULE_ROOT + "/modules.dep.bin": (1, sha256(b"y"), 0o644)},
                    {"modules.dep", "modules.dep.bin"})

        with self.assertRaisesRegex(ValueError, "unreviewed index"):
            self.expected(replay=writable)


if __name__ == "__main__":
    unittest.main()
