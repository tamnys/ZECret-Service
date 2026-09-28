"""Negative checks for the synthetic QEMU/OVMF toolchain boundary."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import boot_qemu_toolchain as boot


def elf():
    result = bytearray(64)
    result[:6] = b"\x7fELF\x02\x01"
    result[18:20] = (62).to_bytes(2, "little")
    return bytes(result)


class BootToolchainTests(unittest.TestCase):
    def test_source_reviewed_lock_is_exact_and_has_only_diagnostic_anchors(self):
        lock = boot.reviewed_lock()
        self.assertEqual([item["name"] for item in lock["anchors"]],
                         ["ovmf", "qemu-system-x86"])
        self.assertEqual(lock["status"], "apt-resolved-candidate-unbuilt-unapproved")
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / "altered.json"
            original = boot.LOCK.read_bytes()
            altered.write_bytes(original.replace(b'"ovmf"', b'"OVMF"', 1))
            with self.assertRaisesRegex(ValueError, "source-reviewed bytes"):
                boot.reviewed_lock(altered)

    def test_elf_architecture_rejects_wrong_machine(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(elf()[:18] + b"\xb7\x00" + elf()[20:])
            with self.assertRaisesRegex(ValueError, "x86_64 ELF"):
                boot.elf_x86_64(path)

    def test_prefetch_rejects_changed_metadata_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata"
            archives = root / "archives"
            metadata.mkdir()
            archives.mkdir()
            with (mock.patch.object(boot.fetcher, "verified_metadata",
                                    return_value=False),
                  mock.patch.object(boot.fetcher, "download_one") as download):
                with self.assertRaisesRegex(ValueError, "metadata missing"):
                    boot.fetch(metadata, archives)
                download.assert_not_called()

    def test_signed_file_must_match_inventory_and_stay_in_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / boot.QEMU
            path.parent.mkdir(parents=True)
            path.write_bytes(elf())
            record = {"kind": "file", "packages": ["qemu-system-x86"],
                      "size": path.stat().st_size,
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertEqual(boot.checked_file(root, {boot.QEMU: record},
                                               boot.QEMU, "qemu-system-x86"), path)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "differs from signed archive"):
                boot.checked_file(root, {boot.QEMU: record}, boot.QEMU,
                                  "qemu-system-x86")
            path.unlink()
            path.symlink_to("/usr/bin/true")
            with self.assertRaisesRegex(ValueError, "redirected"):
                boot.checked_file(root, {boot.QEMU: record}, boot.QEMU,
                                  "qemu-system-x86")

    def test_dynamic_dependency_escape_blocks_stage_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = {}
            for name, package in ((boot.QEMU, "qemu-system-x86"),
                                  (boot.OVMF_CODE, "ovmf"),
                                  (boot.OVMF_VARS, "ovmf")):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                data = elf() if name == boot.QEMU else b"firmware fixture"
                path.write_bytes(data)
                inventory[name] = {"kind": "file", "packages": [package],
                                   "size": len(data),
                                   "sha256": hashlib.sha256(data).hexdigest()}
            loader = root / boot.LOADER
            loader.parent.mkdir(parents=True, exist_ok=True)
            loader.write_bytes(elf())
            inventory[boot.LOADER] = {
                "kind": "file", "packages": ["libc6"],
                "size": loader.stat().st_size,
                "sha256": hashlib.sha256(loader.read_bytes()).hexdigest()}
            reported = subprocess.CompletedProcess(
                [], 0, "\tlinux-vdso.so.1 (0x1)\n"
                       "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x2)\n", "")
            with mock.patch.object(boot.subprocess, "run", return_value=reported):
                with self.assertRaisesRegex(ValueError, "escaped signed toolchain"):
                    boot.dynamic_closure(root, inventory)
            library = root / boot.LIBRARY / "libc.so.6"
            library.write_bytes(elf())
            inventory[str(library.relative_to(root))] = {
                "kind": "file", "packages": ["libc6"],
                "size": library.stat().st_size,
                "sha256": hashlib.sha256(library.read_bytes()).hexdigest()}
            reported = subprocess.CompletedProcess(
                [], 0, f"\tlibc.so.6 => {library} (0x2)\n", "")
            with mock.patch.object(boot.subprocess, "run", return_value=reported):
                self.assertTrue(boot.dynamic_closure(root, inventory)[
                    "dynamic_loader_dependencies_within_signed_stage"])
                library.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "differs from signed archive"):
                    boot.dynamic_closure(root, inventory)

    def test_stage_rejects_apt_plan_change_before_writing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata"
            archives = root / "archives"
            scratch = root / "scratch"
            for path in (metadata, archives, scratch):
                path.mkdir()
            output = root / "output"
            lock = boot.reviewed_lock()
            selected = {entry["name"]: (entry["version"], entry["architecture"])
                        for entry in lock["packages"]}
            with (mock.patch.object(boot, "authenticated_selection",
                                    return_value=(lock, b"index", {}, selected)),
                  mock.patch.object(boot, "cached_archives"),
                  mock.patch.object(boot, "apt_plan", return_value={}),
                  mock.patch.object(boot.stager, "stage") as staging):
                with self.assertRaisesRegex(ValueError, "offline APT plan"):
                    boot.stage(metadata, archives, output, scratch, root)
                staging.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
