#!/usr/bin/env python3
"""Synthetic FAT/UKI tests; signed package fixtures are opt-in local inputs."""

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib

import debian_snapshot
import inspect_raw_esp as esp
import inspect_raw_gpt as gpt
import prepare
import verify_builder_closure as closure


SECTOR = 512
SECTORS = 4096
ESP_FIRST = 160
ESP_SECTORS = 2880  # mformat's documented 1.44 MiB floppy geometry.
ENTRY_COUNT = 128
ENTRY_SIZE = 128


def raw_with_esp(fat):
    assert len(fat) == ESP_SECTORS * SECTOR
    disk = bytearray(SECTORS * SECTOR)
    disk[510:512] = b"\x55\xaa"
    struct.pack_into("<B3sB3sII", disk, 446, 0, bytes(3), 0xee,
                     bytes(3), 1, SECTORS - 1)
    table = bytearray(ENTRY_COUNT * ENTRY_SIZE)
    for index, (kind, first, last) in enumerate((
            (list(gpt.TYPES)[0], 40, 79),
            (list(gpt.TYPES)[1], 80, 119),
            (list(gpt.TYPES)[2], ESP_FIRST, ESP_FIRST + ESP_SECTORS - 1))):
        flags = gpt.READ_ONLY_FLAG if index < 2 else 0
        struct.pack_into("<16s16sQQQ", table, index * ENTRY_SIZE,
                         kind.bytes_le, uuid.UUID(int=index + 1).bytes_le,
                         first, last, flags)
    table_crc = zlib.crc32(table)
    backup_table = SECTORS - 1 - len(table) // SECTOR
    disk[2 * SECTOR:2 * SECTOR + len(table)] = table
    disk[backup_table * SECTOR:backup_table * SECTOR + len(table)] = table
    for current, alternate, entries_lba in ((1, SECTORS - 1, 2),
                                            (SECTORS - 1, 1, backup_table)):
        offset = current * SECTOR
        gpt.HEADER.pack_into(disk, offset, b"EFI PART", 0x10000,
                             gpt.HEADER.size, 0, 0, current, alternate,
                             34, backup_table - 1,
                             uuid.UUID("831d38ce-3138-41f1-89ef-600762bb4be6").bytes_le,
                             entries_lba, ENTRY_COUNT, ENTRY_SIZE, table_crc)
        struct.pack_into("<I", disk, offset + 16,
                         zlib.crc32(disk[offset:offset + gpt.HEADER.size]))
    disk[ESP_FIRST * SECTOR:(ESP_FIRST + ESP_SECTORS) * SECTOR] = fat
    return bytes(disk)


def run(command, *, env=None):
    result = subprocess.run(command, env=env, check=False, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(f"synthetic fixture command failed: {command[0]}: {result.stderr}")


def rename_pe_section(path, old, new):
    """Mutate only a synthetic UKI's PE section name before copying it to FAT."""
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_start = pe_offset + 24 + optional_size
    old_name = old.encode("ascii").ljust(8, b"\0")
    matches = [section_start + index * 40 for index in range(count)
               if data[section_start + index * 40:section_start + index * 40 + 8]
               == old_name]
    assert len(matches) == 1
    data[matches[0]:matches[0] + 8] = new.encode("ascii").ljust(8, b"\0")
    path.write_bytes(data)


def synthetic_pe_section_table(names, *, cmdline=None):
    """Small x86_64 PE32+ envelope for parser rejection tests, not bootable."""
    pe_offset = 0x80
    optional_size = 0xf0
    section_start = pe_offset + 24 + optional_size
    payload_start = section_start + len(names) * 40
    payloads = [(cmdline if cmdline is not None else REVIEWED_CMDLINE.encode())
                if name == ".cmdline" else bytes([index + 1])
                for index, name in enumerate(names)]
    data = bytearray(payload_start + sum(map(len, payloads)))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, pe_offset + 4,
                     0x8664, len(names), 0, 0, 0, optional_size, 0)
    struct.pack_into("<H", data, pe_offset + 24, 0x20b)
    offset = payload_start
    for index, (name, payload) in enumerate(zip(names, payloads)):
        start = section_start + index * 40
        data[start:start + 8] = name.encode("ascii").ljust(8, b"\0")
        struct.pack_into("<I", data, start + 8, len(payload))
        struct.pack_into("<II", data, start + 16, len(payload), offset)
        data[offset:offset + len(payload)] = payload
        offset += len(payload)
    return data


REVIEWED_CMDLINE = f"roothash={'a' * 64} {prepare.FIXED_KERNEL_CMDLINE}"


class EspInspectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="synthetic-esp-", dir=os.environ.get("CODEX_TMP_DIR"),
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_archive_member_rejects_non_deb_input(self):
        with self.assertRaisesRegex(ValueError, "not a deb"):
            esp.regular_member_from_deb(b"wrong", "usr/bin/mtools")

    def test_cli_rejection_never_approves(self):
        result = subprocess.run(
            [sys.executable, str(Path(esp.__file__)), str(self.root / "missing.raw"),
             "0" * 64, "512", "512", "--inrelease", str(self.root / "missing-release"),
             "--packages-index", str(self.root / "missing-index"),
             "--archives", str(self.root), "--scratch", str(self.root)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "blocked")
        for field in ("complete_builder_toolchain", "signed_uki_checked",
                      "image_built", "private_mode_approved"):
            self.assertIs(report[field], False)

    def test_pe_table_rejects_profile_duplicate_and_unreviewed_boot_sections(self):
        base = [".linux", ".initrd", ".cmdline"]
        for extra, reason in ((".profile", "unreviewed UKI boot section"),
                              (".cmdline", "duplicate UKI PE section"),
                              (".initrd", "duplicate UKI PE section"),
                              (".ucode", "unreviewed UKI boot section"),
                              (".dtb", "unreviewed UKI boot section"),
                              (".pcrsig", "unreviewed UKI boot section")):
            with self.subTest(extra=extra):
                image = self.root / "synthetic.efi"
                image.write_bytes(synthetic_pe_section_table(base + [extra]))
                with self.assertRaisesRegex(ValueError, reason):
                    esp.section_report(b"", b"", {}, image, self.root)

    def test_pe_table_accepts_single_reviewed_boot_sections(self):
        image = self.root / "synthetic.efi"
        sections = [".text", ".osrel", ".cmdline", ".initrd", ".linux"]
        image.write_bytes(synthetic_pe_section_table(sections))
        self.assertEqual(esp.pe_section_names(image), sections)

    def test_pe_command_line_bytes_and_ukify_report_must_agree(self):
        image = self.root / "synthetic.efi"
        raw = REVIEWED_CMDLINE.encode()
        image.write_bytes(synthetic_pe_section_table(
            [".linux", ".initrd", ".cmdline"], cmdline=raw))
        names, extracted = esp.pe_section_table(image)
        self.assertEqual(names, [".linux", ".initrd", ".cmdline"])
        self.assertEqual(extracted, raw)
        report = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                  "text": REVIEWED_CMDLINE}
        self.assertEqual(esp.reviewed_cmdline(extracted, report), REVIEWED_CMDLINE)
        for changed in ({**report, "size": len(raw) - 1},
                        {**report, "sha256": "0" * 64},
                        {**report, "text": "roothash=hidden"}):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "differs from PE bytes"):
                    esp.reviewed_cmdline(extracted, changed)

    def test_boot_profile_rejects_extra_options_duplicate_hashes_and_nuls(self):
        raw = REVIEWED_CMDLINE.encode()
        for bad in (raw.replace(b"lockdown=confidentiality", b"lockdown=none"),
                    raw.replace(b"pstore.backend=none ", b""),
                    raw.replace(b"pstore.backend=none", b"pstore.backend=efi_pstore"),
                    raw.replace(b"pstore.backend=none", b"pstore.backend=none pstore.backend=efi_pstore"),
                    raw + b" init=/bin/sh", raw + b"\n", raw + b"\0\0",
                    raw.replace(b"roothash=", b"roothash=" + b"b" * 64 + b" roothash="),
                    raw.replace(b"a" * 64, b"A" * 64),
                    raw.replace(b"systemd.unit=zrpc.target", b"systemd.unit=rescue.target")):
            with self.subTest(bad=bad):
                report = {"size": len(bad), "sha256": hashlib.sha256(bad).hexdigest(),
                          "text": bad.rstrip(b"\0").decode("ascii", errors="replace")}
                with self.assertRaisesRegex(ValueError, "differs from reviewed boot profile"):
                    esp.reviewed_cmdline(bad, report)
        with_nul = raw + b"\0"
        report = {"size": len(with_nul),
                  "sha256": hashlib.sha256(with_nul).hexdigest(),
                  "text": REVIEWED_CMDLINE}
        self.assertEqual(esp.reviewed_cmdline(with_nul, report), REVIEWED_CMDLINE)

    def test_pe_command_line_virtual_size_must_fit_file_payload(self):
        image = self.root / "synthetic.efi"
        data = synthetic_pe_section_table(
            [".linux", ".initrd", ".cmdline"], cmdline=REVIEWED_CMDLINE.encode())
        cmdline_header = 0x80 + 24 + 0xf0 + 2 * 40
        struct.pack_into("<I", data, cmdline_header + 8, len(REVIEWED_CMDLINE) + 1)
        image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "section size differs"):
            esp.pe_section_table(image)

    def test_pe_table_rejects_truncated_section_data(self):
        image = self.root / "synthetic.efi"
        data = synthetic_pe_section_table([".linux", ".initrd", ".cmdline"])
        data.pop()
        image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "section data is outside"):
            esp.pe_section_names(image)

    def signed_inputs(self):
        fixture = os.environ.get("GCP_SIGNED_BUILDER_FIXTURE_ROOT")
        if not fixture or not os.environ.get("CODEX_TMP_DIR"):
            self.skipTest("signed local Debian fixtures and workspace scratch not provided")
        base = Path(fixture)
        return base / "InRelease", base / "Packages.xz", base / "debs"

    def build_fixture(self, *, extra_entry=False, renamed_section=None,
                      cmdline=REVIEWED_CMDLINE):
        inrelease, index, archives = self.signed_inputs()
        tools, _ = esp.authenticated_tools(inrelease, index, archives)
        lock = json.loads(esp.LOCK.read_bytes())
        stub_entry = next(item for item in lock["packages"]
                          if item["name"] == "systemd-boot-efi")
        _, _, index_bytes = debian_snapshot.authenticated_index_bytes(
            inrelease, index, lock["inrelease_sha256"],
        )
        record = debian_snapshot.package_records(io.BytesIO(index_bytes)).get(
            (stub_entry["name"], stub_entry["version"], stub_entry["architecture"]),
        )
        stub_deb = closure.indexed_archive(stub_entry, record, archives, keep_bytes=True)
        stub = esp.regular_member_from_deb(
            stub_deb, "usr/lib/systemd/boot/efi/linuxx64.efi.stub",
        )
        tool_dir = self.root / "tools"
        tool_dir.mkdir()
        mtools = tool_dir / "mtools"
        mtools.write_bytes(tools["mtools"])
        mtools.chmod(0o500)
        for command in ("mformat", "mmd", "mcopy"):
            (tool_dir / command).symlink_to(mtools.name)
        ukify = tool_dir / "ukify"
        ukify.write_bytes(tools["systemd-ukify"])
        (tool_dir / "pefile.py").write_bytes(tools["python3-pefile"])
        lookup = tool_dir / "ordlookup"
        lookup.mkdir()
        for name, filename in (("init", "__init__.py"),
                               ("oleaut32", "oleaut32.py"),
                               ("ws2_32", "ws2_32.py"),
                               ("wsock32", "wsock32.py")):
            (lookup / filename).write_bytes(tools["ordlookup-" + name])
        stub_path = self.root / "stub.efi"
        stub_path.write_bytes(stub)
        (self.root / "linux").write_bytes(b"synthetic-linux")
        (self.root / "initrd").write_bytes(b"synthetic-initrd")
        uki = self.root / "BOOTX64.EFI"
        run([sys.executable, "-S", str(ukify), "--config=/dev/null", "build",
             "--stub", str(stub_path), "--linux", str(self.root / "linux"),
             "--initrd", str(self.root / "initrd"),
             "--cmdline", cmdline, "--os-release", "ID=synthetic",
             "--uname", "synthetic", "--output", str(uki)],
            env={"PYTHONPATH": str(tool_dir), "HOME": str(self.root),
                 "PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        if renamed_section:
            rename_pe_section(uki, *renamed_section)
        fat = self.root / "esp.fat"
        with fat.open("wb") as stream:
            stream.truncate(ESP_SECTORS * SECTOR)
        run([str(tool_dir / "mformat"), "-i", str(fat), "-f", "1440", "::"])
        run([str(tool_dir / "mmd"), "-i", str(fat), "::/EFI", "::/EFI/BOOT"])
        run([str(tool_dir / "mcopy"), "-i", str(fat), str(uki),
             "::/EFI/BOOT/BOOTX64.EFI"])
        if extra_entry:
            run([str(tool_dir / "mmd"), "-i", str(fat),
                 "::/loader", "::/loader/addons"])
            run([str(tool_dir / "mcopy"), "-i", str(fat), str(uki),
                 "::/loader/addons/extra.addon.efi"])
        raw = raw_with_esp(fat.read_bytes())
        disk = self.root / "disk.raw"
        disk.write_bytes(raw)
        return (disk, hashlib.sha256(raw).hexdigest(), len(raw),
                inrelease, index, archives)

    def test_signed_tools_inspect_synthetic_disk_without_approval(self):
        args = self.build_fixture()
        report = esp.inspect(*args[:3], SECTOR, *args[3:], self.root)
        self.assertEqual(report["status"], "diagnostic-esp-uki-sections-unapproved")
        self.assertEqual(report["esp_inventory"], list(esp.EXPECTED_ESP_ENTRIES))
        self.assertEqual(report["uki_cmdline_for_review"], REVIEWED_CMDLINE)
        self.assertTrue(esp.REQUIRED_SECTIONS <= report["uki_sections"].keys())
        for field in ("complete_builder_toolchain", "signed_uki_checked",
                      "cmdline_approved", "dm_verity_checked", "image_built",
                      "private_mode_approved"):
            self.assertIs(report[field], False)

    def test_signed_tools_reject_profile_hidden_by_section_map(self):
        args = self.build_fixture(renamed_section=(".uname", ".profile"))
        with self.assertRaisesRegex(ValueError, "unreviewed UKI boot section: .profile"):
            esp.inspect(*args[:3], SECTOR, *args[3:], self.root)

    def test_signed_tools_reject_duplicate_cmdline_hidden_by_section_map(self):
        args = self.build_fixture(renamed_section=(".uname", ".cmdline"))
        with self.assertRaisesRegex(ValueError, "duplicate UKI PE section: .cmdline"):
            esp.inspect(*args[:3], SECTOR, *args[3:], self.root)

    def test_extra_esp_companion_and_changed_archive_fail_closed(self):
        args = self.build_fixture(extra_entry=True)
        with self.assertRaisesRegex(ValueError, "ESP inventory differs"):
            esp.inspect(*args[:3], SECTOR, *args[3:], self.root)
        archives = self.root / "archives"
        archives.mkdir()
        mtools = next(entry for entry in json.loads(esp.LOCK.read_bytes())["packages"]
                      if entry["name"] == "mtools")
        original = args[-1] / f'{mtools["sha256"]}.deb'
        modified = bytearray(original.read_bytes())
        modified[-1] ^= 1
        (archives / original.name).write_bytes(modified)
        with self.assertRaisesRegex(ValueError, "archive differs from signed index"):
            esp.authenticated_tools(args[-3], args[-2], archives)


if __name__ == "__main__":
    unittest.main()
