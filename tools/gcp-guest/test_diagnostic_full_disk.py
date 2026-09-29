"""Fail-closed tests for both unsigned full-disk rehearsal input modes."""

import json
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import zlib

import diagnostic_full_disk as diagnostic
import test_inspect_raw_gpt as gpt_fixture
import test_prepare as prepare_fixture


def without_partition(index):
    """Remove one GPT type from both valid copies, then repair their CRCs."""
    disk = gpt_fixture.synthetic_disk()
    table_lbas = (2, gpt_fixture.SECTORS - 1 -
                  gpt_fixture.TABLE_BYTES // gpt_fixture.SECTOR)
    for table_lba in table_lbas:
        offset = table_lba * gpt_fixture.SECTOR + index * gpt_fixture.ENTRY_SIZE
        disk[offset:offset + gpt_fixture.ENTRY_SIZE] = bytes(gpt_fixture.ENTRY_SIZE)
    table_offset = table_lbas[0] * gpt_fixture.SECTOR
    table_crc = zlib.crc32(disk[table_offset:table_offset + gpt_fixture.TABLE_BYTES])
    for header_lba in (1, gpt_fixture.SECTORS - 1):
        offset = header_lba * gpt_fixture.SECTOR
        struct.pack_into("<I", disk, offset + 88, table_crc)
        struct.pack_into("<I", disk, offset + 16, 0)
        struct.pack_into("<I", disk, offset + 16,
                         zlib.crc32(disk[offset:offset + diagnostic.gpt.HEADER.size]))
    return disk


class DiagnosticDiskTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="unsigned-full-disk-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_output(self, disk, name="stage"):
        stage = self.root / name
        output = stage / "output"
        output.mkdir(parents=True)
        for name in diagnostic.outer.OUTPUT_FILES:
            (output / name).write_bytes(name.encode())
        (output / "zrpc-gcp.raw").write_bytes(disk)
        for name, target in diagnostic.outer.OUTPUT_ALIASES.items():
            (output / name).symlink_to(target)
        names = ("zrpc-gcp.raw", "zrpc-gcp.efi", "zrpc-gcp.vmlinuz",
                 "zrpc-gcp.initrd")
        (output / "zrpc-gcp.SHA256SUMS").write_text("".join(
            f"{diagnostic.sha256((output / name).read_bytes())} *{name}\n"
            for name in names))
        return stage

    def make_comparable_output(self, disk, name):
        stage = self.make_output(disk, name)
        (stage / "candidate-manifest.json").write_text('{"synthetic":true}\n')
        return stage

    def test_rebuild_comparison_reports_first_root_byte_and_stays_unapproved(self):
        first = gpt_fixture.synthetic_disk()
        second = first.copy()
        offset = 40 * gpt_fixture.SECTOR + 123
        second[offset] = 0x42
        first_stage = self.make_comparable_output(first, "first")
        second_stage = self.make_comparable_output(second, "second")
        report = diagnostic.compare_root_rebuilds(first_stage, second_stage)
        self.assertEqual(report["status"], diagnostic.REBUILD_STATUS)
        self.assertEqual(report["first_difference_kind"], "byte")
        self.assertEqual(report["first_difference_root_offset_bytes"], 123)
        self.assertEqual(report["first_difference_first_disk_offset_bytes"], offset)
        self.assertEqual(report["first_difference_second_disk_offset_bytes"], offset)
        self.assertFalse(report["root_partition_byte_identical"])
        self.assertFalse(report["disk_byte_identical"])
        self.assertEqual(report["first_disk_difference_kind"], "byte")
        self.assertEqual(report["first_disk_difference_offset_bytes"], offset)
        self.assertEqual(report["first_disk_difference_regions"],
                         {"first": "root-x86-64", "second": "root-x86-64"})
        self.assertFalse(report["production_image"])
        self.assertFalse(report["hardware_verified"])
        self.assertFalse(report["private_mode_approved"])
        with mock.patch.object(diagnostic, "signed_block_owners", return_value=[
                {"block": 0, "inode": 8, "paths": []},
                {"block": 0, "inode": 8, "paths": []}]) as owners:
            mapped = diagnostic.compare_root_rebuilds(
                first_stage, second_stage, metadata=self.root,
                builder_archives=self.root, workspace=self.root)
        self.assertEqual(mapped["first_changed_block_owners"][0]["inode"], 8)
        owners.assert_called_once()

        (second_stage / "candidate-manifest.json").write_text('{"other":true}\n')
        with self.assertRaisesRegex(ValueError, "identical staged inputs"):
            diagnostic.compare_root_rebuilds(first_stage, second_stage)
        with self.assertRaisesRegex(ValueError, "distinct rehearsal stages"):
            diagnostic.compare_root_rebuilds(first_stage, first_stage)

    def test_rebuild_comparison_distinguishes_esp_from_unchanged_root(self):
        first = gpt_fixture.synthetic_disk()
        second = first.copy()
        second[120 * gpt_fixture.SECTOR + 7] = 0x42
        first_stage = self.make_comparable_output(first, "first")
        second_stage = self.make_comparable_output(second, "second")
        report = diagnostic.compare_root_rebuilds(first_stage, second_stage)
        self.assertTrue(report["root_partition_byte_identical"])
        self.assertIsNone(report["first_difference_kind"])
        self.assertIsNone(report["first_difference_root_offset_bytes"])
        self.assertFalse(report["disk_byte_identical"])
        self.assertEqual(report["first_disk_difference_offset_bytes"],
                         120 * gpt_fixture.SECTOR + 7)
        self.assertEqual(report["first_disk_difference_regions"],
                         {"first": "esp", "second": "esp"})
        raw = second_stage / "output/zrpc-gcp.raw"
        raw.write_bytes(raw.read_bytes() + b"tamper")
        with self.assertRaises(ValueError):
            diagnostic.compare_root_rebuilds(first_stage, second_stage)

    def test_rebuild_comparison_reports_equal_full_disk_and_changed_gap(self):
        disk = gpt_fixture.synthetic_disk()
        first_stage = self.make_comparable_output(disk, "first")
        second_stage = self.make_comparable_output(disk, "second")
        equal = diagnostic.compare_root_rebuilds(first_stage, second_stage)
        self.assertTrue(equal["disk_byte_identical"])
        self.assertIsNone(equal["first_disk_difference_kind"])
        self.assertIsNone(equal["first_disk_difference_offset_bytes"])
        self.assertIsNone(equal["first_disk_difference_regions"])
        changed = disk.copy()
        changed[100] = 0x42
        self.make_output(changed, "gap")
        second_stage = self.root / "gap"
        (second_stage / "candidate-manifest.json").write_text('{"synthetic":true}\n')
        report = diagnostic.compare_root_rebuilds(first_stage, second_stage)
        self.assertTrue(report["root_partition_byte_identical"])
        self.assertFalse(report["disk_byte_identical"])
        self.assertEqual(report["first_disk_difference_offset_bytes"], 100)
        self.assertEqual(report["first_disk_difference_regions"],
                         {"first": "outside-partitions", "second": "outside-partitions"})

    def test_rebuild_comparison_reports_root_extent_drift(self):
        disk = gpt_fixture.synthetic_disk()
        first_stage = self.make_comparable_output(disk, "first")
        second_stage = self.make_comparable_output(disk, "second")
        raw = first_stage / "output/zrpc-gcp.raw"
        layout = diagnostic.gpt.inspect(raw, diagnostic.sha256(disk),
                                        len(disk), gpt_fixture.SECTOR)
        shorter = json.loads(json.dumps(layout))
        root = next(item for item in shorter["partitions"]
                    if item["type"] == "root-x86-64")
        root["last_lba"] -= 1
        with mock.patch.object(diagnostic.gpt, "inspect", side_effect=(layout, shorter)):
            report = diagnostic.compare_root_rebuilds(first_stage, second_stage)
        self.assertFalse(report["root_partition_byte_identical"])
        self.assertFalse(report["root_partition_layout_identical"])
        self.assertEqual(report["first_difference_kind"], "length")
        self.assertEqual(report["first_root_partition_bytes"] -
                         report["second_root_partition_bytes"], gpt_fixture.SECTOR)
        self.assertIsNone(report["first_difference_root_offset_bytes"])
        self.assertFalse(report["private_mode_approved"])

    def test_signed_debugfs_block_owner_parsing(self):
        stats = "Filesystem UUID: value\nBlock size:               4096\n"
        with mock.patch.object(diagnostic, "debugfs_output", side_effect=(
                stats, "Block\tInode number\n57623\t42\n",
                "Inode\tPathname\n42\t/usr/lib/zrpc/zebrad\n")):
            owner = diagnostic.describe_changed_block(
                Path("/root.img"), Path("/root.img"), 57623 * 4096 + 32, 4)
        self.assertEqual(owner, {"block_size": 4096, "block": 57623,
                                 "inode": 42, "paths": ["/usr/lib/zrpc/zebrad"],
                                 "byte_offset_in_block": 32})
        with mock.patch.object(diagnostic, "debugfs_output", side_effect=(
                stats, "Block\tInode number\n57623\t<block not found>\n")):
            owner = diagnostic.describe_changed_block(
                Path("/root.img"), Path("/root.img"), 57623 * 4096 + 32, 4)
        self.assertIsNone(owner["inode"])
        with mock.patch.object(diagnostic, "debugfs_output", side_effect=(
                stats, "Block\tInode number\n57623\t42\n",
                "Inode\tPathname\n42\t../../other\n")):
            with self.assertRaisesRegex(ValueError, "inode path report"):
                diagnostic.describe_changed_block(
                    Path("/root.img"), Path("/root.img"), 57623 * 4096 + 32, 4)

    def test_signed_debugfs_query_rejects_nonbanner_output(self):
        bad = SimpleNamespace(returncode=0, stderr=b"warning\n", stdout=b"Block\tInode number\n")
        with mock.patch.object(diagnostic.subprocess, "run", return_value=bad):
            with self.assertRaisesRegex(ValueError, "signed debugfs block ownership query failed"):
                diagnostic.debugfs_output(Path("/proc/self/fd/4"), Path("/root.img"),
                                          "icheck 42", 4)

    def boot_receipt(self):
        bundle = self.root / "native-rust"
        artifacts = bundle / "artifacts"
        artifacts.mkdir(parents=True)
        binary = bytearray(96)
        binary[:6] = b"\x7fELF\x02\x01"
        binary[16:18] = b"\x03\x00"
        binary[18:20] = b"\x3e\x00"
        binary[64:] = b"TEST_ONLY_NATIVE_RECEIPT_BINARY____"
        binary = bytes(binary)
        (artifacts / "zrpc-gcp-early-init").write_bytes(binary)
        revision = "a" * 40
        manifest_sha256 = "b" * 64
        report = {
            "status": "diagnostic-unsigned-x86_64-rust-inputs-unapproved",
            "source_commit": revision,
            "reproduction_manifest_sha256": manifest_sha256,
            "artifacts": {"early_init": {
                "path": "early_init", "sha256": diagnostic.sha256(binary)}},
            "image_built": False,
            "private_mode_approved": False,
        }
        return bundle, revision, binary, report

    def selected(self, report):
        return SimpleNamespace(report=report, output=lambda _: b"selected source")

    def boot_input_lock(self, inputs, binary):
        inputs.mkdir()
        artifacts = {}
        for role in diagnostic.SYNTHETIC_ROLES | {
                "secure_boot_certificate", "boot_policy"}:
            data = (binary if role == "early_init" else
                    diagnostic.SYNTHETIC_ELF if role in diagnostic.SYNTHETIC_ROLES else
                    diagnostic.SYNTHETIC_CERTIFICATE if role == "secure_boot_certificate" else
                    diagnostic.SYNTHETIC_BOOT_POLICY)
            (inputs / role).write_bytes(data)
            artifacts[role] = {"path": role, "sha256": diagnostic.sha256(data)}
        return {"artifacts": artifacts}

    def test_missing_esp_root_or_verity_blocks_integrated_inspection(self):
        for index, role in enumerate(("root", "verity", "ESP")):
            with self.subTest(missing=role):
                stage = self.make_output(without_partition(index))
                with self.assertRaisesRegex(ValueError, "exactly the reviewed three partitions"):
                    diagnostic.inspect(stage, self.root, self.root, self.root, {})
                # The next case needs a fresh stage, not a reused output.
                for path in (stage / "output").iterdir():
                    path.unlink()
                (stage / "output").rmdir()
                stage.rmdir()

    def test_missing_uki_blocks_before_package_or_hardware_inspection(self):
        stage = self.make_output(gpt_fixture.synthetic_disk())
        (stage / "output/zrpc-gcp.efi").unlink()
        with self.assertRaisesRegex(ValueError, "output set differs"):
            diagnostic.inspect(stage, self.root, self.root, self.root, {})

    def test_report_exposes_verified_root_and_hash_partition_digests(self):
        stage = self.make_output(gpt_fixture.synthetic_disk())
        output = stage / "output"
        boot = {"uki_sha256": diagnostic.sha256((output / "zrpc-gcp.efi").read_bytes()),
                "uki_sections": {
                    ".linux": {"sha256": diagnostic.sha256(
                        (output / "zrpc-gcp.vmlinuz").read_bytes())},
                    ".initrd": {"sha256": diagnostic.sha256(
                        (output / "zrpc-gcp.initrd").read_bytes())}}}
        hashes = {"root_partition_guid": "root-guid",
                  "verity_partition_sha256": "a" * 64}
        workload = {"status": diagnostic.rootfs.STATUS,
                    "raw_disk_sha256": diagnostic.sha256((output / "zrpc-gcp.raw").read_bytes()),
                    "root_partition_guid": "root-guid",
                    "root_partition_sha256": "b" * 64,
                    "filesystem_uuid": "2a73c4e5-1b2c-4d5e-8f90-a1b2c3d4e5f6",
                    "filesystem_created_utc": "Mon Sep 28 12:34:56 2026",
                    "directory_hash_seed": "3b84d5f6-2c3d-4e5f-901a-b2c3d4e5f607",
                    "reader_executable_matches_signed_package": True,
                    "private_mode_approved": False,
                    "overlay_entries_checked": {"file": 2}}
        with (mock.patch.object(diagnostic.gpt, "inspect"),
              mock.patch.object(diagnostic.esp, "inspect", return_value=boot),
              mock.patch.object(diagnostic.verity, "inspect", return_value=hashes),
              mock.patch.object(diagnostic.roothash, "inspect",
                                return_value={"roothash": "c" * 64}),
              mock.patch.object(diagnostic.rootfs, "inspect", return_value=workload),
              mock.patch.object(diagnostic.packages, "verify", return_value={
                  "status": "diagnostic_supplied_package_lists_match_only"}),
              mock.patch.object(diagnostic.outer, "checked_split_initrd")):
            report = diagnostic.inspect(stage, self.root, self.root, self.root, {})
            self.assertEqual(report["root_partition_sha256"], "b" * 64)
            for field in diagnostic.rootfs.SUPER_FIELDS.values():
                self.assertEqual(report[field], workload[field])
            self.assertEqual(report["verity_partition_sha256"], "a" * 64)
            self.assertTrue(report["gpt_esp_verity_uki_inspected"])
            for source, field in ((workload, "root_partition_sha256"),
                                  (hashes, "verity_partition_sha256")):
                with self.subTest(field=field):
                    original = source[field]
                    source[field] = "not-a-digest"
                    with self.assertRaisesRegex(ValueError, "synthetic workload bytes"):
                        diagnostic.inspect(stage, self.root, self.root, self.root, {})
                    source[field] = original
            for field in diagnostic.rootfs.SUPER_FIELDS.values():
                with self.subTest(field=field):
                    original = workload.pop(field)
                    with self.assertRaisesRegex(ValueError, "lacks required metadata"):
                        diagnostic.inspect(stage, self.root, self.root, self.root, {})
                    workload[field] = "malformed"
                    with self.assertRaises(ValueError):
                        diagnostic.inspect(stage, self.root, self.root, self.root, {})
                    workload[field] = original

    def test_changed_workload_with_recomputed_hash_is_still_refused(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        artifacts = {}
        for role in diagnostic.SYNTHETIC_ROLES | {
                "secure_boot_certificate", "boot_policy"}:
            data = (diagnostic.SYNTHETIC_ELF if role in diagnostic.SYNTHETIC_ROLES else
                    diagnostic.SYNTHETIC_CERTIFICATE if role == "secure_boot_certificate"
                    else diagnostic.SYNTHETIC_BOOT_POLICY)
            (inputs / role).write_bytes(data)
            artifacts[role] = {"path": role, "sha256": diagnostic.sha256(data)}
        lock = {"artifacts": artifacts}
        self.assertEqual(diagnostic.checked_synthetic_inputs(lock, inputs),
                         sorted(diagnostic.SYNTHETIC_ROLES))
        changed = diagnostic.SYNTHETIC_ELF + b"even if the lock hashes it"
        (inputs / "wrapper").write_bytes(changed)
        lock["artifacts"]["wrapper"]["sha256"] = diagnostic.sha256(changed)
        with self.assertRaisesRegex(ValueError, "non-synthetic workload"):
            diagnostic.checked_synthetic_inputs(lock, inputs)

    def test_override_is_only_for_exact_production_staged_recipe(self):
        # Reuse the existing staging fixture: it copies the real profile and
        # obtains a source-bound stage manifest, with synthetic package inputs.
        fixture = prepare_fixture.CandidateTests("test_verify_stage_matches_only_pinned_source_inputs")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        stage, report = fixture.stage_synthetic_candidate()
        config = stage / "mkosi.conf"
        before = config.read_bytes()
        self.assertEqual(diagnostic.checked_override(
            stage, report["manifest_sha256"], report["manifest_bytes"]),
            diagnostic.SECURE_BOOT_OVERRIDE)
        self.assertEqual(config.read_bytes(), before)
        for old, new in ((b"SecureBoot=yes\n", b"SecureBoot=no\n"),
                         (b"Bootloader=uki\n", b"Bootloader=none\n"),
                         (b"RepartDirectories=repart\n", b"RepartDirectories=other\n"),
                         (b"BuildSources=\n", b"BuildSources=.\n"),
                         (b"WorkspaceDirectory=work\n", b"WorkspaceDirectory=other\n"),
                         (diagnostic.prepare.EXTERNAL_SECURE_BOOT_KEY.encode(),
                          b"/tmp/unreviewed.key")):
            with self.subTest(changed=old):
                config.write_bytes(before.replace(old, new, 1))
                with self.assertRaisesRegex(ValueError, "staged input differs"):
                    diagnostic.checked_override(
                        stage, report["manifest_sha256"], report["manifest_bytes"])
                config.write_bytes(before)

    def test_changed_staged_synthetic_workload_blocks_rootfs_comparison(self):
        fixture = prepare_fixture.CandidateTests("test_verify_stage_matches_only_pinned_source_inputs")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        stage, _ = fixture.stage_synthetic_candidate()
        manifest = json.loads((stage / "candidate-manifest.json").read_text())
        diagnostic.rootfs.checked_overlay(manifest, stage)
        wrapper = stage / "rootfs/usr/lib/zrpc/zrpc-node-wrapper"
        original_mode = wrapper.stat().st_mode & 0o777
        wrapper.chmod(original_mode | 0o200)
        wrapper.write_bytes(wrapper.read_bytes() + b"changed after staging")
        wrapper.chmod(original_mode)
        with self.assertRaisesRegex(ValueError, "staged rootfs file bytes differ"):
            diagnostic.rootfs.checked_overlay(manifest, stage)

    def test_non_synthetic_inputs_prevent_mkosi_invocation(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        changed = diagnostic.SYNTHETIC_ELF + b"changed"
        (inputs / "wrapper").write_bytes(changed)
        lock = self.root / "lock.json"
        lock.write_text(json.dumps({"artifacts": {"wrapper": {
            "path": "wrapper", "sha256": diagnostic.sha256(changed)}}}))
        with mock.patch.object(diagnostic.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                diagnostic.build(lock, inputs, self.root / "stage", self.root,
                                 self.root, self.root, self.root, self.root,
                                 "user:[0]", "net:[0]", "pid:[0]")
            run.assert_not_called()

    def test_boot_receipt_accepts_only_exact_head_native_early_init(self):
        bundle, revision, binary, report = self.boot_receipt()
        selected = self.selected(report)
        with (mock.patch.object(diagnostic, "selected_boot_source", return_value=selected),
              mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=report) as inspect):
            observed, manifest = diagnostic.checked_boot_receipt(bundle, revision)
        self.assertEqual(observed, binary)
        self.assertEqual(manifest, report["reproduction_manifest_sha256"])
        inspect.assert_called_once_with(bundle, revision,
                                        selected_output=selected.output)

        with (mock.patch.object(diagnostic, "selected_boot_source") as source,
              mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=report) as inspect):
            with self.assertRaisesRegex(ValueError, "exact-HEAD"):
                diagnostic.checked_boot_receipt(bundle, "HEAD")
            source.assert_not_called()
            inspect.assert_not_called()
        for changed in (
                {**report, "source_commit": "c" * 40},
                {**report, "private_mode_approved": True},
                {**report, "status": "approved"},
                {**report, "artifacts": {"early_init": {
                    "path": "wrapper", "sha256": diagnostic.sha256(binary)}}},
        ):
            with self.subTest(receipt=changed):
                with (mock.patch.object(diagnostic, "selected_boot_source",
                                        return_value=self.selected(changed)),
                      mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=changed)):
                    with self.assertRaisesRegex(ValueError, "cannot supply"):
                        diagnostic.checked_boot_receipt(bundle, revision)
        (bundle / "artifacts/zrpc-gcp-early-init").write_bytes(binary + b"changed")
        with (mock.patch.object(diagnostic, "selected_boot_source", return_value=selected),
              mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=report)):
            with self.assertRaisesRegex(ValueError, "differs from exact-HEAD"):
                diagnostic.checked_boot_receipt(bundle, revision)
        (bundle / "artifacts/zrpc-gcp-early-init").write_bytes(diagnostic.SYNTHETIC_ELF)
        synthetic = {**report, "artifacts": {"early_init": {
            "path": "early_init", "sha256": diagnostic.sha256(diagnostic.SYNTHETIC_ELF)}}}
        with (mock.patch.object(diagnostic, "selected_boot_source",
                                return_value=self.selected(synthetic)),
              mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=synthetic)):
            with self.assertRaisesRegex(ValueError, "differs from exact-HEAD"):
                diagnostic.checked_boot_receipt(bundle, revision)

    def test_boot_source_must_match_selected_archive_without_git(self):
        bundle, revision, _, report = self.boot_receipt()
        producer = Path(diagnostic.__file__).read_bytes()
        selected = SimpleNamespace(report=report, output=lambda _: producer)
        with (mock.patch.object(diagnostic.outer, "checked_package_runner_bytes") as package,
              mock.patch.object(diagnostic.package_runner, "ReceiptSourceArchive",
                                return_value=selected)):
            self.assertIs(diagnostic.selected_boot_source(bundle, revision), selected)
            package.assert_called_once_with(
                revision, bundle, Path(diagnostic.__file__).with_name("package_initrd_runner.py"))
        changed = SimpleNamespace(report=report, output=lambda _: b"changed source")
        with (mock.patch.object(diagnostic.outer, "checked_package_runner_bytes"),
              mock.patch.object(diagnostic.package_runner, "ReceiptSourceArchive",
                                return_value=changed)):
            with self.assertRaisesRegex(ValueError, "producer differs"):
                diagnostic.selected_boot_source(bundle, revision)

    def test_boot_input_creation_binds_only_init_and_cannot_approve(self):
        bundle, revision, binary, report = self.boot_receipt()
        metadata = self.root / "metadata"
        archives = self.root / "archives"
        metadata.mkdir()
        archives.mkdir()
        (metadata / "InRelease").write_bytes(b"test signed metadata")
        (metadata / "Packages.xz").write_bytes(b"test signed package index")
        package_bytes = b"test signed package archive"
        package_sha256 = diagnostic.sha256(package_bytes)
        (archives / (package_sha256 + ".deb")).write_bytes(package_bytes)
        manifest = [{"path": "debs/package.deb", "size": len(package_bytes),
                     "sha256": package_sha256}]
        disk_packages = {role: {"size": len(package_bytes), "sha256": package_sha256}
                         for role in diagnostic.prepare.DISK_TOOL_PACKAGES}
        inputs = self.root / "inputs"
        lock_path = self.root / "inputs.lock.json"
        with (mock.patch.object(diagnostic, "selected_boot_source",
                                return_value=self.selected(report)),
              mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=report),
              mock.patch.object(diagnostic.guest, "verify_cached_archives", return_value={
                  "status": "diagnostic-guest-archives-matched-signed-snapshot-unbuilt",
                  "signed_snapshot_rechecked": True,
                  "private_mode_approved": False}),
              mock.patch.object(diagnostic.guest, "reviewed_manifest",
                                return_value=(b"[]", manifest)),
              mock.patch.object(diagnostic.prepare, "DISK_TOOL_PACKAGES", disk_packages),
              mock.patch.object(diagnostic.prepare, "validate_lock")):
            staged = diagnostic.create_boot_inputs(metadata, archives, inputs,
                                                   lock_path, bundle, revision)
        lock = json.loads(lock_path.read_text())
        for role in disk_packages:
            self.assertEqual((inputs / role).read_bytes(), package_bytes)
            self.assertEqual(lock["artifacts"][role]["sha256"], package_sha256)
        self.assertEqual((inputs / "early_init").read_bytes(), binary)
        self.assertEqual((inputs / "wrapper").read_bytes(), diagnostic.SYNTHETIC_ELF)
        self.assertEqual((inputs / "zebra").read_bytes(), diagnostic.SYNTHETIC_ELF)
        self.assertEqual(diagnostic.checked_diagnostic_inputs(lock, inputs, binary),
                         sorted(diagnostic.SYNTHETIC_ROLES))
        with self.assertRaisesRegex(ValueError, "non-synthetic"):
            diagnostic.checked_synthetic_inputs(lock, inputs)
        self.assertFalse(staged["synthetic_workload"])
        self.assertTrue(staged["synthetic_service_payloads"])
        self.assertFalse(staged["boot_verified"])
        self.assertFalse(staged["private_mode_approved"])
        self.assertEqual(staged["native_early_init_sha256"], diagnostic.sha256(binary))

        for role in ("wrapper", "zebra", "secure_boot_certificate"):
            with self.subTest(changed=role):
                before = (inputs / role).read_bytes()
                (inputs / role).write_bytes(before + b"changed")
                with self.assertRaisesRegex(ValueError, "non-synthetic"):
                    diagnostic.checked_diagnostic_inputs(lock, inputs, binary)
                (inputs / role).write_bytes(before)

    def test_bad_boot_receipt_creates_no_inputs_or_invokes_builder(self):
        bundle, revision, binary, report = self.boot_receipt()
        inputs = self.root / "inputs"
        lock_path = self.root / "inputs.lock.json"
        with (mock.patch.object(diagnostic, "selected_boot_source",
                                return_value=self.selected(report)),
              mock.patch.object(diagnostic.rust_inputs, "inspect",
                                side_effect=ValueError("receipt rejected"))):
            with self.assertRaisesRegex(ValueError, "receipt rejected"):
                diagnostic.create_boot_inputs(self.root, self.root, inputs,
                                              lock_path, bundle, revision)
        self.assertFalse(inputs.exists())
        self.assertFalse(lock_path.exists())
        self.boot_input_lock(inputs, binary)
        (inputs / "wrapper").write_bytes(b"changed service")
        lock = {"artifacts": {role: {"path": role,
                "sha256": diagnostic.sha256((inputs / role).read_bytes())}
                for role in diagnostic.SYNTHETIC_ROLES | {
                    "secure_boot_certificate", "boot_policy"}}}
        lock_path.write_text(json.dumps(lock))
        with (mock.patch.object(diagnostic, "selected_boot_source",
                                return_value=self.selected(report)),
              mock.patch.object(diagnostic.rust_inputs, "inspect", return_value=report),
              mock.patch.object(diagnostic.subprocess, "run") as run):
            with self.assertRaisesRegex(ValueError, "non-synthetic"):
                diagnostic.build_boot(lock_path, inputs, self.root / "stage",
                                      self.root, self.root, self.root, self.root,
                                      self.root, "net:[0]", "user:[0]", "pid:[0]",
                                      bundle, revision)
            run.assert_not_called()

    def test_boot_build_rechecks_native_receipt_after_mkosi(self):
        bundle, revision, binary, _ = self.boot_receipt()
        inputs = self.root / "inputs"
        lock = self.boot_input_lock(inputs, binary)
        lock_path = self.root / "inputs.lock.json"
        lock_path.write_text(json.dumps(lock))
        stage = self.root / "stage"
        receipt = [(binary, "b" * 64), (binary + b"changed", "b" * 64)]

        def staged(*_):
            stage.mkdir()
            (stage / "candidate-manifest.json").write_text("{}")
            return {"manifest_sha256": "c" * 64, "manifest_bytes": b"manifest"}

        with (mock.patch.object(diagnostic, "checked_boot_receipt", side_effect=receipt),
              mock.patch.object(diagnostic.builder, "verify_execution_context",
                                return_value={"status": "diagnostic-signed-staged-builder-no-route"}),
              mock.patch.object(diagnostic.guest, "verify_cached_archives",
                                return_value={"signed_snapshot_rechecked": True}),
              mock.patch.object(diagnostic.prepare, "stage", side_effect=staged),
              mock.patch.object(diagnostic, "checked_override",
                                return_value=diagnostic.SECURE_BOOT_OVERRIDE),
              mock.patch.object(diagnostic.outer, "immutable_stage_inventory",
                                return_value={}),
              mock.patch.object(diagnostic.prepare, "digest", return_value="c" * 64),
              mock.patch.object(diagnostic.subprocess, "run",
                                return_value=SimpleNamespace(returncode=0)) as run,
              mock.patch.object(diagnostic, "inspect", return_value={
                  "private_mode_approved": False})):
            with self.assertRaisesRegex(ValueError, "changed during boot disk build"):
                diagnostic.build_boot(lock_path, inputs, stage, self.root,
                                      self.root, self.root, self.root, self.root,
                                      "net:[0]", "user:[0]", "pid:[0]",
                                      bundle, revision)
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
