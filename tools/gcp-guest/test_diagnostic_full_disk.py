"""Fail-closed tests for the unsigned, deliberately unbootable disk rehearsal."""

import json
from pathlib import Path
import struct
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

    def make_output(self, disk):
        stage = self.root / "stage"
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


if __name__ == "__main__":
    unittest.main()
