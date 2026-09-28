#!/usr/bin/env python3
"""Synthetic GPT checks for offline import sizing; no guest boot or cloud API."""

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("prepare_import_disk", HERE / "prepare_import_disk.py")
import_disk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(import_disk)
fixture_spec = importlib.util.spec_from_file_location("test_inspect_raw_gpt", HERE / "test_inspect_raw_gpt.py")
fixture = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture)


class PrepareImportDiskTests(unittest.TestCase):
    def setUp(self):
        workspace_temp = Path.cwd() / ".codex-tmp"
        workspace_temp.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-import-", dir=workspace_temp)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "zrpc-gcp.raw"
        self.source.write_bytes(fixture.synthetic_disk())
        self.output = self.root / "disk.raw"
        self.original_sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.original_size = self.source.stat().st_size

    def prepare(self, *, sfdisk=None, sha=None, env=None):
        return import_disk._prepare(
            self.source, self.original_sha if sha is None else sha,
            self.original_size, self.output,
            sfdisk if sfdisk is not None else self.root / "missing-sfdisk",
            allow_non_workspace_paths=True, sfdisk_env=env)

    def signed_tool(self):
        binary = os.environ.get("SFDISK_TEST_BINARY")
        library = os.environ.get("SFDISK_TEST_LIBDIR")
        if not binary or not library:
            self.skipTest("signed fdisk package and libfdisk test paths not supplied")
        path = Path(binary)
        with path.open("rb") as stream:
            self.assertEqual(hashlib.file_digest(stream, "sha256").hexdigest(),
                             import_disk.SFDISK_SHA256)
        return path, {"LD_LIBRARY_PATH": library, "LC_ALL": "C", "PATH": "/usr/bin:/bin"}

    def test_rejects_wrong_source_identity_and_existing_output(self):
        with self.assertRaisesRegex(ValueError, "reviewed input identity"):
            self.prepare(sha="0" * 64)
        self.assertFalse(self.output.exists())
        self.output.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "new absolute disk.raw"):
            self.prepare()
        self.assertEqual(self.output.read_bytes(), b"existing")

    def test_rejects_unpinned_executable_before_copy(self):
        fake = self.root / "fake-sfdisk"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "differs from pinned"):
            self.prepare(sfdisk=fake)
        self.assertFalse(self.output.exists())

    def test_signed_sfdisk_relocates_and_reinspects_final_disk(self):
        binary, environment = self.signed_tool()
        report = self.prepare(sfdisk=binary, env=environment)
        self.assertEqual(self.output.stat().st_size, import_disk.GIB)
        self.assertEqual(self.source.stat().st_size, self.original_size)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.original_sha)
        self.assertEqual(report["status"], "diagnostic-import-sized-gpt-unapproved")
        self.assertEqual(report["raw_disk_bytes"], import_disk.GIB)
        self.assertEqual(report["full_image_reinspection_required"],
                         ["esp", "uki", "rootfs", "verity"])
        self.assertTrue(report["gpt_reinspected"])
        self.assertTrue(report["partition_bytes_preserved"])
        self.assertTrue(report["old_backup_gpt_removed"])
        self.assertFalse(report["import_package_ready"])
        self.assertFalse(report["private_mode_approved"])
        original = self.source.read_bytes()
        old_backup_start = (self.original_size // fixture.SECTOR - 1
                            - fixture.TABLE_BYTES // fixture.SECTOR) * fixture.SECTOR
        with self.output.open("rb") as stream:
            stream.seek(old_backup_start)
            self.assertEqual(stream.read(self.original_size - old_backup_start),
                             bytes(self.original_size - old_backup_start))
            for start, end in ((40, 80), (80, 120), (120, 160)):
                stream.seek(start * fixture.SECTOR)
                self.assertEqual(stream.read((end - start) * fixture.SECTOR),
                                 original[start * fixture.SECTOR:end * fixture.SECTOR])

    def test_partition_change_after_relocation_is_rejected(self):
        binary, environment = self.signed_tool()
        real_run = subprocess.run

        def changed_partition(*args, **kwargs):
            result = real_run(*args, **kwargs)
            if result.returncode == 0:
                with open(args[0][-1], "r+b") as stream:
                    stream.seek(40 * fixture.SECTOR)
                    stream.write(b"X")
            return result

        with mock.patch.object(import_disk.subprocess, "run", side_effect=changed_partition):
            with self.assertRaisesRegex(ValueError, "partition bytes changed"):
                self.prepare(sfdisk=binary, env=environment)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
