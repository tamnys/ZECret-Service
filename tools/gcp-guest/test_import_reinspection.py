"""Synthetic orchestration checks; no signed image, cloud API, or approval."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("outer_image_runner", HERE / "outer_image_runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
REAL_INSPECTED_UKI_DIGEST = runner.inspected_uki_digest


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ReinspectImportTests(unittest.TestCase):
    def setUp(self):
        scratch = runner.ROOT / ".codex-tmp"
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-reinspection-",
                                                     dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.stage = root / "stage"
        output = self.stage / "output"
        output.mkdir(parents=True)
        self.old = b"synthetic mkosi disk"
        (output / "zrpc-gcp.raw").write_bytes(self.old)
        roles = {name: {"sha256": "a" * 64}
                 for name in ("wrapper", "broker", "guard", "cookie", "early_init")}
        (self.stage / "inputs.lock.json").write_text(json.dumps({"artifacts": roles}))
        (self.stage / "candidate-manifest.json").write_text(json.dumps({
            "entries": {}, "input_lock_sha256": sha(
                (self.stage / "inputs.lock.json").read_bytes())}) + "\n")
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.import_directory = self.workspace / "import"
        self.metadata = root / "metadata"
        self.metadata.mkdir()
        self.inputs = root / "inputs"
        self.inputs.mkdir()
        self.archives = root / "archives"
        self.archives.mkdir()
        self.rust = root / "rust"
        self.rust.mkdir()
        (self.rust / "manifest.json").write_text("{}\n")
        self.zebra_receipt = root / "zebra-receipt.json"
        self.zebra_receipt.write_text("{}")
        self.sfdisk = root / "sfdisk"
        self.sfdisk.write_text("synthetic path only")
        self.final_bytes = b"synthetic final disk"
        self.final_sha = sha(self.final_bytes)
        self.old_sha = sha(self.old)
        self.uki_sha = "b" * 64
        self.root_sha = "c" * 64
        self.roothash = "d" * 64
        self.calls = []

        def inspect(name, report):
            def run(*args):
                self.calls.append((name, args))
                return report.copy()
            return run

        identity = {"raw_disk_sha256": self.final_sha,
                    "raw_disk_bytes": len(self.final_bytes),
                    "private_mode_approved": False}
        self.layout = {**identity, "status": "diagnostic-gpt-only-unapproved"}
        self.boot = {**identity, "status": "diagnostic-esp-uki-sections-unapproved",
                     "uki_sha256": self.uki_sha, "uki_bytes": 16}
        self.verity = {**identity, "status": "diagnostic-raw-root-verity-unapproved",
                       "verity_userspace_verified": True}
        self.binding = {**identity, "status": "diagnostic-uki-roothash-gpt-match-unapproved",
                        "roothash": self.roothash}
        self.rootfs = {**identity, "status": "diagnostic-raw-root-overlay-bytes-matched-unapproved",
                       "root_partition_sha256": self.root_sha,
                       "reader_executable_matches_signed_package": True}
        self.uki_digest = {"schema_version": 1,
                           "status": "diagnostic-uki-pe-coff-sha384-unapproved",
                           "uki_sha256": self.uki_sha, "uki_bytes": 16,
                           "private_mode_approved": False}
        prepare = types.SimpleNamespace(
            verify_stage=mock.Mock(), validate_lock=mock.Mock(),
            unique_object=runner.unique_object)
        source = types.SimpleNamespace(
            guest=types.SimpleNamespace(prepare=prepare),
            rust_inputs=types.SimpleNamespace(inspect=mock.Mock(return_value={
                "artifacts": {name: {"sha256": "a" * 64} for name in roles}})))
        self.context = types.SimpleNamespace(
            selected=types.SimpleNamespace(output=mock.Mock()), source=source,
            package=types.SimpleNamespace(check_loopback_only_ip_state=mock.Mock(
                return_value={"loopback_only": True})),
            import_disk=types.SimpleNamespace(
                SFDISK_SHA256="e" * 64, SFDISK_PACKAGE_SHA256="f" * 64,
                _prepare=mock.Mock(side_effect=self.size_disk)),
            gpt=types.SimpleNamespace(inspect=inspect("gpt", self.layout)),
            esp=types.SimpleNamespace(inspect=inspect("esp", self.boot)),
            verity=types.SimpleNamespace(inspect=inspect("verity", self.verity)),
            roothash=types.SimpleNamespace(inspect=inspect("roothash", self.binding)),
            rootfs=types.SimpleNamespace(
                STATUS="diagnostic-raw-root-overlay-bytes-matched-unapproved",
                inspect=inspect("rootfs", self.rootfs)))
        self.patches = [
            mock.patch.object(runner, "source_context", return_value=self.context),
            mock.patch.object(runner, "checked_source_tree"),
            mock.patch.object(runner, "immutable_stage_inventory", return_value=2),
            mock.patch.object(runner, "checked_outputs", return_value={
                "zrpc-gcp.raw": (len(self.old), self.old_sha)}),
            mock.patch.object(runner, "inspect_outputs", return_value={
                "uki_sha256": self.uki_sha, "roothash": self.roothash,
                "raw_rootfs_audit": {"root_partition_sha256": self.root_sha}}),
            mock.patch.object(runner, "checked_zebra"),
            mock.patch.object(runner, "checked_sfdisk_package", return_value=({
                "sfdisk_sha256": "e" * 64,
                "sfdisk_package_archive_sha256": "f" * 64,
                "sfdisk_archive_membership_rechecked": True,
                "sfdisk_dynamic_runtime_authenticated": False}, (b"program", b"loader", ()))),
            mock.patch.object(runner, "signed_sfdisk_runtime"),
            mock.patch.object(runner, "inspected_uki_digest", return_value=self.uki_digest),
            mock.patch.object(runner, "require_unchanged_outputs"),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def size_disk(self, source, source_sha, source_bytes, destination, sfdisk, **kwargs):
        self.assertEqual((source, source_sha, source_bytes, sfdisk),
                         (self.stage / "output/zrpc-gcp.raw", self.old_sha,
                          len(self.old), self.sfdisk))
        self.assertIs(kwargs["gpt_module"], self.context.gpt)
        self.assertTrue(callable(kwargs["sfdisk_runner"]))
        destination.write_bytes(self.final_bytes)
        return {"status": "diagnostic-import-sized-gpt-unapproved",
                "mkosi_disk_sha256": self.old_sha, "mkosi_disk_bytes": len(self.old),
                "raw_disk_sha256": self.final_sha,
                "raw_disk_bytes": len(self.final_bytes),
                "sfdisk_sha256": "e" * 64,
                "sfdisk_package_archive_sha256": "f" * 64,
                "sfdisk_archive_membership_rechecked": False,
                "sfdisk_dynamic_runtime_authenticated": False,
                "import_package_ready": False, "private_mode_approved": False}

    def run_import(self, *, source_sha=None, rust_manifest_sha=None):
        return runner.reinspect_import(
            self.stage, self.inputs, self.rust, "f" * 40, self.metadata, self.archives,
            self.workspace, self.import_directory, self.sfdisk,
            self.old_sha if source_sha is None else source_sha, len(self.old),
            sha((self.rust / "manifest.json").read_bytes())
            if rust_manifest_sha is None else rust_manifest_sha,
            self.zebra_receipt, "parent-net", "parent-mount")

    def test_final_identity_is_inspected_and_packaging_reports_are_new(self):
        report = self.run_import()
        raw = self.import_directory / "disk.raw"
        self.assertEqual(raw.read_bytes(), self.final_bytes)
        self.assertEqual(report["raw_disk_sha256"], self.final_sha)
        self.assertEqual(report["raw_disk_bytes"], len(self.final_bytes))
        self.assertEqual(report["sfdisk_sha256"], "e" * 64)
        self.assertTrue(report["sfdisk_archive_membership_rechecked"])
        self.assertFalse(report["sfdisk_dynamic_runtime_authenticated"])
        self.assertEqual(report["input_lock_sha256"],
                         sha((self.stage / "inputs.lock.json").read_bytes()))
        self.assertEqual(report["native_rust_manifest_sha256"],
                         sha((self.rust / "manifest.json").read_bytes()))
        self.assertFalse(report["import_archive_created"])
        self.assertFalse(report["import_package_ready"])
        self.assertFalse(report["private_mode_approved"])
        for name in ("gpt", "esp", "verity", "rootfs"):
            arguments = dict(self.calls)[name]
            self.assertEqual(arguments[:4],
                             (raw, self.final_sha, len(self.final_bytes), 512))
        for key, filename in (("esp_diagnostic", "esp.json"),
                              ("uki_digest_diagnostic", "uki-digest.json"),
                              ("verity_diagnostic", "verity.json")):
            artifact = report["package_diagnostics"][key]
            self.assertEqual(artifact["path"], str(self.import_directory / filename))
            self.assertEqual(artifact["sha256"], sha(Path(artifact["path"]).read_bytes()))
        self.assertEqual(report["receipt_artifact"]["sha256"],
                         sha((self.import_directory / "reinspection.json").read_bytes()))

    def test_wrong_source_identity_stops_before_conversion(self):
        with self.assertRaisesRegex(ValueError, "recorded exact identity"):
            self.run_import(source_sha="0" * 64)
        self.context.import_disk._prepare.assert_not_called()
        self.assertFalse(self.import_directory.exists())

    def test_unsigned_sfdisk_package_stops_before_conversion(self):
        runner.checked_sfdisk_package.side_effect = ValueError(
            "sfdisk executable differs from signed fdisk package")
        with self.assertRaisesRegex(ValueError, "sfdisk executable differs"):
            self.run_import()
        self.context.import_disk._prepare.assert_not_called()
        self.assertFalse(self.import_directory.exists())

    def test_unchecked_sfdisk_loader_stops_before_conversion(self):
        runner.signed_sfdisk_runtime.side_effect = ValueError(
            "signed sfdisk ELF loader used ambient objects")
        with self.assertRaisesRegex(ValueError, "ambient objects"):
            self.run_import()
        self.context.import_disk._prepare.assert_not_called()
        self.assertFalse(self.import_directory.exists())

    def test_second_rust_bundle_manifest_stops_before_conversion(self):
        with self.assertRaisesRegex(ValueError, "Rust bundle differs"):
            self.run_import(rust_manifest_sha="0" * 64)
        self.context.import_disk._prepare.assert_not_called()
        self.assertFalse(self.import_directory.exists())

    def test_wrong_final_inspector_identity_writes_no_handoff_receipt(self):
        self.context.verity.inspect = mock.Mock(return_value={
            **self.verity, "raw_disk_sha256": self.old_sha})
        with self.assertRaisesRegex(ValueError, "final import disk inspection differs"):
            self.run_import()
        self.assertFalse((self.import_directory / "reinspection.json").exists())
        self.assertFalse((self.import_directory / "esp.json").exists())

    def test_changed_final_disk_bytes_write_no_handoff_receipt(self):
        def changed_rootfs(*_args):
            (self.import_directory / "disk.raw").write_bytes(b"changed final bytes")
            return self.rootfs.copy()
        self.context.rootfs.inspect = changed_rootfs
        with self.assertRaisesRegex(ValueError, "final import disk inspection differs"):
            self.run_import()
        self.assertFalse((self.import_directory / "reinspection.json").exists())

    def test_uki_digest_requires_receipt_binary_and_exact_esp_bytes(self):
        output = self.stage / "output"
        uki = b"synthetic UKI bytes"
        (output / "zrpc-gcp.efi").write_bytes(uki)
        binary = self.rust / "artifacts/zrpc-uki-digest"
        binary.parent.mkdir()
        binary.write_bytes(b"synthetic digest executable")
        (self.rust / "manifest.json").write_text(json.dumps({
            "artifact_sha256": {"zrpc-uki-digest": sha(binary.read_bytes())}}))
        boot = {"uki_sha256": sha(uki), "uki_bytes": len(uki)}
        result = {"schema_version": 1,
                  "status": "diagnostic-uki-pe-coff-sha384-unapproved",
                  **boot, "signed_uki_checked": False,
                  "boot_measurement_checked": False,
                  "release_approved": False, "private_mode_approved": False}
        completed = types.SimpleNamespace(returncode=0, stdout=json.dumps(result).encode())
        with mock.patch.object(runner.subprocess, "run", return_value=completed) as invoked:
            self.assertEqual(REAL_INSPECTED_UKI_DIGEST(self.context, self.rust,
                                                        output, boot), result)
            self.assertEqual(invoked.call_args.args[0][:4],
                             [str(binary), str(output / "zrpc-gcp.efi"),
                              sha(uki), str(len(uki))])
        bad = types.SimpleNamespace(returncode=0, stdout=json.dumps({
            **result, "uki_sha256": "0" * 64}).encode())
        with mock.patch.object(runner.subprocess, "run", return_value=bad):
            with self.assertRaisesRegex(ValueError, "differs from inspected import disk"):
                REAL_INSPECTED_UKI_DIGEST(self.context, self.rust, output, boot)
        (output / "zrpc-gcp.efi").write_bytes(b"changed")
        with mock.patch.object(runner.subprocess, "run") as invoked:
            with self.assertRaisesRegex(ValueError, "differs from signed mkosi output"):
                REAL_INSPECTED_UKI_DIGEST(self.context, self.rust, output, boot)
            invoked.assert_not_called()
        binary.write_bytes(b"replaced executable")
        with mock.patch.object(runner.subprocess, "run") as invoked:
            with self.assertRaisesRegex(ValueError, "native Rust receipt"):
                REAL_INSPECTED_UKI_DIGEST(self.context, self.rust, output, boot)
            invoked.assert_not_called()

    def test_existing_build_cli_dispatch_still_passes_its_arguments(self):
        arguments = ["build", "--lock", str(self.stage / "inputs.lock.json"),
                     "--inputs", str(self.inputs),
                     "--zebra-receipt", str(self.zebra_receipt),
                     "--rust-bundle", str(self.rust), "--stage", str(self.stage),
                     "--metadata", str(self.metadata),
                     "--builder-archives", str(self.archives),
                     "--workspace", str(self.workspace),
                     "--revision", "f" * 40,
                     "--parent-network-namespace", "parent-net",
                     "--parent-mount-namespace", "parent-mount"]
        with mock.patch.object(runner, "build", return_value={
                "status": "candidate-outer-image-built-unapproved"}) as built:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(arguments), 0)
        self.assertEqual(built.call_args.args,
                         (self.stage / "inputs.lock.json", self.inputs,
                          self.zebra_receipt, self.rust, "f" * 40, self.stage,
                          self.metadata, self.archives, self.workspace,
                          "parent-net", "parent-mount"))


if __name__ == "__main__":
    unittest.main()
