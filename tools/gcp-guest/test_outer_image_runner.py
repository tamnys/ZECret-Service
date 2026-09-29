"""Focused fail-closed checks for the source-bound production disk runner."""

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("outer_image_runner", HERE / "outer_image_runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class OuterImageRunnerTest(unittest.TestCase):
    def test_final_initrd_requires_unique_kernel_and_depmod_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "package_manifest"
            entries = [{"name": name} for name in ("linux-image-reviewed", "kmod", "libkmod2")]
            manifest.write_text(json.dumps(entries))
            self.assertEqual(set(runner.selected_initrd_packages(
                manifest, "linux-image-reviewed")),
                {"linux-image-reviewed", "kmod", "libkmod2"})
            for changed in (entries[:-1], entries + [entries[1]], []):
                manifest.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "lacks exact kernel or depmod"):
                    runner.selected_initrd_packages(manifest, "linux-image-reviewed")

    def test_package_runner_source_is_checked_before_any_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "rust"
            (bundle / "guest-inputs").mkdir(parents=True)
            package = root / "package_initrd_runner.py"
            marker = root / "ambient-code-ran"
            package.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n")
            selected = b"selected_source = True\n"
            archive_stream = io.BytesIO()
            with tarfile.open(fileobj=archive_stream, mode="w") as archive:
                member = tarfile.TarInfo(runner.PACKAGE_SCRIPT)
                member.size = len(selected)
                archive.addfile(member, io.BytesIO(selected))
            archive_bytes = archive_stream.getvalue()
            (bundle / "source.tar").write_bytes(archive_bytes)
            revision = "a" * 40
            manifest_bytes = json.dumps({"source_commit": revision,
                "source_tree": "b" * 40,
                "source_archive_sha256": runner.sha256(archive_bytes)}).encode()
            (bundle / "manifest.json").write_bytes(manifest_bytes)
            (bundle / "guest-inputs/diagnostic-rust-inputs.json").write_text(json.dumps({
                "status": "diagnostic-unsigned-x86_64-rust-inputs-unapproved",
                "source_commit": revision, "source_tree": "b" * 40,
                "reproduction_manifest_sha256": runner.sha256(manifest_bytes),
                "image_built": False, "private_mode_approved": False}))
            with self.assertRaisesRegex(ValueError, "differs from selected source"):
                runner.checked_package_runner_bytes(revision, bundle, package)
            self.assertFalse(marker.exists())
            package.write_bytes(selected)
            self.assertEqual(runner.checked_package_runner_bytes(revision, bundle, package),
                             selected)
            (bundle / "source.tar").write_bytes(archive_bytes + b"changed")
            with self.assertRaisesRegex(ValueError, "differs from Rust receipt"):
                runner.checked_package_runner_bytes(revision, bundle, package)

    def test_production_sector_size_is_source_pinned(self):
        recipe = (HERE.parents[1] / "deploy/gcp/guest/mkosi.conf").read_text()
        self.assertEqual(recipe.count("SectorSize=512\n"), 1)
        self.assertEqual(runner.SECTOR_SIZE, 512)
        self.assertNotIn("--sector-size", (HERE / "outer_image_runner.py").read_text())

    def test_production_workspace_requires_empty_build_sources(self):
        config = (b"SectorSize=512\nOutputDirectory=output\n"
                  b"FinalizeScripts=seal-shadow.py,sanitize-mount.py,audit-rootfs.py\n[Build]\n"
                  b"BuildSources=\nWorkspaceDirectory=work\n"
                  b"PackageCacheDirectory=package-cache\n")
        runner.checked_mkosi_recipe(config)
        for changed in (config.replace(b"BuildSources=\n", b""),
                        config.replace(b"BuildSources=\n", b"BuildSources=.\n"),
                        config.replace(b"FinalizeScripts=seal-shadow.py,sanitize-mount.py,audit-rootfs.py\n", b"FinalizeScripts=audit-rootfs.py\n"),
                        config.replace(b"WorkspaceDirectory=work\n", b"WorkspaceDirectory=other\n")):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "source layout"):
                runner.checked_mkosi_recipe(changed)

    def test_changed_output_inspector_is_rejected_before_loading(self):
        selected = types.SimpleNamespace(output=lambda arguments: b"changed selected bytes")
        with self.assertRaisesRegex(ValueError, "differs from selected HEAD"):
            runner.bind_file_module("outer_changed_gpt", "tools/gcp-guest/inspect_raw_gpt.py",
                                    selected, "a" * 40)
        self.assertNotIn("outer_changed_gpt", runner.sys.modules)

    def test_immutable_stage_recheck_allows_only_mkosi_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            config = stage / "mkosi.conf"
            config.write_bytes(b"production\n")
            (stage / "package-cache").mkdir(mode=0o700)
            manifest = {"entries": {
                "mkosi.conf": {"type": "file", "sha256": runner.sha256(config.read_bytes()),
                               "mode": config.stat().st_mode & 0o777},
                "package-cache": {"type": "directory",
                                  "mode": (stage / "package-cache").stat().st_mode & 0o777},
            }}
            (stage / "candidate-manifest.json").write_text("{}")
            (stage / "output").mkdir()
            (stage / "work").mkdir()
            (stage / "package-cache/apt-list").write_bytes(b"mutable")
            self.assertEqual(runner.immutable_stage_inventory(stage, manifest), 1)
            config.write_bytes(b"changed\n")
            with self.assertRaisesRegex(ValueError, "input changed"):
                runner.immutable_stage_inventory(stage, manifest)
            config.write_bytes(b"production\n")
            (stage / "rootfs").mkdir()
            with self.assertRaisesRegex(ValueError, "unexpected source input"):
                runner.immutable_stage_inventory(stage, manifest)

    def test_immutable_stage_rejects_redirected_output_and_missing_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            (stage / "package-cache").mkdir()
            config = stage / "mkosi.conf"
            config.write_bytes(b"source")
            manifest = {"entries": {
                "package-cache": {"type": "directory", "mode":
                                  (stage / "package-cache").stat().st_mode & 0o777},
                "mkosi.conf": {"type": "file", "sha256": runner.sha256(b"source"),
                               "mode": config.stat().st_mode & 0o777},
            }}
            (stage / "output").symlink_to(stage / "package-cache")
            with self.assertRaisesRegex(ValueError, "redirects"):
                runner.immutable_stage_inventory(stage, manifest)
            (stage / "output").unlink()
            config.unlink()
            with self.assertRaisesRegex(ValueError, "disappeared"):
                runner.immutable_stage_inventory(stage, manifest)

    def output_fixture(self, root):
        root = Path(root)
        for name in runner.OUTPUT_FILES:
            (root / name).write_bytes(name.encode())
        for name, target in runner.OUTPUT_ALIASES.items():
            (root / name).symlink_to(target)
        checksummed = ("zrpc-gcp.raw", "zrpc-gcp.efi", "zrpc-gcp.vmlinuz",
                       "zrpc-gcp.initrd")
        (root / "zrpc-gcp.SHA256SUMS").write_text("".join(
            f"{runner.sha256((root / name).read_bytes())} *{name}\n"
            for name in checksummed))

    def test_output_inspection_binds_checksum_and_alias_to_real_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.output_fixture(root)
            files = runner.checked_outputs(root)
            self.assertEqual(files["zrpc-gcp.raw"][1], runner.sha256(b"zrpc-gcp.raw"))
            (root / "zrpc-gcp").unlink()
            (root / "zrpc-gcp").symlink_to("../other.raw")
            with self.assertRaisesRegex(ValueError, "alias differs"):
                runner.checked_outputs(root)
            (root / "zrpc-gcp").unlink()
            (root / "zrpc-gcp").symlink_to("zrpc-gcp.raw")
            (root / "zrpc-gcp.raw").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum list differs"):
                runner.checked_outputs(root)
            (root / "zrpc-gcp.SHA256SUMS").write_text("".join(
                f"{runner.sha256((root / name).read_bytes())} *{name}\n"
                for name in ("zrpc-gcp.raw", "zrpc-gcp.efi",
                             "zrpc-gcp.vmlinuz", "zrpc-gcp.initrd")))
            with self.assertRaisesRegex(ValueError, "outputs changed after inspection"):
                runner.require_unchanged_outputs(root, files)
            (root / "unreviewed.efi").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "output set differs"):
                runner.checked_outputs(root)

    def test_zebra_requires_pinned_eligible_elf_and_attestation_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "zebrad").write_bytes(b"elf")
            digest = runner.sha256(b"elf")
            release = {"asset": {"created_at": "2026-09-01T00:00:00Z",
                                 "sha256": "a" * 64},
                       "minimum_age_days": 7,
                       "zebrad_elf_sha256": digest, "zebrad_elf_size": 3,
                       "gh_verifier_executable_sha256": "b" * 64}
            receipt = {"status": "staged-diagnostic-unapproved", "image_built": False,
                       "private_mode_approved": False, "release_lock_sha256": "c" * 64,
                       "asset_sha256": "a" * 64, "zebrad_elf_sha256": digest,
                       "zebrad_elf_size": 3,
                       "gh_verifier_executable_sha256": "b" * 64,
                       "verified_attestation_count": 1,
                       "eligible_at_utc": "2026-09-08T00:00:00Z",
                       "checked_at_utc": "2026-09-09T00:00:00Z"}
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt))
            identities = {"schema_version": 1, "status": "incomplete-non-deployable",
                          "distribution": "debian", "release": "trixie",
                          "architecture": "x86_64", "mkosi_source": {},
                          "downloaded_metadata": {}, "required_local_inputs": [],
                          "artifact_hashes": None, "measurement_values": None,
                          "reviewed_zebra_provenance_receipt_sha256":
                          runner.sha256(receipt_path.read_bytes())}
            (root / "input-identities.json").write_text(json.dumps(identities))
            zebra = types.SimpleNamespace(load_lock=lambda: (release, "c" * 64),
                                          utc=lambda value: runner.datetime.fromisoformat(
                                              value.replace("Z", "+00:00")))
            source = types.SimpleNamespace(guest=types.SimpleNamespace(
                prepare=types.SimpleNamespace(unique_object=dict, PROFILE=root)))
            context = types.SimpleNamespace(zebra=zebra, source=source)
            lock = {"artifacts": {"zebra": {"path": "zebrad", "sha256": digest}}}
            now = runner.datetime.fromisoformat("2026-09-10T00:00:00+00:00")
            self.assertEqual(runner.checked_zebra(context, lock, root, receipt_path, now)[
                "zebrad_elf_sha256"], digest)
            identities["reviewed_zebra_provenance_receipt_sha256"] = None
            (root / "input-identities.json").write_text(json.dumps(identities))
            with self.assertRaisesRegex(ValueError, "no source-reviewed digest"):
                runner.checked_zebra(context, lock, root, receipt_path, now)
            identities["reviewed_zebra_provenance_receipt_sha256"] = runner.sha256(
                receipt_path.read_bytes())
            (root / "input-identities.json").write_text(json.dumps(identities))
            release["zebrad_elf_sha256"] = None
            with self.assertRaisesRegex(ValueError, "ineligible or incomplete"):
                runner.checked_zebra(context, lock, root, receipt_path, now)
            release["zebrad_elf_sha256"] = digest
            receipt["verified_attestation_count"] = 0
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "differs from source-reviewed bytes"):
                runner.checked_zebra(context, lock, root, receipt_path, now)
            identities["reviewed_zebra_provenance_receipt_sha256"] = runner.sha256(
                receipt_path.read_bytes())
            (root / "input-identities.json").write_text(json.dumps(identities))
            with self.assertRaisesRegex(ValueError, "staging consistency receipt"):
                runner.checked_zebra(context, lock, root, receipt_path, now)

    def test_post_build_inspector_binds_split_uki_cpio_signature_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            stage = workspace / "stage"
            output = stage / "output"
            output.mkdir(parents=True)
            self.output_fixture(output)
            cpio = b"audited-cpio"
            (output / "initrd.cpio.zst").write_bytes(cpio)
            (output / "zrpc-gcp.initrd").write_bytes(cpio + b"appended-modules")
            checked = ("zrpc-gcp.raw", "zrpc-gcp.efi", "zrpc-gcp.vmlinuz",
                       "zrpc-gcp.initrd")

            def rewrite_sums():
                (output / "zrpc-gcp.SHA256SUMS").write_text("".join(
                    f"{runner.sha256((output / name).read_bytes())} *{name}\n"
                    for name in checked))

            rewrite_sums()
            (stage / "artifacts").mkdir()
            kernel_name = "linux-image-reviewed-kernel"
            (stage / "artifacts/package_manifest").write_text(json.dumps([
                {"name": kernel_name, "sha256": "a" * 64},
                {"name": "kmod", "sha256": "b" * 64},
                {"name": "libkmod2", "sha256": "c" * 64},
            ]))
            certificate = b"test certificate"
            (stage / "artifacts/secure_boot_certificate").write_bytes(certificate)
            audit = stage / "mkosi.images/initrd/audit-initrd.py"
            audit.parent.mkdir(parents=True)
            audit.write_bytes(b"audit")
            rust = workspace / "rust"
            (rust / "artifacts").mkdir(parents=True)
            (rust / "artifacts/zrpc-uki-digest").write_bytes(b"verified rust binary")
            (rust / "manifest.json").write_text(json.dumps({
                "artifact_sha256": {"zrpc-uki-digest": runner.sha256(b"verified rust binary")}}))
            metadata = workspace / "metadata"
            archives = workspace / "builder-archives"
            metadata.mkdir()
            archives.mkdir()
            files = runner.checked_outputs(output)
            package_report = {"root_package_count": 104, "initrd_package_count": 72,
                              "root_manifest_sha256": files["zrpc-gcp.manifest"][1],
                              "initrd_manifest_sha256": files["initrd.manifest"][1]}
            esp = {"uki_sha256": files["zrpc-gcp.efi"][1], "uki_sections": {
                ".linux": {"sha256": files["zrpc-gcp.vmlinuz"][1]},
                ".initrd": {"sha256": files["zrpc-gcp.initrd"][1]}}}
            verity_report = {"status": "verity", "root_partition_guid": "root-guid"}
            rootfs_report = {"status": "diagnostic-rootfs-test-only",
                             "raw_disk_sha256": files["zrpc-gcp.raw"][1],
                             "raw_disk_bytes": files["zrpc-gcp.raw"][0],
                             "root_partition_guid": "root-guid",
                             "reader_executable_matches_signed_package": True,
                             "private_mode_approved": False}
            rootfs_inspect = mock.Mock(return_value=rootfs_report)
            source = types.SimpleNamespace(
                guest=types.SimpleNamespace(prepare=types.SimpleNamespace(
                    unique_object=dict, KERNEL_PACKAGE=kernel_name)),
                audit_cpio=lambda *_: {"cpio_sha256": files["initrd.cpio.zst"][1],
                                       "cpio_size": files["initrd.cpio.zst"][0]})

            def stage_sbverify(_archives, destination):
                destination.mkdir()
                return {"status": "diagnostic-sbverify-objects-staged-unapproved"}

            def inspect_final(base_digest, base_length, _final, digest, length, kernel_archive,
                              _kernel_entry, kmod_archive, _kmod_entry,
                              libkmod_archive, _libkmod_entry, _libzstd,
                              _workspace, _source):
                self.assertEqual(kernel_archive.name, "a" * 64 + ".deb")
                self.assertEqual(kmod_archive.name, "b" * 64 + ".deb")
                self.assertEqual(libkmod_archive.name, "c" * 64 + ".deb")
                self.assertEqual(base_digest, files["initrd.cpio.zst"][1])
                self.assertEqual(base_length, files["initrd.cpio.zst"][0])
                return {"status": "diagnostic-final-initrd-unapproved",
                        "final_initrd_sha256": digest, "final_initrd_bytes": length,
                        "private_mode_approved": False}

            context = types.SimpleNamespace(
                source=source,
                packages=types.SimpleNamespace(verify=lambda *_: package_report),
                gpt=types.SimpleNamespace(inspect=lambda *_: {"status": "gpt"}),
                esp=types.SimpleNamespace(inspect=lambda *_: esp),
                verity=types.SimpleNamespace(inspect=lambda *_: verity_report),
                roothash=types.SimpleNamespace(inspect=lambda *_: {"roothash": "a" * 64}),
                rootfs=types.SimpleNamespace(STATUS="diagnostic-rootfs-test-only",
                                            inspect=rootfs_inspect),
                sbverify=types.SimpleNamespace(stage=stage_sbverify),
                final_initrd=types.SimpleNamespace(
                    STATUS="diagnostic-final-initrd-unapproved", inspect=inspect_final),
                importer=types.SimpleNamespace(GIB=1024 ** 3, MAX_IMPORT_GIB=2048),
            )
            signature = {"status": "diagnostic-supplied-signer-signature-verified-unapproved",
                         "signed_uki_checked": True,
                         "uki_sha256": esp["uki_sha256"],
                         "signer_certificate_sha256": runner.sha256(certificate),
                         "private_mode_approved": False}
            with mock.patch.object(runner.subprocess, "run", return_value=
                    types.SimpleNamespace(returncode=0, stdout=json.dumps(signature).encode())) as call:
                result = runner.inspect_outputs(context, stage, rust, metadata, archives,
                                                workspace, {}, files, {})
            self.assertEqual(call.call_args.args[0][1], "verify-signature")
            self.assertEqual(result["uki_sha256"], esp["uki_sha256"])
            self.assertTrue(result["signed_uki_checked"])
            self.assertEqual(result["raw_rootfs_audit"], rootfs_report)
            self.assertEqual(rootfs_inspect.call_args.args[0], output / "zrpc-gcp.raw")
            self.assertEqual(result["final_initrd_audit"]["final_initrd_sha256"],
                             files["zrpc-gcp.initrd"][1])
            self.assertFalse(result["gcp_import_package_size_eligible"])
            rootfs_inspect.side_effect = ValueError("raw rootfs file bytes differ")
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError(
                    "signature must not run on altered raw rootfs")):
                with self.assertRaisesRegex(ValueError, "raw rootfs file bytes differ"):
                    runner.inspect_outputs(context, stage, rust, metadata, archives,
                                           workspace, {}, files, {})
            rootfs_inspect.side_effect = None
            (output / "zrpc-gcp.initrd").write_bytes(b"unreviewed-prefix" + cpio)
            rewrite_sums()
            esp["uki_sections"][".initrd"]["sha256"] = runner.sha256(
                (output / "zrpc-gcp.initrd").read_bytes())
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError(
                    "signature must not run on unreviewed initrd")):
                with self.assertRaisesRegex(ValueError, "unreviewed prefix"):
                    runner.inspect_outputs(context, stage, rust, metadata, archives,
                                           workspace, {}, runner.checked_outputs(output), {})

    def test_missing_key_blocks_before_mkosi(self):
        with self.assertRaisesRegex(ValueError, "private mount"):
            runner.checked_signing_key(Path("/nonexistent/certificate"),
                                       Path("/run/zrpc-build-signing/secure-boot.key"))

    def test_stage_cannot_overlap_a_reviewed_input_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_root = root / ".codex-tmp"
            inputs = build_root / "inputs"
            inputs.mkdir(parents=True)
            lock = inputs / "inputs.lock.json"
            lock.write_text("{}")
            receipt = inputs / "receipt.json"
            receipt.write_text("{}")
            with mock.patch.object(runner, "ROOT", root), mock.patch.object(
                    runner.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(
                    runner, "source_context", side_effect=AssertionError(
                        "source must not load for overlapping stage")):
                with self.assertRaisesRegex(ValueError, "disjoint"):
                    runner.build(lock, inputs, receipt, inputs, "a" * 40,
                                 inputs / "stage", inputs, inputs, root,
                                 "net:[1]", "mnt:[2]")

    def test_main_fail_closed_without_isolated_python(self):
        with mock.patch.object(runner, "sys", types.SimpleNamespace(
                flags=types.SimpleNamespace(isolated=0))):
            with mock.patch("builtins.print") as printed:
                self.assertEqual(runner.main([]), 1)
        report = json.loads(printed.call_args.args[0])
        self.assertFalse(report["image_built"])
        self.assertFalse(report["private_mode_approved"])


if __name__ == "__main__":
    unittest.main()
