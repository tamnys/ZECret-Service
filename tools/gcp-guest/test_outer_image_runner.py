"""Focused fail-closed checks for the source-bound production disk runner."""

import importlib.util
import io
import json
from pathlib import Path
import sys
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
    def test_signed_kernel_mutation_changes_only_one_pinned_payload_byte(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            kernel = b"unique-kernel-payload"
            uki = b"MZ-test-prefix" + kernel + b"-signature-trailer"
            (output / "zrpc-gcp.efi").write_bytes(uki)
            (output / "zrpc-gcp.vmlinuz").write_bytes(kernel)
            files = {
                "zrpc-gcp.efi": (len(uki), runner.sha256(uki)),
                "zrpc-gcp.vmlinuz": (len(kernel), runner.sha256(kernel)),
            }
            destination = root / "changed.efi"
            digest, offset = runner.changed_kernel_uki(output, files, destination)
            changed = destination.read_bytes()
            self.assertEqual(digest, runner.sha256(changed))
            self.assertEqual(offset, uki.index(kernel) + len(kernel) // 2)
            self.assertEqual([index for index, (before, after) in
                              enumerate(zip(uki, changed)) if before != after], [offset])
            self.assertNotEqual(digest, files["zrpc-gcp.efi"][1])
            with self.assertRaises(FileExistsError):
                runner.changed_kernel_uki(output, files, destination)
            (output / "zrpc-gcp.efi").write_bytes(uki + kernel)
            files["zrpc-gcp.efi"] = (len(uki + kernel), runner.sha256(uki + kernel))
            with self.assertRaisesRegex(ValueError, "no unique exact split kernel"):
                runner.changed_kernel_uki(output, files, root / "duplicate.efi")

    def test_signed_diagnostic_requires_actual_verifier_rejection_of_changed_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            output = stage / "output"
            artifacts = stage / "artifacts"
            output.mkdir(parents=True)
            artifacts.mkdir()
            kernel = b"exact-split-kernel"
            uki = b"MZ-header" + kernel + b"-signature"
            (output / "zrpc-gcp.efi").write_bytes(uki)
            (output / "zrpc-gcp.vmlinuz").write_bytes(kernel)
            certificate = b"test-certificate"
            (artifacts / "secure_boot_certificate").write_bytes(certificate)
            bundle = root / "bundle"
            (bundle / "artifacts").mkdir(parents=True)
            verifier = b"test-verifier"
            (bundle / "artifacts/zrpc-uki-digest").write_bytes(verifier)
            (bundle / "manifest.json").write_text(json.dumps({
                "artifact_sha256": {"zrpc-uki-digest": runner.sha256(verifier)}}))
            files = {"zrpc-gcp.efi": (len(uki), runner.sha256(uki)),
                     "zrpc-gcp.vmlinuz": (len(kernel), runner.sha256(kernel))}
            signature = {
                "status": "diagnostic-supplied-signer-signature-verified-unapproved",
                "signed_uki_checked": True, "uki_sha256": runner.sha256(uki),
                "signer_certificate_sha256": runner.sha256(certificate),
                "private_mode_approved": False}
            rejection = {
                "schema_version": 2, "status": "blocked",
                "reason": "UKI Authenticode signature rejected by reviewed sbverify binary",
                "signed_uki_checked": False, "release_approved": False,
                "private_mode_approved": False}
            context = types.SimpleNamespace(
                source=types.SimpleNamespace(guest=types.SimpleNamespace(
                    prepare=types.SimpleNamespace(unique_object=dict))),
                sbverify=types.SimpleNamespace(stage=lambda *_: {
                    "status": "diagnostic-sbverify-objects-staged-unapproved"}))

            calls = []
            def verified_run(command, **_):
                calls.append(command)
                if len(calls) == 1:
                    return types.SimpleNamespace(returncode=0, stdout=json.dumps(signature).encode(),
                                                 stderr=b"")
                changed = Path(command[2]).read_bytes()
                self.assertEqual(command[3], runner.sha256(changed))
                self.assertEqual(len(changed), len(uki))
                self.assertEqual(sum(a != b for a, b in zip(uki, changed)), 1)
                return types.SimpleNamespace(returncode=1, stdout=json.dumps(rejection).encode(),
                                             stderr=b"")

            with (mock.patch.object(runner, "source_context", return_value=context),
                  mock.patch.object(runner, "checked_outputs", return_value=files),
                  mock.patch.object(runner, "require_unchanged_outputs"),
                  mock.patch.object(runner.subprocess, "run", side_effect=verified_run)):
                report = runner.diagnostic_verify_uki(
                    stage, root, root, bundle, "a" * 40, runner.sha256(uki))
            self.assertEqual(len(calls), 2)
            self.assertTrue(report["signed_kernel_byte_mutation_rejected"])
            self.assertFalse(report["private_mode_approved"])

            calls.clear()
            with (mock.patch.object(runner, "source_context", return_value=context),
                  mock.patch.object(runner, "checked_outputs", return_value=files),
                  mock.patch.object(runner.subprocess, "run", side_effect=[
                      types.SimpleNamespace(returncode=0,
                                            stdout=json.dumps(signature).encode(), stderr=b""),
                      types.SimpleNamespace(returncode=0,
                                            stdout=json.dumps(signature).encode(), stderr=b"")])):
                with self.assertRaisesRegex(ValueError, "not rejected by pinned sbverify"):
                    runner.diagnostic_verify_uki(
                        stage, root, root, bundle, "a" * 40, runner.sha256(uki))

    def test_sfdisk_rejects_ambient_loader_object_before_disk_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            disk = root / "disk.raw"
            disk.write_bytes(b"unchanged")
            runtime = (b"\x7fELFprogram", b"\x7fELFloader", (b"\x7fELFlibrary",))
            ambient = types.SimpleNamespace(
                returncode=0, stderr="",
                stdout="\t/proc/self/fd/99 (0x1000)\n")
            with mock.patch.object(runner.subprocess, "run", return_value=ambient) as invoked:
                with self.assertRaisesRegex(ValueError, "ambient objects"):
                    runner.signed_sfdisk_runtime(runtime, root, disk)
            self.assertEqual(invoked.call_count, 1)
            self.assertEqual(disk.read_bytes(), b"unchanged")

    def test_import_sfdisk_is_reconstructed_from_signed_package(self):
        with mock.patch.object(sys, "path", [str(HERE), *sys.path]):
            import debian_snapshot
            import verify_builder_closure as closure

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / "metadata"
            archives = root / "archives"
            metadata.mkdir()
            archives.mkdir()
            executable = b"\x7fELFsynthetic-sfdisk"
            installed = root / "sfdisk"
            installed.write_bytes(executable)
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:xz") as members:
                member = tarfile.TarInfo("./usr/sbin/sfdisk")
                member.mode = 0o755
                member.size = len(executable)
                members.addfile(member, io.BytesIO(executable))
            package = bytearray(b"!<arch>\n")
            for name, payload in (("debian-binary/", b"2.0\n"),
                                  ("data.tar.xz/", data.getvalue())):
                package.extend(
                    f"{name:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8}{len(payload):<10}`\n".encode())
                package.extend(payload)
                if len(payload) % 2:
                    package.extend(b"\n")
            package_hash = runner.sha256(package)
            (archives / (package_hash + ".deb")).write_bytes(package)
            entry = {"name": "fdisk", "version": "synthetic", "architecture": "amd64",
                     "filename": "pool/main/f/fdisk.deb", "size": len(package),
                     "sha256": package_hash}
            lock = root / "builder.json"
            runtime_entries = [{**entry, "name": name}
                               for name in {"libc6", *(package for _, package in
                                              runner.SFDISK_ELF_PROVIDERS)}]
            lock.write_text(json.dumps({"snapshot": "https://example.invalid/snapshot/",
                                        "packages": [entry, *runtime_entries]}))
            guest = types.SimpleNamespace(
                SNAPSHOT="https://example.invalid/snapshot/",
                INRELEASE_SHA256="a" * 64, SIGNED_RELEASE_EPOCH=1,
                PACKAGES_SHA256="b" * 64, PACKAGES_SIZE=4,
                prepare=types.SimpleNamespace(unique_object=dict))
            context = types.SimpleNamespace(
                source=types.SimpleNamespace(guest=guest),
                import_disk=types.SimpleNamespace(
                    SFDISK_PACKAGE_SHA256=package_hash,
                    SFDISK_SHA256=runner.sha256(executable)))
            records = {("fdisk", "synthetic", "amd64"):
                       {"Filename": entry["filename"], "Size": str(entry["size"]),
                        "SHA256": entry["sha256"]}}
            records.update({(candidate["name"], "synthetic", "amd64"):
                            {"Filename": entry["filename"], "Size": str(entry["size"]),
                             "SHA256": entry["sha256"]}
                            for candidate in runtime_entries})
            with (mock.patch.object(closure, "LOCK", lock),
                  mock.patch.object(closure, "LOCK_BYTES", lock.stat().st_size),
                  mock.patch.object(closure, "LOCK_SHA256", runner.sha256(lock.read_bytes())),
                  mock.patch.object(debian_snapshot, "authenticated_index_bytes",
                                    return_value=(1, ("b" * 64, 4), b"test")),
                  mock.patch.object(debian_snapshot, "package_records", return_value=records),
                  mock.patch.object(closure, "package_elf", return_value=b"\x7fELFsynthetic-library")):
                checked, runtime = runner.checked_sfdisk_package(
                    context, metadata, archives, installed)
                self.assertTrue(checked["sfdisk_archive_membership_rechecked"])
                self.assertFalse(checked["sfdisk_dynamic_runtime_authenticated"])
                self.assertEqual(runtime[0], executable)
                self.assertEqual(len(runtime[2]), len(runner.SFDISK_ELF_PROVIDERS))
                installed.write_bytes(b"\x7fELFsubstituted")
                with self.assertRaisesRegex(ValueError, "differs from signed fdisk package"):
                    runner.checked_sfdisk_package(context, metadata, archives, installed)
                installed.write_bytes(executable)
                (archives / (package_hash + ".deb")).write_bytes(package + b"changed")
                with self.assertRaisesRegex(ValueError, "differs from signed index"):
                    runner.checked_sfdisk_package(context, metadata, archives, installed)

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
            verity_report = {"status": "verity", "root_partition_guid": "root-guid",
                             "one_byte_root_change_rejected": True}
            rootfs_report = {"status": "diagnostic-rootfs-test-only",
                             "raw_disk_sha256": files["zrpc-gcp.raw"][1],
                             "raw_disk_bytes": files["zrpc-gcp.raw"][0],
                             "root_partition_guid": "root-guid",
                             "reader_executable_matches_signed_package": True,
                             "forbidden_surfaces_checked": True,
                             "raw_root_inventory_entries": 1,
                             "authenticated_package_components_checked": {
                                 "regular": 1, "directory": 1,
                                 "symlink": 0, "removed": 1},
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
            rootfs_report["forbidden_surfaces_checked"] = False
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError(
                    "signature must not run without forbidden-surface audit")):
                with self.assertRaisesRegex(ValueError, "raw rootfs workload inspection"):
                    runner.inspect_outputs(context, stage, rust, metadata, archives,
                                           workspace, {}, files, {})
            rootfs_report["forbidden_surfaces_checked"] = True
            rootfs_report["authenticated_package_components_checked"]["regular"] = 0
            with mock.patch.object(runner.subprocess, "run", side_effect=AssertionError(
                    "signature must not run without package identity audit")):
                with self.assertRaisesRegex(ValueError, "raw rootfs workload inspection"):
                    runner.inspect_outputs(context, stage, rust, metadata, archives,
                                           workspace, {}, files, {})
            rootfs_report["authenticated_package_components_checked"]["regular"] = 1
            verity_report["one_byte_root_change_rejected"] = False
            with self.assertRaisesRegex(ValueError, "signed verity negative check"):
                runner.inspect_outputs(context, stage, rust, metadata, archives,
                                       workspace, {}, files, {})
            verity_report["one_byte_root_change_rejected"] = True
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
