"""The production input assembler remains blocked until source review fills pins."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import assemble_production_inputs as assembler


def digest(data):
    return hashlib.sha256(data).hexdigest()


class GitSelected:
    """Test-only reader for exact selected Git bytes."""

    def __init__(self, report=None):
        self.report = report

    def output(self, arguments):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("GIT_")}
        environment["GIT_NO_REPLACE_OBJECTS"] = "1"
        return subprocess.check_output(
            ["git", "-c", f"safe.directory={assembler.ROOT}", *arguments],
            cwd=assembler.ROOT, env=environment)


class ReviewedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selected = GitSelected()
        cls.revision = cls.selected.output(["rev-parse", "HEAD"]).decode().strip()

    def test_current_selected_commit_has_no_reviewed_input_pins(self):
        assembler.exact_checkout(types.SimpleNamespace(selected=self.selected),
                                 self.revision)
        with self.assertRaisesRegex(ValueError, "not source-reviewed"):
            assembler.reviewed_hashes(self.selected, self.revision)

    def test_assembler_and_transitive_verifier_changes_are_rejected(self):
        context = types.SimpleNamespace(selected=self.selected)
        original = assembler.outer.regular_bytes
        producer = assembler.ROOT / assembler.SCRIPT
        with mock.patch.object(assembler.outer, "regular_bytes",
                               side_effect=lambda path: b"changed producer" if path == producer
                               else original(path)):
            with self.assertRaisesRegex(ValueError, "assembler producer differs"):
                assembler.exact_checkout(context, self.revision)

        # outer.source_context calls this binder before loading verifier code.
        import prepare_initrd_basetree_profile as binder
        original_source = binder.source_file
        with mock.patch.object(binder, "source_file",
                               side_effect=lambda path: b"changed verifier"
                               if path.name == "debian_snapshot.py"
                               else original_source(path)):
            with self.assertRaisesRegex(ValueError, "debian_snapshot.py"):
                binder.verified_source_closure(
                    self.revision, selected_output=self.selected.output)

    def test_selected_source_bytes_and_digest_are_both_required(self):
        path = assembler.ROOT / "tools/gcp-guest/prepare.py"
        selected = assembler.selected_bytes(self.selected, self.revision,
                                            "tools/gcp-guest/prepare.py")
        self.assertEqual(assembler.reviewed_file(
            self.selected, self.revision, path, digest(selected),
            "source fixture"), selected)
        with self.assertRaisesRegex(ValueError, "source-reviewed identity"):
            assembler.reviewed_file(self.selected, self.revision, path, "0" * 64,
                                    "source fixture")
        with self.assertRaises(OSError):
            assembler.reviewed_file(self.selected, self.revision,
                                    assembler.ROOT / "missing-boot-policy.json",
                                    digest(selected), "boot policy")

    def test_pins_reject_missing_or_caller_written_values(self):
        original = json.loads(assembler.selected_bytes(
            self.selected, self.revision, assembler.IDENTITIES))
        for hashes in (None, {"secure_boot_certificate": "1" * 64},
                       {name: "0" * 64 for name in assembler.REVIEWED_HASHES}
                       | {"extra": "0" * 64}):
            candidate = {**original, "artifact_hashes": hashes}
            with mock.patch.object(assembler, "selected_bytes",
                                   return_value=json.dumps(candidate).encode()):
                with self.assertRaisesRegex(ValueError, "not source-reviewed"):
                    assembler.reviewed_hashes(self.selected, self.revision)

    def test_runtime_requires_exact_reviewed_fields(self):
        values = {key: 1 for key in assembler.RUNTIME_FIELDS}
        self.assertEqual(assembler.runtime_policy(json.dumps(values).encode()), values)
        for invalid in ({**values, "max_quotes": True},
                        {**values, "max_quotes": 0},
                        {**values, "extra": 1},
                        {key: 1 for key in values if key != "max_quotes"}):
            with self.assertRaisesRegex(ValueError, "runtime fields"):
                assembler.runtime_policy(json.dumps(invalid).encode())
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            assembler.runtime_policy(b'{"listen_port":1,"listen_port":2}')

    def test_missing_pins_and_nonworkspace_output_create_no_artifacts(self):
        with tempfile.TemporaryDirectory(dir=assembler.ROOT) as directory:
            source = Path(directory) / "source"
            source.mkdir()
            output = Path(directory) / "result"
            args = dict(revision=self.revision, rust_bundle=source,
                        zebra_stage=source, guest_metadata=source,
                        guest_archives=source, certificate=source / "cert",
                        boot_policy=source / "boot", runtime_json=source / "runtime",
                        output=output)
            context = types.SimpleNamespace(
                selected=self.selected,
                source=types.SimpleNamespace(
                    guest=types.SimpleNamespace(prepare=object()),
                    rust_inputs=object()))
            with mock.patch.object(assembler.outer, "source_context",
                                   return_value=context):
                with self.assertRaisesRegex(ValueError, "not source-reviewed"):
                    assembler.assemble(**args)
            self.assertFalse(output.exists())
            with mock.patch.object(assembler.outer, "source_context",
                                   side_effect=AssertionError("builder must not run")):
                with self.assertRaisesRegex(ValueError, "real /workspace volume"):
                    assembler.assemble(**{**args, "output": Path("/tmp/assembler-out")})

    def test_preexisting_output_and_zebra_failure_leave_no_success_report(self):
        runtime = {key: 1 for key in assembler.RUNTIME_FIELDS}
        with tempfile.TemporaryDirectory(dir=assembler.ROOT) as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            output = root / "output"
            output.mkdir()
            common = dict(revision=self.revision, rust_bundle=source,
                          zebra_stage=source, guest_metadata=source,
                          guest_archives=source, certificate=source / "cert",
                          boot_policy=source / "boot",
                          runtime_json=source / "runtime", output=output)
            with self.assertRaisesRegex(ValueError, "fresh output"):
                assembler.assemble(**common)
            self.assertFalse((output / "assembly-report.json").exists())
            output.rmdir()
            selected = GitSelected(report={"artifacts": {}})
            guest = types.SimpleNamespace(prepare=object())
            context = types.SimpleNamespace(selected=selected,
                                            source=types.SimpleNamespace(
                                                guest=guest, rust_inputs=object()))
            with (mock.patch.object(assembler.outer, "source_context",
                                    return_value=context),
                  mock.patch.object(assembler, "reviewed_hashes",
                                    return_value={key: "0" * 64 for key in
                                                  assembler.REVIEWED_HASHES}),
                  mock.patch.object(assembler, "reviewed_file",
                                    side_effect=[b"cert", b"boot",
                                                 json.dumps(runtime).encode()]),
                  mock.patch.object(assembler.outer, "checked_zebra",
                                    side_effect=ValueError("Zebra ELF or receipt absent"))):
                with self.assertRaisesRegex(ValueError, "Zebra ELF or receipt absent"):
                    assembler.assemble(**common)
            self.assertFalse(output.exists())

    def test_changed_copied_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=assembler.ROOT) as directory:
            root = Path(directory)
            source = root / "source"
            target = root / "target"
            source.write_bytes(b"changed synthetic workload")
            with self.assertRaisesRegex(ValueError, "copied input differs"):
                assembler.copy_checked(source, target, digest(b"reviewed workload"))


class SyntheticAssemblyPlumbingTests(unittest.TestCase):
    def test_delegates_final_validation_and_copies_exact_roles(self):
        with tempfile.TemporaryDirectory(dir=assembler.ROOT) as directory:
            root = Path(directory)
            rust_bundle = root / "rust"
            (rust_bundle / "artifacts").mkdir(parents=True)
            zebra_stage = root / "zebra"
            zebra_stage.mkdir()
            metadata = root / "metadata"
            metadata.mkdir()
            archives = root / "archives"
            archives.mkdir()
            certificate = root / "cert"
            boot = root / "boot"
            runtime_file = root / "runtime"
            certificate.write_bytes(b"synthetic-certificate")
            boot.write_bytes(b"synthetic-boot-policy")
            runtime = {key: 1 for key in assembler.RUNTIME_FIELDS}
            runtime_file.write_text(json.dumps(runtime))
            zebra_data = b"synthetic-zebra"
            (zebra_stage / "zebrad").write_bytes(zebra_data)
            receipt = zebra_stage / "receipt.json"
            receipt.write_bytes(b"synthetic-receipt")
            inrelease = b"synthetic-inrelease"
            index = b"synthetic-index"
            (metadata / "InRelease").write_bytes(inrelease)
            (metadata / "Packages.xz").write_bytes(index)
            package = b"synthetic-package"
            (archives / (digest(package) + ".deb")).write_bytes(package)
            names = {"wrapper": "zrpc-node-wrapper", "broker": "zrpc-gcp-quote-broker",
                     "guard": "zrpc-gcp-guard", "cookie": "zrpc-gcp-cookie",
                     "early_init": "zrpc-gcp-early-init"}
            rust_roles = {}
            for role, name in names.items():
                data = ("synthetic-" + role).encode()
                (rust_bundle / "artifacts" / name).write_bytes(data)
                rust_roles[role] = {"path": role, "sha256": digest(data)}
            rust_report = {"artifacts": rust_roles,
                           "reproduction_manifest_sha256": "a" * 64}
            zebra_report = {"zebrad_elf_sha256": digest(zebra_data),
                            "zebra_release_lock_sha256": "b" * 64,
                            "reviewed_zebra_provenance_receipt_sha256":
                                digest(receipt.read_bytes())}
            package_manifest = b"synthetic-manifest"
            package_list = [{"path": "debs/" + digest(package) + ".deb",
                             "sha256": digest(package), "size": len(package)}]
            pins = {"secure_boot_certificate": digest(certificate.read_bytes()),
                    "boot_policy": digest(boot.read_bytes()),
                    "runtime_policy": digest(runtime_file.read_bytes())}
            roles = set(names) | {"zebra", "secure_boot_certificate", "boot_policy",
                                  "package_manifest", "snapshot_inrelease",
                                  "packages_index"}
            validate = mock.Mock()
            prepare = types.SimpleNamespace(
                SOURCE_COMMIT="c" * 40, KERNEL_VERSION="synthetic-kernel",
                ROLES=roles, validate_lock=validate)
            guest = types.SimpleNamespace(
                prepare=prepare, SIGNED_RELEASE_EPOCH=1,
                SNAPSHOT="synthetic-snapshot", INRELEASE_SHA256=digest(inrelease),
                PACKAGES_SHA256=digest(index),
                verify_cached_archives=lambda *_: {
                    "signed_snapshot_rechecked": True,
                    "archive_bytes_checked": True, "private_mode_approved": False},
                reviewed_manifest=lambda: (package_manifest, package_list))
            rust = types.SimpleNamespace(EXPECTED_GUEST_BINARIES=names)
            selected = GitSelected(report=rust_report)
            revision = selected.output(["rev-parse", "HEAD"]).decode().strip()
            context = types.SimpleNamespace(selected=selected,
                                            source=types.SimpleNamespace(
                                                guest=guest, rust_inputs=rust))
            output = root / "output"
            with (mock.patch.object(assembler.outer, "source_context",
                                    return_value=context),
                  mock.patch.object(assembler, "reviewed_hashes", return_value=pins),
                  mock.patch.object(assembler, "reviewed_file",
                                    side_effect=lambda _selected, _revision, path, *_:
                                        path.read_bytes()),
                  mock.patch.object(assembler.outer, "checked_zebra",
                                    return_value=zebra_report) as checked_zebra):
                report = assembler.assemble(
                    revision=revision, rust_bundle=rust_bundle,
                    zebra_stage=zebra_stage, guest_metadata=metadata,
                    guest_archives=archives, certificate=certificate,
                    boot_policy=boot, runtime_json=runtime_file, output=output)
                validate.side_effect = ValueError("final schema validation rejected")
                rejected = root / "rejected"
                with self.assertRaisesRegex(ValueError, "final schema validation rejected"):
                    assembler.assemble(
                        revision=revision, rust_bundle=rust_bundle,
                        zebra_stage=zebra_stage, guest_metadata=metadata,
                        guest_archives=archives, certificate=certificate,
                        boot_policy=boot, runtime_json=runtime_file,
                        output=rejected)
                validate.side_effect = None
                changed = root / "changed-receipt"
                calls = 0

                def mutate_receipt(*_args):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        receipt.write_bytes(b"changed receipt")
                    return zebra_report

                checked_zebra.side_effect = mutate_receipt
                with self.assertRaisesRegex(ValueError, "copied input differs"):
                    assembler.assemble(
                        revision=revision, rust_bundle=rust_bundle,
                        zebra_stage=zebra_stage, guest_metadata=metadata,
                        guest_archives=archives, certificate=certificate,
                        boot_policy=boot, runtime_json=runtime_file,
                        output=changed)
            self.assertEqual(validate.call_count, 3)
            self.assertFalse((rejected / "inputs.lock.json").exists())
            self.assertFalse((rejected / "assembly-report.json").exists())
            self.assertFalse((changed / "inputs.lock.json").exists())
            self.assertFalse((changed / "assembly-report.json").exists())
            lock, copied = validate.call_args_list[0].args
            self.assertEqual(copied, output / "inputs")
            self.assertEqual(set(lock["artifacts"]), roles)
            self.assertEqual(lock["runtime"], runtime)
            self.assertEqual(checked_zebra.call_count, 5)
            self.assertEqual(report["status"],
                             "production-inputs-staged-unbuilt-unapproved")
            self.assertFalse(report["private_mode_approved"])
            self.assertFalse(report["image_built"])
            self.assertEqual((output / "zebra-provenance.json").read_bytes(),
                             b"synthetic-receipt")


if __name__ == "__main__":
    unittest.main()
