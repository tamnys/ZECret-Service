"""Tamper and architecture checks for diagnostic guest Rust inputs."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "export_rust_inputs", Path(__file__).with_name("export_rust_inputs.py")
)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


def git(args):
    return subprocess.check_output(["git", *args], cwd=ROOT).strip().decode()


def elf(name, machine=b"\x3e\x00"):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    data[16:18] = b"\x03\x00"
    data[18:20] = machine
    return bytes(data) + name.encode()


class GuestRustInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name)
        self.revision = git(["rev-parse", "HEAD"])
        self.contents = {name: elf(name) for name in exporter.EXPECTED_ALL_BINARIES}
        self.write_bundle()

    def write_bundle(self):
        digests = {}
        for name, data in self.contents.items():
            digests[name] = hashlib.sha256(data).hexdigest()
            for parent in (self.bundle / "artifacts",
                           self.bundle / "build-a/target/release",
                           self.bundle / "build-b/target/release"):
                parent.mkdir(parents=True, exist_ok=True)
                (parent / name).write_bytes(data)
        self.manifest = {
            "artifact_kind": "unsigned_native_scaffold",
            "compiled_artifacts_are_synthetic": False,
            "source_commit": self.revision,
            "source_tree": git(["show", "-s", "--format=%T", self.revision]),
            "source_archive_sha256": hashlib.sha256(b"synthetic archive").hexdigest(),
            "tools": {"rustc": {"version": "rustc 1.94.1\nhost: x86_64-unknown-linux-gnu\n"}},
            "script_sha256": hashlib.sha256(exporter.git_bytes(
                self.revision, "scripts/reproduce-release.py")).hexdigest(),
            "script_in_source_sha256": hashlib.sha256(exporter.git_bytes(
                self.revision, "scripts/reproduce-release.py")).hexdigest(),
            "script_matches_source": True,
            "input_sha256": {path: hashlib.sha256(exporter.git_bytes(
                self.revision, path)).hexdigest() for path in (
                    "Cargo.lock", "rust-toolchain.toml")},
            "selected_binaries": [
                {"package": "zrpc-cli" if name == "zrpc" else "zrpc-server",
                 "name": name} for name in sorted(digests)
            ],
            "artifact_sha256": digests,
            "builds": [{"directory": label, "exit_code": 0,
                        "artifact_sha256": digests} for label in ("build-a", "build-b")],
            "approved_release": False,
            "private_accepted": False,
            "deployment_enabled": False,
            "published": False,
            "signed": False,
            "reproducible": True,
        }
        (self.bundle / "source.tar").write_bytes(b"synthetic archive")
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))
        (self.bundle / "SHA256SUMS").write_text("".join(
            f"{digests[name]}  artifacts/{name}\n" for name in sorted(digests)
        ))

    def test_matching_x86_64_binaries_yield_partial_nonapproving_role_map(self):
        result = exporter.inspect(self.bundle, self.revision)
        self.assertEqual(set(result["artifacts"]), set(exporter.EXPECTED_GUEST_BINARIES))
        self.assertEqual(result["artifacts"]["early_init"]["path"], "early_init")
        self.assertFalse(result["image_built"])
        self.assertFalse(result["private_mode_approved"])

    def test_changed_copy_is_rejected(self):
        (self.bundle / "build-b/target/release/zrpc-gcp-guard").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "binary differs"):
            exporter.inspect(self.bundle, self.revision)

    def test_matching_wrong_machine_is_rejected(self):
        self.contents["zrpc-gcp-early-init"] = elf("zrpc-gcp-early-init", b"\xb7\x00")
        self.write_bundle()
        with self.assertRaisesRegex(ValueError, "not an x86_64 ELF"):
            exporter.inspect(self.bundle, self.revision)

    def test_approval_flag_is_rejected(self):
        self.manifest["private_accepted"] = True
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "not an unsigned matched build"):
            exporter.inspect(self.bundle, self.revision)

    def test_non_x86_64_builder_receipt_is_rejected(self):
        self.manifest["tools"]["rustc"]["version"] = "host: aarch64-unknown-linux-gnu\n"
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "did not use the x86_64 Rust host"):
            exporter.inspect(self.bundle, self.revision)


if __name__ == "__main__":
    unittest.main()
