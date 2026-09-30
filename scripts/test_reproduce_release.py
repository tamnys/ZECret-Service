"""Local regression tests for the unsigned guest executable set."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "reproduce_release", ROOT / "scripts/reproduce-release.py"
)
reproduce_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reproduce_release)


class GuestArtifactTests(unittest.TestCase):
    def test_current_workspace_binaries_are_covered(self):
        reproduce_release.check_project_artifacts(ROOT)
        reproduce_release.check_payment_helper(ROOT)

    def test_payment_helper_must_keep_its_separate_pinned_graph(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("CODEX_TMP_DIR")) as temporary:
            helper = Path(temporary) / "tools/payment-crypto"
            (helper / "src").mkdir(parents=True)
            for relative in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
                (helper / relative).write_bytes((ROOT / "tools/payment-crypto" / relative).read_bytes())
            manifest = helper / "Cargo.toml"
            manifest.write_text(manifest.read_text().replace(
                'blind-rsa-signatures = "=0.17.2"',
                'blind-rsa-signatures = "*"'))
            with self.assertRaisesRegex(reproduce_release.Refusal, "payment helper differs"):
                reproduce_release.check_payment_helper(Path(temporary))

    def test_omitting_a_non_guest_binary_fails(self):
        artifacts = tuple(artifact for artifact in reproduce_release.ARTIFACTS
                          if artifact[1] != "zrpc-uki-digest")
        with mock.patch.object(reproduce_release, "ARTIFACTS", artifacts):
            with self.assertRaisesRegex(reproduce_release.Refusal,
                                        "project Rust binary inventory differs"):
                reproduce_release.check_project_artifacts(ROOT)

    def test_current_guest_profile_is_covered(self):
        reproduce_release.check_guest_artifacts(ROOT)

    def test_omitting_any_staged_project_executable_fails(self):
        for name in (
            "zrpc-node-wrapper",
            "zrpc-gcp-quote-broker",
            "zrpc-gcp-guard",
            "zrpc-gcp-disk-id",
            "zrpc-gcp-cookie",
            "zrpc-gcp-early-init",
        ):
            with self.subTest(name=name):
                artifacts = tuple(
                    artifact for artifact in reproduce_release.ARTIFACTS
                    if artifact[1] != name
                )
                with mock.patch.object(reproduce_release, "ARTIFACTS", artifacts):
                    with self.assertRaisesRegex(
                        reproduce_release.Refusal,
                        "GCP guest executable missing from double build",
                    ):
                        reproduce_release.check_guest_artifacts(ROOT)

    def test_reproduction_refuses_a_script_outside_the_selected_commit(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("CODEX_TMP_DIR")) as temporary:
            source = Path(temporary) / "source"
            script = source / "scripts/reproduce-release.py"
            script.parent.mkdir(parents=True)
            original = (ROOT / "scripts/reproduce-release.py").read_bytes()
            script.write_bytes(original)
            invoking_sha256 = reproduce_release.digest(script)
            manifest = {}
            reproduce_release.require_source_script(
                source, invoking_sha256, manifest
            )
            self.assertTrue(manifest["script_matches_source"])

            script.write_bytes(original + b"\n# changed build rules\n")
            manifest = {}
            with self.assertRaisesRegex(
                reproduce_release.Refusal, "differs from selected commit"
            ):
                reproduce_release.require_source_script(
                    source, invoking_sha256, manifest
                )
            self.assertFalse(manifest["script_matches_source"])
            self.assertNotEqual(
                manifest["script_in_source_sha256"], invoking_sha256
            )


if __name__ == "__main__":
    unittest.main()
