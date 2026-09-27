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
    def test_current_guest_profile_is_covered(self):
        reproduce_release.check_guest_artifacts(ROOT)

    def test_omitting_any_staged_project_executable_fails(self):
        for name in (
            "zrpc-node-wrapper",
            "zrpc-gcp-quote-broker",
            "zrpc-gcp-guard",
            "zrpc-gcp-cookie",
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
