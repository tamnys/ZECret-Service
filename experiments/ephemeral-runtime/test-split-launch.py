"""Synthetic local launch-bundle tests; no Phala resource or acceptance path."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("prepare-split-launch.py")
spec = importlib.util.spec_from_file_location("phala_split_launch", SCRIPT)
split = importlib.util.module_from_spec(spec)
spec.loader.exec_module(split)
IMAGE = "example.invalid/synthetic@sha256:" + "0" * 64
RUNTIME = {key: 1 for key in split.RUNTIME_KEYS}
SYS_BYTES = b'{"vm_config":"{}","kms_urls":["https://kms.example.invalid"]}\n'


class SplitLaunchTests(unittest.TestCase):
    def setUp(self) -> None:
        split.SCRATCH.mkdir(mode=0o700, exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=split.SCRATCH)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.sys_config = self.root / "synthetic-sys-config.json"
        self.sys_config.write_bytes(SYS_BYTES)
        self.output = self.root / "bundle"

    def prepare(self, **changes):
        values = {
            "image": IMAGE,
            "name": "SYNTHETIC_ONLY",
            "kms_identity": "01",
            "runtime": RUNTIME,
            "sys_config": self.sys_config,
            "output": self.output,
        }
        values.update(changes)
        return split.prepare(**values)

    def test_bundle_binds_exact_bytes_without_claiming_acceptance(self) -> None:
        manifest = self.prepare()
        launch = (self.output / "app-compose.json").read_bytes()
        system = (self.output / "sys-config.json").read_bytes()
        compose = (self.output / "docker-compose.json").read_bytes()
        self.assertEqual(system, SYS_BYTES)
        self.assertEqual(manifest["launch_config_sha256"], hashlib.sha256(launch).hexdigest())
        self.assertEqual(manifest["sys_config_sha256"], hashlib.sha256(SYS_BYTES).hexdigest())
        self.assertEqual(manifest["docker_compose_sha256"], hashlib.sha256(compose).hexdigest())
        self.assertEqual(json.loads(launch)["docker_compose_file"], compose.decode().rstrip("\n"))
        fixture = SCRIPT.with_name("fixtures") / "split-compose-synthetic.json"
        self.assertEqual(json.loads(compose), json.loads(fixture.read_bytes()))
        self.assertEqual(manifest["status"], "local_source_only_unapproved")
        self.assertIs(manifest["application_image_reviewed"], False)
        self.assertIs(manifest["guest_image_built"], False)
        self.assertIs(manifest["phala_admission_verified"], False)
        self.assertIs(manifest["private_accepted"], False)
        self.assertEqual(manifest["cloud_resources_created_by_this_tool"], 0)
        self.assertEqual(json.loads((self.output / "bundle-manifest.json").read_bytes()), manifest)
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

        second = self.root / "second"
        self.prepare(output=second)
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())

    def test_refuses_unreviewed_image_and_runtime_values(self) -> None:
        for image in ("example.invalid/synthetic:latest", IMAGE[:-1] + "X"):
            with self.subTest(image=image), self.assertRaises(ValueError):
                self.prepare(image=image)
            self.assertFalse(self.output.exists())
        for runtime in ({**RUNTIME, "max_quotes": 0},
                        {**RUNTIME, "max_quotes": True},
                        {**RUNTIME, "quote_startup_timeout_secs": 1}):
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                self.prepare(runtime=runtime)
            self.assertFalse(self.output.exists())

    def test_refuses_unsafe_or_ambiguous_system_configuration(self) -> None:
        for payload in (b'{"vm_config":"{}","vm_config":"{}"}',
                        b'{"vm_config":"[]"}',
                        b'{"vm_config":"{}","unexpected":NaN}',
                        b'{"vm_config":"{}","docker_registry":"unreviewed"}'):
            with self.subTest(payload=payload):
                self.sys_config.write_bytes(payload)
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertFalse(self.output.exists())
        self.sys_config.write_bytes(SYS_BYTES)
        symlink = self.root / "linked-system.json"
        symlink.symlink_to(self.sys_config)
        with self.assertRaises(ValueError):
            self.prepare(sys_config=symlink)
        fifo = self.root / "nonregular-system.json"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            self.prepare(sys_config=fifo)

    def test_refuses_existing_output_and_non_scratch_destination(self) -> None:
        self.prepare()
        with self.assertRaises(ValueError):
            self.prepare()
        with self.assertRaises(ValueError):
            self.prepare(output=split.ROOT / "records" / "bundle")

    def test_cli_requires_every_input(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT), "--image-ref", IMAGE],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())
        args = [sys.executable, str(SCRIPT), "--image-ref", IMAGE,
                "--name", "SYNTHETIC_ONLY", "--key-provider-id", "01",
                "--sys-config", str(self.sys_config), "--output-dir", str(self.output)]
        for key in split.RUNTIME_KEYS:
            args.extend(["--" + key.replace("_", "-"), "1"])
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("private acceptance remain blocked", result.stdout)
        self.assertTrue((self.output / "bundle-manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
