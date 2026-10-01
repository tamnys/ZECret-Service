"""Fail-closed checks for guest image launch-profile input; all data is synthetic."""

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = Path(__file__).with_name("prepare-image-source.py")
spec = importlib.util.spec_from_file_location("guest_source_generator", GENERATOR)
guest_source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest_source)


class LaunchProfileInputTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = ROOT / ".codex-tmp"
        directory.mkdir(exist_ok=True)
        self.scratch = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name) / "synthetic-app-compose.json"
        self.sys_path = Path(self.scratch.name) / "synthetic-sys-config.json"
        self.compose = json.loads((GENERATOR.parent / "fixtures" /
                                   "split-compose-synthetic.json").read_text())
        self.profile = {
            "manifest_version": 2,
            "name": "SYNTHETIC_ONLY",
            "runner": "docker-compose",
            "storage_fs": "ext4",
            "storage_encrypted": True,
            "swap_size": 0,
            "key_provider": "kms",
            "key_provider_id": "01",
            "kms_enabled": True,
            "tproxy_enabled": True,
            "public_logs": False,
            "public_sysinfo": False,
            "public_tcbinfo": False,
            "allowed_envs": [],
            "port_policy": {
                "restrict_mode": True,
                "ports": [{"port": 8443, "pp": False}],
            },
            "docker_compose_file": json.dumps(self.compose, separators=(",", ":")),
        }

    def write(self, value: object) -> bytes:
        payload = json.dumps(value, separators=(",", ":")).encode()
        self.path.write_bytes(payload)
        return payload

    def test_exact_bytes_are_bound_without_private_acceptance(self) -> None:
        payload = self.write(self.profile)
        system_payload = b'{"vm_config":"{}","kms_urls":["https://kms.example.invalid"]}'
        self.sys_path.write_bytes(system_payload)
        self.assertEqual(
            guest_source.launch_config_digest(self.path),
            hashlib.sha256(payload).digest(),
        )
        self.assertEqual(
            guest_source.bound_digests(self.path, self.sys_path),
            (hashlib.sha256(payload).digest(), hashlib.sha256(system_payload).digest()),
        )
        self.sys_path.write_bytes(system_payload + b"\n")
        self.assertNotEqual(guest_source.sys_config_digest(self.sys_path),
                            hashlib.sha256(system_payload).digest())
        self.assertIsNone(guest_source.launch_config_digest(None))
        self.assertEqual(guest_source.bound_digests(None, None), (None, None))
        self.assertEqual(guest_source.rust_hash_option(None), "None")

    def test_unsafe_profile_fields_are_rejected_before_generation(self) -> None:
        for key, value in (
            ("runner", "bash"),
            ("storage_fs", "zfs"),
            ("storage_encrypted", False),
            ("swap_size", True),
            ("key_provider", "local"),
            ("key_provider_id", ""),
            ("kms_enabled", False),
            ("tproxy_enabled", False),
            ("docker_compose_file", ""),
            ("public_logs", True),
            ("public_sysinfo", True),
            ("public_tcbinfo", True),
            ("allowed_envs", ["SECRET"]),
            ("port_policy", {"restrict_mode": False, "ports": [{"port": 8443}]}),
            (
                "port_policy",
                {"restrict_mode": True, "ports": [{"port": 8443}, {"port": 18232}]},
            ),
            ("port_policy", {"restrict_mode": True, "ports": [{"port": 8443, "pp": True}]}),
            ("port_policy", {"restrict_mode": True, "ports": [{"port": 0}]}),
            ("port_policy", {"restrict_mode": True,
                             "ports": [{"port": 18232, "pp": False}]}),
            ("port_policy", {"restrict_mode": True,
                             "ports": [{"port": 8443, "pp": 0}]}),
            ("extra_runtime_control", True),
            ("init_script", "echo bad"),
            ("pre_launch_script", "echo bad"),
            ("bash_script", "echo bad"),
        ):
            with self.subTest(key=key):
                self.write({**self.profile, key: value})
                with self.assertRaises(ValueError):
                    guest_source.launch_config_digest(self.path)

    def test_compose_profile_rejects_indirect_and_privileged_inputs(self) -> None:
        for field, value in (
            ("build", "."),
            ("extends", {"file": "other.yaml", "service": "other"}),
            ("env_file", "private.env"),
            ("profiles", ["hidden"]),
            ("label_file", "labels.txt"),
            ("privileged", True),
            ("volumes", ["/run/docker.sock:/run/docker.sock"]),
            ("ports", ["18232:18232"]),
            ("tmpfs", ["/run/secrets"]),
            ("command", ["sh", "-c", "run.sh"]),
            ("entrypoint", ["/bin/sh"]),
            ("working_dir", "/data"),
            ("depends_on", ["other"]),
            ("group_add", ["0"]),
            ("healthcheck", {"test": ["CMD", "true"]}),
            ("init", True),
            ("stop_signal", "SIGKILL"),
            ("stop_grace_period", "1h"),
            ("image", "example.invalid/synthetic:latest"),
            ("image", "example.invalid/synthetic@sha256:${DIGEST}"),
            ("user", "0:0"),
            ("read_only", False),
            ("read_only", 1),
            ("cap_drop", []),
            ("security_opt", []),
            ("logging", {"driver": "json-file"}),
            ("restart", "always"),
            ("network_mode", "host"),
            ("environment", {"TOKEN": None}),
        ):
            with self.subTest(field=field, value=value):
                compose = copy.deepcopy(self.compose)
                compose["services"]["node"][field] = value
                self.write({**self.profile, "docker_compose_file": json.dumps(compose)})
                with self.assertRaises(ValueError):
                    guest_source.launch_config_digest(self.path)
        for content in (
            "services:\n  node:\n    image: example.invalid/synthetic:latest\n",
            '{"services":{},"services":{}}',
            json.dumps({**self.compose, "include": ["other.yaml"]}),
            json.dumps({**self.compose, "networks": {"outside": {"external": True}}}),
        ):
            with self.subTest(content=content):
                self.write({**self.profile, "docker_compose_file": content})
                with self.assertRaises(ValueError):
                    guest_source.launch_config_digest(self.path)

    def test_split_roles_and_mounts_are_exact(self) -> None:
        changes = (
            ("wrapper", "network_mode", "bridge"),
            ("wrapper", "network_mode", "service:wrapper"),
            ("wrapper", "ports", ["8443:8443"]),
            ("wrapper", "environment", {"MAX_QUOTES": "1"}),
            ("wrapper", "depends_on", {"node": {"condition": "service_started"}}),
            ("node", "ports", ["18232:18232"]),
            ("node", "environment", {"NODE_POLL_INTERVAL_MS": "2"}),
            ("node", "healthcheck", {"test": ["CMD-SHELL", "true"]}),
            ("node", "platform", "linux/arm64"),
        )
        for service, field, value in changes:
            with self.subTest(service=service, field=field):
                compose = copy.deepcopy(self.compose)
                compose["services"][service][field] = value
                self.write({**self.profile, "docker_compose_file": json.dumps(compose)})
                with self.assertRaises(ValueError):
                    guest_source.launch_config_digest(self.path)
        for service, index, key, value in (
            ("node", 1, "source", "/var/lib/docker"),
            ("node", 1, "target", "/run/docker.sock"),
            ("node", 1, "read_only", True),
            ("node", 1, "read_only", 0),
            ("wrapper", 1, "read_only", False),
            ("wrapper", 1, "bind", {"create_host_path": True}),
            ("wrapper", 1, "bind", {"create_host_path": 0,
                                     "propagation": "rprivate"}),
        ):
            with self.subTest(service=service, key=key):
                compose = copy.deepcopy(self.compose)
                compose["services"][service]["volumes"][index][key] = value
                self.write({**self.profile, "docker_compose_file": json.dumps(compose)})
                with self.assertRaises(ValueError):
                    guest_source.launch_config_digest(self.path)

    def test_ambiguous_or_missing_input_is_rejected(self) -> None:
        self.path.write_text('{"runner":"docker-compose","runner":"bash"}')
        with self.assertRaises(ValueError):
            guest_source.launch_config_digest(self.path)
        self.path.write_text("{}")
        with self.assertRaises(ValueError):
            guest_source.launch_config_digest(self.path)
        self.path.unlink()
        with self.assertRaises(ValueError):
            guest_source.launch_config_digest(self.path)

    def test_system_controls_cannot_be_unpaired_or_ambiguous(self) -> None:
        self.write(self.profile)
        self.sys_path.write_text('{"vm_config":"{}"}')
        with self.assertRaises(ValueError):
            guest_source.bound_digests(self.path, None)
        with self.assertRaises(ValueError):
            guest_source.bound_digests(None, self.sys_path)
        for payload in (
            '{"vm_config":"{}","vm_config":"{}"}',
            '{"vm_config":"{\\"image\\":1,\\"image\\":2}"}',
            '{"vm_config":"not JSON"}',
            '{"vm_config":"[]"}',
            '{"vm_config":"{}","unexpected":NaN}',
            '{"vm_config":"{\\"unexpected\\":NaN}"}',
            '{"vm_config":"{}","docker_registry":"https://registry.example"}',
        ):
            with self.subTest(payload=payload):
                self.sys_path.write_text(payload)
                with self.assertRaises(ValueError):
                    guest_source.bound_digests(self.path, self.sys_path)
        self.sys_path.write_bytes(b"x" * (32 * 1024 + 1))
        with self.assertRaises(ValueError):
            guest_source.bound_digests(self.path, self.sys_path)
        self.sys_path.unlink()
        with self.assertRaises(ValueError):
            guest_source.bound_digests(self.path, self.sys_path)

    def test_attached_compose_termination_fails_the_launcher(self) -> None:
        fixture = GENERATOR.with_name("fixtures") / "pinned-app-compose.sh"
        original = fixture.read_bytes()
        self.assertEqual(
            hashlib.sha256(original).hexdigest(),
            guest_source.SOURCE_HASHES[guest_source.APP_LAUNCH_PATH],
        )
        payload = self.write(self.profile)
        work = Path(self.scratch.name)
        (work / "app-compose.json").write_bytes(payload)
        (work / "docker-compose.yaml").write_text(self.profile["docker_compose_file"] + "\n")
        for name in ("compose.yaml", "compose.override.yaml", "docker-compose.override.yaml"):
            (work / name).write_text(
                "services:\n  unreviewed:\n    image: example.invalid/poison\n"
            )
        (work / ".env").write_text("COMPOSE_FILE=compose.yaml\nCOMPOSE_PROFILES=hidden\n")
        launcher = work / "app-compose.sh"
        launcher.write_text(
            guest_source.candidate_app_launch(
                original.decode(), hashlib.sha256(payload).digest()
            )
        )
        stubs = work / "stubs"
        stubs.mkdir()
        (stubs / "docker").write_text(
            '#!/bin/sh\nprintf "%s\\n" "$*" >> "$ZRPC_STUB_LOG"\n'
            'exit "$ZRPC_DOCKER_EXIT"\n'
        )
        (stubs / "docker").chmod(0o700)
        (stubs / "dstack-util").write_text("#!/bin/sh\nexit 0\n")
        (stubs / "dstack-util").chmod(0o700)
        log = work / "docker-calls"
        env = {
            **os.environ,
            "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
            "ZRPC_STUB_LOG": str(log),
        }

        for docker_exit in ("0", "42"):
            with self.subTest(docker_exit=docker_exit):
                log.unlink(missing_ok=True)
                result = subprocess.run(
                    ["bash", str(launcher)], cwd=work,
                    env={**env, "ZRPC_DOCKER_EXIT": docker_exit},
                    capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    log.read_text().splitlines(),
                    ["--host unix:///run/docker.sock compose --env-file /dev/null -f docker-compose.yaml up --remove-orphans --abort-on-container-exit "
                     "--no-build --pull never"],
                )

        log.unlink()
        (work / "app-compose.json").write_bytes(payload + b" ")
        result = subprocess.run(
            ["bash", str(launcher)], cwd=work,
            env={**env, "ZRPC_DOCKER_EXIT": "0"},
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(log.exists(), "changed launch bytes reached Docker")

    def test_app_unit_tracks_the_foreground_supervisor(self) -> None:
        fixture = GENERATOR.with_name("fixtures") / "pinned-app-compose.service"
        original = fixture.read_bytes()
        self.assertEqual(
            hashlib.sha256(original).hexdigest(),
            guest_source.SOURCE_HASHES[guest_source.APP_UNIT_PATH],
        )
        candidate = guest_source.candidate_app_unit(original.decode())
        self.assertIn("Type=simple\n", candidate)
        self.assertNotIn("RemainAfterExit=true", candidate)
        self.assertIn("BindsTo=zrpc-quote-proxy.service\n", candidate)
        self.assertIn(
            "After=docker.service dstack-prepare.service dstack-guest-agent.service "
            "zrpc-quote-proxy.service\n", candidate,
        )
        self.assertIn("StandardOutput=null\n", candidate)

    def test_quote_bridge_must_signal_socket_readiness_before_compose(self) -> None:
        candidate = guest_source.quote_proxy_unit()
        self.assertIn("Before=app-compose.service\n", candidate)
        self.assertIn("BindsTo=app-compose.service ", candidate)
        self.assertIn("Type=notify\nNotifyAccess=main\n", candidate)
        self.assertNotIn("After=dstack-prepare.service app-compose.service", candidate)


if __name__ == "__main__":
    unittest.main()
