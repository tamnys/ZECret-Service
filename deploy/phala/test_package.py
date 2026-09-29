"""Synthetic checks for the offline Phala preview package boundary."""

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("phala_prepare", HERE / "prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
spec = importlib.util.spec_from_file_location(
    "phala_supervisor", HERE / "image/supervisor.py")
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


class PackageTests(unittest.TestCase):
    def setUp(self):
        scratch = prepare.ROOT / ".codex-tmp"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_hold_blocks_image_context_before_creating_output(self):
        _, zebra, _ = prepare.locks()
        eligible, due = prepare.eligibility(
            zebra, datetime(2026, 9, 29, tzinfo=timezone.utc))
        self.assertFalse(eligible)
        self.assertEqual(due.isoformat(), "2026-10-02T19:59:10+00:00")
        args = argparse.Namespace(output=self.root / "context")
        with patch.object(prepare, "eligibility", return_value=(False, due)):
            with self.assertRaisesRegex(ValueError, "release hold"):
                prepare.image_context(args)
        self.assertFalse(args.output.exists())

    def test_stock_tuple_drift_blocks_rendering(self):
        altered = self.root / "stock.json"
        stock = prepare.read_json(prepare.STOCK_LOCK)
        stock["kms_endpoint"] = "https://changed.invalid"
        altered.write_bytes(prepare.canonical(stock))
        with patch.object(prepare, "STOCK_LOCK", altered):
            with self.assertRaisesRegex(ValueError, "stock or Zebra identity"):
                prepare.locks()

    def test_render_binds_exact_bytes_and_isolates_backend_socket(self):
        stock, zebra, lock_digest = prepare.locks()
        inputs = self.root / "image-inputs.json"
        inputs.write_bytes(prepare.canonical({
            "status": "local-image-context-unapproved",
            "zebra_release_lock_sha256": lock_digest,
            "zebra_asset_sha256": zebra["asset"]["sha256"],
            "stock_os_image_sha256": stock["os_image_sha256"],
            "stock_candidate_lock_sha256": prepare.STOCK_LOCK_SHA256,
            "private_accepted": False,
            "deployment_enabled": False,
        }))
        runtime = self.root / "runtime.json"
        runtime.write_bytes(prepare.canonical({
            "quote_startup_timeout_secs": 1,
            "node_startup_timeout_secs": 1,
            "node_poll_interval_ms": 1,
            "max_connections": 1,
            "max_quotes": 1,
            "quote_spacing_ms": 1,
        }))
        image = "registry.example.invalid/zrpc@sha256:" + "a" * 64
        args = argparse.Namespace(image=image, image_inputs=inputs, runtime=runtime,
                                  output=self.root / "render")
        with patch.object(prepare, "eligibility", return_value=(True, datetime.now(timezone.utc))):
            receipt = prepare.launch_documents(args)
        compose_bytes = (args.output / "compose.json").read_bytes()
        app_bytes = (args.output / "app-compose.json").read_bytes()
        compose = json.loads(compose_bytes)
        app = json.loads(app_bytes)
        self.assertEqual(app["docker_compose_file"].encode(), compose_bytes)
        self.assertEqual(receipt["docker_compose_file_sha256"], prepare.digest(compose_bytes))
        self.assertEqual(receipt["app_compose_file_sha256"], prepare.digest(app_bytes))
        self.assertEqual(compose["services"]["app"]["ports"], ["8443:8443"])
        self.assertEqual(compose["services"]["quote"]["network_mode"], "none")
        self.assertEqual(compose["services"]["quote"]["user"], "10002:0")
        self.assertEqual(compose["services"]["app"]["user"], "10001:0")
        self.assertEqual(compose["services"]["app"]["image"], image)
        self.assertEqual(compose["services"]["quote"]["image"], image)
        self.assertEqual(compose["volumes"]["runtime_tmpfs"]["driver_opts"]["type"], "tmpfs")
        self.assertIn("/run/dstack.sock", json.dumps(compose["services"]["quote"]))
        self.assertNotIn("/run/dstack.sock", json.dumps(compose["services"]["app"]))
        self.assertFalse(receipt["private_accepted"])
        self.assertFalse(receipt["deployment_enabled"])
        self.assertFalse(receipt["cloud_calls"])

    def test_mutable_image_and_missing_limits_refuse_render(self):
        runtime = self.root / "runtime.json"
        runtime.write_text('{"max_connections":1}')
        with self.assertRaisesRegex(ValueError, "runtime limits"):
            prepare.runtime_config(runtime)
        self.assertIsNone(prepare.IMAGE_REF.fullmatch("registry.example.invalid/zrpc:latest"))

    def test_quote_health_requires_marker_and_both_actual_sockets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quote = root / "zrpc-quote"
            quote.mkdir()
            marker = root / "zrpc-quote-ready"
            marker.write_bytes(b"")
            marker.chmod(0o600)
            sockets = []
            try:
                for name in ("quote.sock", "watch.sock"):
                    item = socket.socket(socket.AF_UNIX)
                    item.bind(str(quote / name))
                    (quote / name).chmod(0o660)
                    sockets.append(item)
                with patch.object(supervisor, "RUN", root), patch.object(
                    supervisor, "QUOTE_READY", marker
                ):
                    self.assertTrue(supervisor.quote_health())
                    (quote / "watch.sock").unlink()
                    self.assertFalse(supervisor.quote_health())
            finally:
                for item in sockets:
                    item.close()


if __name__ == "__main__":
    unittest.main()
