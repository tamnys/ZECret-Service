"""Synthetic checks for the offline Phala preview package boundary."""

import argparse
from datetime import datetime, timedelta, timezone
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

    def test_image_context_check_rejects_changed_build_inputs(self):
        stock, zebra, lock_digest = prepare.locks()
        eligible_at = prepare.utc(zebra["asset"]["created_at"]) + timedelta(days=7)
        elf = b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x03\x00\x3e\x00" + b"\x00" * 44
        elf_hash = prepare.digest(elf)
        zebra = {**zebra, "zebrad_elf_sha256": elf_hash, "zebrad_elf_size": len(elf)}
        native = {name: elf_hash for name in prepare.NATIVE_BINARIES_SHA256}
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "zebrad").write_bytes(elf)
        (stage / "receipt.json").write_bytes(prepare.canonical({
            "schema_version": 1,
            "status": "staged-diagnostic-unapproved",
            "checked_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
            "eligible_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
            "archive_downloaded_by_tool": False,
            "image_built": False,
            "private_mode_approved": False,
            "local_hold_exception": None,
            "release_lock_sha256": lock_digest,
            "asset_sha256": zebra["asset"]["sha256"],
            "zebrad_elf_sha256": elf_hash,
            "zebrad_elf_size": len(elf),
            "verified_attestation_count": 1,
            "gh_verifier_executable_sha256": zebra["gh_verifier_executable_sha256"],
        }))
        for name in native:
            (self.root / name).write_bytes(elf)
        args = argparse.Namespace(
            zebra_stage=stage,
            node_wrapper=self.root / "zrpc-node-wrapper",
            node_wrapper_sha256=elf_hash,
            quote_proxy=self.root / "zrpc-quote-proxy",
            quote_proxy_sha256=elf_hash,
            base_image=prepare.BASE_IMAGE,
            base_image_created_at=prepare.BASE_IMAGE_CREATED_AT,
            output=self.root / "context",
        )
        with (patch.object(prepare, "locks", return_value=(stock, zebra, lock_digest)),
              patch.object(prepare, "NATIVE_BINARIES_SHA256", native),
              patch.object(prepare, "eligibility", return_value=(True, eligible_at))):
            prepare.image_context(args)
            checked = prepare.check_image_context(argparse.Namespace(context=args.output))
            self.assertEqual(checked["status"], "local-image-context-checked-unapproved")
            (args.output / "supervisor.py").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "reviewed inputs"):
                prepare.check_image_context(argparse.Namespace(context=args.output))
            (args.output / "supervisor.py").write_bytes(
                (prepare.HERE / "image/supervisor.py").read_bytes())
            native_file = args.output / "bin/zrpc-node-wrapper"
            native_file.chmod(0o755)
            native_file.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "reviewed inputs"):
                prepare.check_image_context(argparse.Namespace(context=args.output))
            native_file.write_bytes(elf)
            (args.output / ".dockerignore").write_text("bin/\n")
            with self.assertRaisesRegex(ValueError, "missing, extra"):
                prepare.check_image_context(argparse.Namespace(context=args.output))

    def test_exact_stage_exception_allows_local_context_only(self):
        stock, zebra, lock_digest = prepare.locks()
        due = prepare.utc(zebra["asset"]["created_at"]) + timedelta(days=7)
        checked = due - timedelta(days=1)
        elf = b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x03\x00\x3e\x00" + b"\x00" * 44
        elf_hash = prepare.digest(elf)
        zebra = {**zebra, "zebrad_elf_sha256": elf_hash, "zebrad_elf_size": len(elf)}
        native = {name: elf_hash for name in prepare.NATIVE_BINARIES_SHA256}
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "zebrad").write_bytes(elf)
        receipt = {
            "schema_version": 1,
            "status": "staged-diagnostic-unapproved",
            "checked_at_utc": checked.isoformat().replace("+00:00", "Z"),
            "eligible_at_utc": due.isoformat().replace("+00:00", "Z"),
            "archive_downloaded_by_tool": False,
            "image_built": False,
            "private_mode_approved": False,
            "local_hold_exception": prepare.LOCAL_HOLD_EXCEPTION,
            "release_lock_sha256": lock_digest,
            "asset_sha256": zebra["asset"]["sha256"],
            "zebrad_elf_sha256": elf_hash,
            "zebrad_elf_size": len(elf),
            "verified_attestation_count": 1,
            "gh_verifier_executable_sha256": zebra["gh_verifier_executable_sha256"],
        }
        (stage / "receipt.json").write_bytes(prepare.canonical(receipt))
        synthetic_receipt_hash = prepare.digest((stage / "receipt.json").read_bytes())
        for name in native:
            (self.root / name).write_bytes(elf)
        args = argparse.Namespace(
            zebra_stage=stage,
            node_wrapper=self.root / "zrpc-node-wrapper",
            node_wrapper_sha256=elf_hash,
            quote_proxy=self.root / "zrpc-quote-proxy",
            quote_proxy_sha256=elf_hash,
            base_image=prepare.BASE_IMAGE,
            base_image_created_at=prepare.BASE_IMAGE_CREATED_AT,
            output=self.root / "context",
            allow_v642_local_hold_exception=True,
        )
        with (patch.object(prepare, "locks", return_value=(stock, zebra, lock_digest)),
              patch.object(prepare, "NATIVE_BINARIES_SHA256", native),
              patch.object(prepare, "eligibility", return_value=(False, due))):
            with self.assertRaisesRegex(ValueError, "approved asset"):
                prepare.image_context(args)
        stock = {**stock, "reviewed_zebra_local_hold_receipt_sha256":
                 synthetic_receipt_hash}
        with (patch.object(prepare, "locks", return_value=(stock, zebra, lock_digest)),
              patch.object(prepare, "NATIVE_BINARIES_SHA256", native),
              patch.object(prepare, "eligibility", return_value=(False, due))):
            context = prepare.image_context(args)
            self.assertEqual(context["zebra_local_hold_exception"],
                             prepare.LOCAL_HOLD_EXCEPTION)
            self.assertEqual(prepare.check_image_context(
                argparse.Namespace(context=args.output))["status"],
                "local-image-context-checked-unapproved")
            with self.assertRaisesRegex(ValueError, "release hold"):
                prepare.launch_documents(argparse.Namespace())
            receipt["local_hold_exception"] = {
                **prepare.LOCAL_HOLD_EXCEPTION, "asset_id": 1}
            (args.output / "zebra-stage-receipt.json").write_bytes(
                prepare.canonical(receipt))
            with self.assertRaisesRegex(ValueError, "approved asset"):
                prepare.check_image_context(argparse.Namespace(context=args.output))

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
        self.assertNotIn("swap_size", app)
        self.assertNotIn("key_provider", app)
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
