"""Synthetic negatives for the non-approving QEMU VGA observer."""

import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import boot_observe_qemu as observe


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-qemu-observe-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def stage(self):
        root = self.directory / "actual-stage"
        root.mkdir(mode=0o755)
        manifest = {"builder_closure_lock_sha256": observe.toolchain.LOCK_SHA256,
                    "package_scripts_executed": False, "entries": []}
        data = json.dumps(manifest).encode()
        (root / observe.stager.MANIFEST).write_bytes(data)
        reported_root = "/workspace/boot-toolchain"
        report = {"status": "diagnostic-pinned-qemu-ovmf-staged-unapproved",
                  "stage_host_path": reported_root,
                  "stage_inventory_sha256": digest(data),
                  "lock_sha256": observe.toolchain.LOCK_SHA256,
                  "package_scripts_executed": False,
                  "post_start_plugin_loads_verified": False,
                  "boot_verified": False, "hardware_verified": False,
                  "private_mode_approved": False,
                  "qemu_host_path": reported_root + "/" + observe.toolchain.QEMU,
                  "ovmf_code_host_path": reported_root + "/" + observe.toolchain.OVMF_CODE,
                  "ovmf_vars_template_host_path": reported_root + "/" + observe.toolchain.OVMF_VARS,
                  "qemu_chroot_path": "/" + observe.toolchain.QEMU,
                  "ovmf_code_chroot_path": "/" + observe.toolchain.OVMF_CODE,
                  "ovmf_vars_template_chroot_path": "/" + observe.toolchain.OVMF_VARS}
        report_path = self.directory / "stage.json"
        report_path.write_text(json.dumps(report))
        paths = {name: report[name] for name in
                 ("qemu_chroot_path", "ovmf_code_chroot_path",
                  "ovmf_vars_template_chroot_path")}
        return root, report, report_path, paths

    def disk(self):
        path = self.directory / "zrpc-gcp.raw"
        path.write_bytes(b"synthetic unsigned disk bytes")
        report = {"status": observe.BOOT_DISK_STATUS,
                  "production_image": False, "synthetic_service_payloads": True,
                  "gpt_esp_verity_uki_inspected": True,
                  "secure_boot_signature_checked": False,
                  "boot_verified": False, "hardware_verified": False,
                  "private_mode_approved": False,
                  "raw_disk_sha256": digest(path.read_bytes()),
                  "raw_disk_bytes": path.stat().st_size}
        report_path = self.directory / "disk.json"
        report_path.write_text(json.dumps(report))
        return path, report, report_path

    def test_stage_rebases_reported_paths_but_rechecks_actual_inventory(self):
        root, report, report_path, paths = self.stage()
        with (mock.patch.object(observe, "mounted_at", return_value=True),
              mock.patch.object(observe.os, "statvfs", return_value=
                                types.SimpleNamespace(f_flag=observe.os.ST_RDONLY)),
              mock.patch.object(observe.toolchain, "dynamic_closure", return_value=paths)):
            self.assertEqual(observe.checked_stage(root, report_path), report)
            report["stage_inventory_sha256"] = "0" * 64
            report_path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                observe.checked_stage(root, report_path)

    def test_stage_rejects_path_substitution_and_writable_mount(self):
        root, report, report_path, paths = self.stage()
        report["qemu_host_path"] = "/usr/bin/qemu-system-x86_64"
        report_path.write_text(json.dumps(report))
        with (mock.patch.object(observe, "mounted_at", return_value=True),
              mock.patch.object(observe.os, "statvfs", return_value=
                                types.SimpleNamespace(f_flag=observe.os.ST_RDONLY)),
              mock.patch.object(observe.toolchain, "dynamic_closure", return_value=paths)):
            with self.assertRaisesRegex(ValueError, "path relationship"):
                observe.checked_stage(root, report_path)
        with mock.patch.object(observe, "mounted_at", return_value=False):
            with self.assertRaisesRegex(ValueError, "read-only mount"):
                observe.checked_stage(root, report_path)

    def test_disk_is_read_only_hash_bound_and_never_accepts_approval(self):
        path, report, report_path = self.disk()
        fd, _ = observe.checked_disk(path, report_path)
        try:
            self.assertEqual(observe.digest_fd(fd, report["raw_disk_bytes"]),
                             report["raw_disk_sha256"])
        finally:
            observe.os.close(fd)
        path.write_bytes(b"synthetic unsigned disk byteX")
        with self.assertRaisesRegex(ValueError, "hash differs"):
            observe.checked_disk(path, report_path)
        path.write_bytes(b"synthetic unsigned disk bytes")
        report["private_mode_approved"] = True
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "unsigned boot diagnostic"):
            observe.checked_disk(path, report_path)

    def test_qemu_command_has_no_network_or_guest_input_override(self):
        command = observe.qemu_command(7, 2048, 2)
        self.assertEqual(command[0], "/" + observe.toolchain.QEMU)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertIn("-nodefaults", command)
        self.assertIn("-display", command)
        self.assertIn("-vga", command)
        self.assertIn("readonly=on,file=/dev/fdset/1", " ".join(command))
        self.assertNotIn("-kernel", command)
        self.assertNotIn("-append", command)
        self.assertNotIn("-netdev", command)
        for value in (0, -1):
            with self.assertRaisesRegex(ValueError, "explicit QEMU"):
                observe.qemu_command(7, value, 2)

    def test_qmp_event_before_reply_does_not_become_boot_evidence(self):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        qmp = observe.Qmp(client)
        def respond():
            request = server.recv(4096)
            self.assertIn(b'"execute":"query-status"', request)
            server.sendall(b'{"event":"SHUTDOWN","data":{"guest":true}}\r\n'
                           b'{"return":{"status":"shutdown","running":false},'
                           b'"id":"query-status"}\r\n')
        thread = threading.Thread(target=respond)
        thread.start()
        self.addCleanup(thread.join)
        result = qmp.command("query-status", {}, observe.time.monotonic() + 1)
        self.assertEqual(result["status"], "shutdown")
        self.assertEqual(qmp.events[0]["event"], "SHUTDOWN")
        self.assertNotIn("early_init_handoff_verified", result)

    def test_buffered_qmp_events_cannot_extend_explicit_deadline(self):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        qmp = observe.Qmp(client)
        qmp.pending = b'{"event":"RESET"}\r\n'
        with self.assertRaisesRegex(TimeoutError, "deadline reached"):
            qmp.receive(observe.time.monotonic() - 1)

    def test_no_route_context_rejects_same_namespace(self):
        with (mock.patch.object(observe.platform, "system", return_value="Linux"),
              mock.patch.object(observe.platform, "machine", return_value="x86_64"),
              mock.patch.object(observe.os, "geteuid", return_value=0),
              mock.patch.object(observe.os, "readlink", return_value="net:[123]")):
            with self.assertRaisesRegex(ValueError, "separate no-route namespace"):
                observe.checked_execution_context("net:[123]", 1000, 1000)

    def test_child_rejects_capability_retention(self):
        status = ("CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
                  "CapEff:\t0000000000000001\nCapAmb:\t0000000000000000\n"
                  "NoNewPrivs:\t1\n")
        libc = types.SimpleNamespace(prctl=lambda *args: 0)
        with (mock.patch.object(observe.os, "chroot"),
              mock.patch.object(observe.os, "chdir"),
              mock.patch.object(observe.os, "setgroups"),
              mock.patch.object(observe.os, "setgid"),
              mock.patch.object(observe.os, "setuid"),
              mock.patch.object(observe.os, "geteuid", return_value=1000),
              mock.patch.object(observe.os, "getegid", return_value=1000),
              mock.patch.object(observe.os, "getgroups", return_value=[]),
              mock.patch.object(observe.ctypes, "CDLL", return_value=libc),
              mock.patch.object(observe.Path, "read_text", return_value=status)):
            with self.assertRaisesRegex(ValueError, "capabilities"):
                observe._drop_and_chroot(self.directory, 1000, 1000, 10)

    def test_observation_report_is_fresh_and_nonapproving(self):
        root = self.directory / "stage"
        root.mkdir()
        output = root / "observe"
        output.mkdir()
        report = {"status": observe.STATUS, "boot_verified": False,
                  "private_mode_approved": False}
        with (mock.patch.object(observe, "mounted_at", return_value=True),
              mock.patch.object(observe.os, "statvfs", return_value=
                                types.SimpleNamespace(f_flag=0))):
            self.assertTrue(observe.persist_report(root, output, report))
            self.assertEqual(json.loads((output / "observation.json").read_text()), report)
            with self.assertRaises(FileExistsError):
                observe.persist_report(root, output, report)


if __name__ == "__main__":
    unittest.main()
