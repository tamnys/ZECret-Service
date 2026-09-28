"""Synthetic failures for the non-accepting native CPIO builder probe."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import preflight_initrd_builder as candidate


class InitrdBuilderProbeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="initrd-builder-probe-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.entries = []
        for path, package in candidate.TOOLS.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            data = (path + "\n").encode()
            target.write_bytes(data)
            target.chmod(0o755)
            self.entries.append({"path": path, "kind": "file", "packages": [package],
                                 "sha256": hashlib.sha256(data).hexdigest(),
                                 "size": len(data), "staged_mode": 0o755})
        link = self.root / candidate.INTERPRETER_LINK
        link.symlink_to(candidate.INTERPRETER_TARGET)
        self.entries.append({"path": candidate.INTERPRETER_LINK,
                             "kind": "symlink",
                             "packages": [candidate.INTERPRETER_PACKAGE],
                             "target": candidate.INTERPRETER_TARGET})
        self.manifest = {
            "status": candidate.staged.STATUS,
            "builder_closure_lock_sha256": candidate.closure.LOCK_SHA256,
            "entries": self.entries,
            "signed_snapshot_rechecked": False,
            "package_scripts_executed": False,
            "runtime_execution_verified": False,
            "complete_builder_toolchain": False,
            "image_built": False,
            "private_mode_approved": False,
        }
        self.write_manifest()

    def write_manifest(self):
        (self.root / candidate.staged.MANIFEST).write_text(
            json.dumps(self.manifest, sort_keys=True))

    def test_selected_staged_executables_are_only_a_diagnostic(self):
        with mock.patch.object(candidate, "network_observation", return_value="net:[2]"):
            report = candidate.probe(self.root, "net:[1]")
        self.assertEqual(report["status"], candidate.STATUS)
        self.assertEqual(report["selected_executables"],
                         sorted(set(candidate.TOOLS) | {candidate.INTERPRETER_LINK}))
        self.assertTrue(report["selected_executable_bytes_match_staged_receipt"])
        for field in ("signed_snapshot_rechecked_by_this_probe",
                      "network_confinement_verified",
                      "complete_builder_toolchain", "mkosi_executed_by_this_probe",
                      "initrd_built", "image_built", "private_mode_approved"):
            self.assertIs(report[field], False)

    def test_payload_change_or_redirect_blocks_before_capability_report(self):
        executable = self.root / "usr/bin/cpio"
        executable.write_bytes(b"different executable bytes")
        with self.assertRaisesRegex(ValueError, "metadata changed"):
            candidate.probe(self.root, "net:[1]")
        executable.unlink()
        executable.symlink_to("zstd")
        with self.assertRaises(OSError):
            candidate.probe(self.root, "net:[1]")

    def test_python_interpreter_link_must_reach_selected_binary(self):
        link = self.root / candidate.INTERPRETER_LINK
        link.unlink()
        link.symlink_to("/usr/bin/other-python")
        with self.assertRaisesRegex(ValueError, "interpreter link changed"):
            candidate.probe(self.root, "net:[1]")

    def test_receipt_cannot_claim_complete_toolchain_or_lack_cpio(self):
        self.manifest["complete_builder_toolchain"] = True
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "non-accepting staged closure"):
            candidate.probe(self.root, "net:[1]")
        self.manifest["complete_builder_toolchain"] = False
        self.manifest["entries"] = [entry for entry in self.entries
                                    if entry["path"] != "usr/bin/cpio"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "absent"):
            candidate.probe(self.root, "net:[1]")

    def test_network_observation_rejects_same_namespace_routes_and_interfaces(self):
        header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        ipv4_local = "lo 0000007F 00000000 0001 0 0 0 000000FF 0 0 0\n"
        ipv6_local = " ".join(["0" * 32, "80", "0" * 32, "00", "0" * 32,
                               "00000000", "00000000", "00000000", "00000001", "lo"]) + "\n"
        good = ("net:[1]", "net:[2]", [(1, "lo")], "", ipv6_local)
        self.assertEqual(candidate.network_observation(*good), "net:[2]")
        self.assertEqual(candidate.network_observation(
            "net:[1]", "net:[2]", [(1, "lo")], header + ipv4_local,
            ipv6_local), "net:[2]")
        rejected = (
            ("net:[1]", "net:[1]", [(1, "lo")], header, ""),
            ("net:[1]", "net:[2]", [(1, "lo"), (2, "eth0")], header, ""),
            ("net:[1]", "net:[2]", [(1, "lo")], header + "eth0 route\n", ""),
            ("net:[1]", "net:[2]", [(1, "lo")], header,
             ipv6_local.removesuffix("lo\n") + "eth0\n"),
            ("net:[1]", "net:[2]", [(1, "lo")], "garbled\n", ""),
        )
        for values in rejected:
            with self.subTest(values=values), self.assertRaises(ValueError):
                candidate.network_observation(*values)


if __name__ == "__main__":
    unittest.main()
