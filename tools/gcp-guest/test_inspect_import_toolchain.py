"""Synthetic import-tool diagnostic tests; no package or cloud acceptance."""

import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspect_import_toolchain as tool


def deb_with_executable(path, content):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:xz") as archive:
        member = tarfile.TarInfo("./" + path)
        member.size = len(content)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(content))
    members = [("debian-binary/", b"2.0\n"),
               ("data.tar.xz/", data.getvalue())]
    result = bytearray(b"!<arch>\n")
    for name, payload in members:
        result.extend(f"{name:<16}{0:<12}{0:<6}{0:<6}{0o100644:<8}{len(payload):<10}`\n".encode())
        result.extend(payload)
        if len(payload) % 2:
            result.extend(b"\n")
    return bytes(result)


class ImportToolchainTests(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("CODEX_TMP_DIR")
        if not base:
            raise RuntimeError("managed workspace scratch required")
        self.scratch = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.lock_path = self.root / "closure.json"
        self.identities_path = self.root / "identities.json"
        self.receipt_path = self.root / "receipt.json"
        self.python_target = self.root / "python3.13"
        self.python_link = self.root / "python3"
        self.python_link.symlink_to(self.python_target.name)
        self.executables = {
            "tar": b"\x7fELFsynthetic-tar",
            "gzip": b"\x7fELFsynthetic-gzip",
            "python3.13-minimal": b"\x7fELFsynthetic-python",
        }
        self.python_target.write_bytes(self.executables["python3.13-minimal"])
        self.python_target.chmod(0o755)
        self.packages = {}
        self.entries = []
        for name, (path, _) in tool.TOOLS.items():
            data = deb_with_executable(path, self.executables[name])
            sha = hashlib.sha256(data).hexdigest()
            self.packages[name] = data
            self.entries.append({"name": name, "version": "synthetic", "architecture": "amd64",
                                 "filename": f"pool/main/{name}.deb", "size": len(data), "sha256": sha})
        self.lock_path.write_text(json.dumps({
            "snapshot": "https://example.invalid/snapshot/",
            "status": "apt-resolved-candidate-unbuilt-unapproved",
            "packages": self.entries,
        }))
        self.identities_path.write_text(json.dumps({
            "downloaded_metadata": {"trixie_snapshot_candidate": {
                "url": "https://example.invalid/snapshot/", "inrelease_sha256": "a" * 64,
                "main_binary_amd64_packages_xz_sha256": "b" * 64,
                "main_binary_amd64_packages_xz_size": 4,
                "signed_release_date_epoch": 1,
            }}
        }))
        self.receipt = {"toolchain_reviewed": False, "private_mode_approved": False,
                        "oldgnu_single_member_checked": True}
        for name, (_, field) in tool.TOOLS.items():
            self.receipt[field] = hashlib.sha256(self.executables[name]).hexdigest()
        self.write_receipt()

    def write_receipt(self):
        self.receipt_path.write_text(json.dumps(self.receipt))

    def verify(self):
        with (mock.patch.object(tool.closure, "LOCK", self.lock_path),
              mock.patch.object(tool.closure, "LOCK_BYTES", self.lock_path.stat().st_size),
              mock.patch.object(tool.closure, "LOCK_SHA256", hashlib.sha256(self.lock_path.read_bytes()).hexdigest()),
              mock.patch.object(tool.closure, "IDENTITIES", self.identities_path),
              mock.patch.object(tool, "EXPECTED_PYTHON_TARGET", self.python_target),
              mock.patch.object(tool.debian_snapshot, "authenticated_index_bytes",
                                return_value=(1, ("b" * 64, 4), b"test")),
              mock.patch.object(tool.debian_snapshot, "package_records",
                                return_value={(e["name"], "synthetic", "amd64"): {
                                    "Filename": e["filename"], "Size": str(e["size"]),
                                    "SHA256": e["sha256"]} for e in self.entries}),
              mock.patch.object(tool.closure, "indexed_archive",
                                side_effect=lambda entry, record, archives, keep_bytes:
                                    self.packages[entry["name"]])):
            return tool.verify(self.root / "InRelease", self.root / "Packages.xz",
                               self.archives, self.receipt_path,
                               operator_python=self.python_link)

    def test_signed_package_bytes_bind_receipt_and_operator_interpreter(self):
        report = self.verify()
        self.assertEqual(report["status"],
                         "diagnostic-import-receipt-claims-match-signed-debian-unapproved")
        self.assertEqual(report["import_receipt_sha256"],
                         hashlib.sha256(self.receipt_path.read_bytes()).hexdigest())
        for field in ("producer_execution_authenticated", "python_modules_verified", "elf_runtime_verified",
                      "complete_import_toolchain", "deployment_approved",
                      "private_mode_approved"):
            self.assertFalse(report[field])

    def test_producer_hash_or_false_approval_fails_closed(self):
        self.receipt["gnu_tar_sha256"] = "0" * 64
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "producer import executable"):
            self.verify()
        self.receipt["gnu_tar_sha256"] = hashlib.sha256(self.executables["tar"]).hexdigest()
        self.receipt["toolchain_reviewed"] = True
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "invalid executable identities or status"):
            self.verify()

    def test_operator_interpreter_mismatch_and_redirection_fail_closed(self):
        self.python_target.write_bytes(b"\x7fELFother-python")
        with self.assertRaisesRegex(ValueError, "operator Python differs"):
            self.verify()
        self.python_target.write_bytes(self.executables["python3.13-minimal"])
        self.python_link.unlink()
        self.python_link.symlink_to("other-python")
        with self.assertRaises((OSError, ValueError)):
            self.verify()

    def test_package_reader_rejects_missing_and_duplicate(self):
        sample = self.packages["tar"]
        self.assertEqual(tool.executable_from_package(sample, "usr/bin/tar"),
                         self.executables["tar"])
        with self.assertRaisesRegex(ValueError, "absent"):
            tool.executable_from_package(sample, "usr/bin/other")
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:xz") as archive:
            for _ in range(2):
                member = tarfile.TarInfo("./usr/bin/tar")
                member.mode = 0o755
                member.size = 4
                archive.addfile(member, io.BytesIO(b"\x7fELF"))
        # The parser also catches duplicate paths after authenticated package
        # bytes have been decoded; patch only that decoder for this synthetic case.
        with mock.patch.object(tool.closure, "deb_data_tar", return_value=payload.getvalue()):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                tool.executable_from_package(sample, "usr/bin/tar")


if __name__ == "__main__":
    unittest.main()
