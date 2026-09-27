"""Synthetic safety tests for script-free builder payload staging."""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_builder_toolchain as stage


def ar_member(name, data):
    header = (name.ljust(16).encode() + b"0".ljust(12) + b"0".ljust(6)
              + b"0".ljust(6) + b"100644".ljust(8)
              + str(len(data)).encode().ljust(10) + b"`\n")
    return header + data + (b"\n" if len(data) % 2 else b"")


def package(members):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:xz") as archive:
        for kind, path, value, mode in members:
            member = tarfile.TarInfo(path)
            member.mode = mode
            if kind == "directory":
                member.type = tarfile.DIRTYPE
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = value
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = value
            elif kind == "special":
                member.type = tarfile.CHRTYPE
            else:
                member.size = len(value)
            archive.addfile(member, io.BytesIO(value) if kind == "file" else None)
    # A control script is present as inert bytes; staging must never invoke it.
    return (b"!<arch>\n" + ar_member("debian-binary/", b"2.0\n")
            + ar_member("control.tar.xz/", b"synthetic-postinst-script")
            + ar_member("data.tar.xz/", payload.getvalue()))


class BuilderStagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gcp-builder-stage-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.output = self.root / "output"

    def run_stage(self, named_packages):
        entries = []
        for name, data in named_packages:
            digest = hashlib.sha256(data).hexdigest()
            archive = self.archives / (digest + ".deb")
            if not archive.exists():
                archive.write_bytes(data)
            entries.append({"name": name, "version": "1", "architecture": "amd64",
                            "filename": f"pool/main/{name}/{name}_1_amd64.deb",
                            "size": len(data), "sha256": digest})
        lock = self.root / "lock.json"
        lock.write_text(json.dumps({"status": "apt-resolved-candidate-unbuilt-unapproved",
                                    "snapshot": "https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                                    "packages": entries}))
        lock_bytes = lock.read_bytes()
        return stage.stage(self.archives, self.output, workspace=self.root,
                           lock_path=lock, lock_size=len(lock_bytes),
                           lock_sha256=hashlib.sha256(lock_bytes).hexdigest())

    def test_stages_exact_files_links_and_modes_without_running_scripts(self):
        alpha = package([
            ("directory", "./usr/", None, 0o755),
            ("directory", "./usr/bin/", None, 0o755),
            ("file", "./usr/bin/tool", b"not executed", 0o4755),
        ])
        beta = package([
            ("directory", "./usr/", None, 0o755),
            ("directory", "./usr/lib/", None, 0o755),
            ("symlink", "./usr/lib/tool", "../bin/tool", 0o777),
            ("symlink", "./usr/lib/config", "/etc/config", 0o777),
        ])
        report = self.run_stage([("alpha", alpha), ("beta", beta)])
        self.assertEqual(report["status"], stage.STATUS)
        self.assertFalse(report["package_scripts_executed"])
        self.assertFalse(report["runtime_execution_verified"])
        self.assertFalse(report["complete_builder_toolchain"])
        self.assertFalse(report["private_mode_approved"])
        self.assertEqual((self.output / "usr/bin/tool").read_bytes(), b"not executed")
        self.assertEqual(stat.S_IMODE((self.output / "usr/bin/tool").stat().st_mode), 0o755)
        self.assertEqual((self.output / "usr/lib/tool").readlink(), Path("../bin/tool"))
        self.assertEqual((self.output / "usr/lib/config").readlink(), Path("/etc/config"))
        manifest = json.loads((self.output / stage.MANIFEST).read_bytes())
        self.assertFalse(manifest["signed_snapshot_rechecked"])
        self.assertEqual(manifest["entries"][0]["packages"], ["alpha", "beta"])
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(
            (self.output / stage.MANIFEST).read_bytes()).hexdigest())

    def test_rejects_unsafe_members_before_creating_output(self):
        base = [("directory", "./usr/", None, 0o755)]
        cases = [
            ("traversal", ("file", "./usr/../../outside", b"bad", 0o644)),
            ("absolute", ("file", "/outside", b"bad", 0o644)),
            ("hardlink", ("hardlink", "./usr/hard", "target", 0o644)),
            ("special", ("special", "./usr/device", None, 0o644)),
            ("escaping link", ("symlink", "./usr/link", "../../outside", 0o777)),
        ]
        for label, bad in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    self.run_stage([("alpha", package(base + [bad]))])
                self.assertFalse(self.output.exists())

    def test_rejects_cross_package_collision_and_symlink_parent(self):
        first = package([("directory", "./usr/", None, 0o755),
                         ("file", "./usr/item", b"first", 0o644)])
        second = package([("directory", "./usr/", None, 0o755),
                          ("file", "./usr/item", b"second", 0o644)])
        with self.assertRaisesRegex(ValueError, "collision"):
            self.run_stage([("alpha", first), ("beta", second)])
        self.assertFalse(self.output.exists())
        first = package([("directory", "./usr/", None, 0o755),
                         ("symlink", "./usr/redirect", "/tmp", 0o777)])
        second = package([("directory", "./usr/", None, 0o755),
                          ("file", "./usr/redirect/escape", b"bad", 0o644)])
        with self.assertRaisesRegex(ValueError, "symlink parent"):
            self.run_stage([("alpha", first), ("beta", second)])
        self.assertFalse(self.output.exists())

    def test_rejects_changed_archive_and_existing_output(self):
        data = package([("directory", "./usr/", None, 0o755),
                        ("file", "./usr/tool", b"safe", 0o755)])
        self.output.mkdir()
        (self.output / "owned").write_text("keep")
        with self.assertRaises(FileExistsError):
            self.run_stage([("alpha", data)])
        self.assertEqual((self.output / "owned").read_text(), "keep")
        self.output.rename(self.root / "owned-output")
        digest = hashlib.sha256(data).hexdigest()
        (self.archives / (digest + ".deb")).write_bytes(data + b"tampered")
        with self.assertRaisesRegex(ValueError, "size differs"):
            self.run_stage([("alpha", data)])
        self.assertFalse(self.output.exists())

    def test_casefold_collision_requires_a_case_sensitive_output(self):
        data = package([("directory", "./usr/", None, 0o755),
                        ("file", "./usr/PAM", b"upper", 0o644),
                        ("file", "./usr/pam", b"lower", 0o644)])
        with mock.patch.object(stage, "case_sensitive_directory", return_value=False):
            with self.assertRaisesRegex(ValueError, "case-sensitive workspace"):
                self.run_stage([("alpha", data)])
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
