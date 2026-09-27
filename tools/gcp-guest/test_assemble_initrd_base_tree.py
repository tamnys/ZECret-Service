"""Synthetic failure and byte-binding tests for the initrd input archive."""

import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import assemble_initrd_base_tree as candidate
from test_assemble_guest_base_tree import identity, package


ELF = b"\x7fELF" + b"synthetic x86 input"
SELECTED_SOURCE_PLAN = candidate.selected_source_plan


def source_package(*, tool=ELF, link="tool"):
    return package([
        ("directory", "proc", None, 0o755, (0, 0)),
        ("directory", "usr", None, 0o755, (0, 0)),
        ("directory", "usr/bin", None, 0o755, (0, 0)),
        ("file", "usr/bin/tool", tool, 0o755, (0, 0)),
        ("symlink", "usr/bin/tool-link", link, 0o777, (0, 0)),
        ("file", "usr/bin/bash", b"#!/bin/sh\n", 0o755, (0, 0)),
    ])


class InitrdInputAssemblyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="initrd-input-test-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.metadata = self.workspace / "metadata"
        self.archives = self.workspace / "archives"
        self.artifact = self.workspace / "artifact"
        self.metadata.mkdir()
        self.archives.mkdir()

    def authenticated(self, data=None, *, tool=ELF):
        data = data if data is not None else source_package(tool=tool)
        return [(identity("alpha", data), data)]

    @staticmethod
    def plan(authenticated):
        return SELECTED_SOURCE_PLAN(
            authenticated,
            selected_files=("usr/bin/tool", "usr/bin/tool-link"),
            mount_directories=("proc",),
            elf_entrypoints=("usr/bin/tool",),
        )

    def test_allowlist_omits_admin_binary_and_control_member(self):
        payloads, entries = self.plan(self.authenticated())
        self.assertIn("alpha", payloads)
        paths = {row["path"] for row in entries}
        self.assertEqual(paths, {".", "proc", "usr", "usr/bin",
                                 "usr/bin/tool", "usr/bin/tool-link"})
        self.assertNotIn("usr/bin/bash", paths)
        self.assertEqual(next(row for row in entries if row["path"] == "usr/bin/tool")["uid"], 0)

    def test_real_archive_is_deterministic_and_manifest_never_approves(self):
        authenticated = self.authenticated()
        with (mock.patch.object(candidate.preflight, "authenticated_archives",
                                return_value=authenticated),
              mock.patch.object(candidate, "selected_source_plan", side_effect=self.plan)):
            first = candidate.assemble(self.metadata, self.archives,
                                       self.artifact, self.workspace)
            checked = candidate.verify(self.metadata, self.archives, self.artifact)
            second_artifact = self.workspace / "second"
            second = candidate.assemble(self.metadata, self.archives,
                                        second_artifact, self.workspace)
        self.assertEqual(first["archive_sha256"], checked["archive_sha256"])
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertEqual((self.artifact / candidate.MANIFEST).read_bytes(),
                         (second_artifact / candidate.MANIFEST).read_bytes())
        manifest = json.loads((self.artifact / candidate.MANIFEST).read_bytes())
        self.assertEqual(manifest["selected_packages"][0]["name"], "alpha")
        for name in ("early_init_included", "runtime_closure_verified", "initrd_built",
                     "boot_verified", "private_mode_approved", "package_control_scripts_executed"):
            self.assertIs(manifest[name], False)
        with tarfile.open(self.artifact / candidate.ARCHIVE, mode="r:") as tar:
            paths = {member.name for member in tar}
            self.assertEqual(paths, {".", "./proc", "./usr", "./usr/bin",
                                     "./usr/bin/tool", "./usr/bin/tool-link"})
            self.assertEqual(tar.getmember("./usr/bin/tool").uid, 0)
            self.assertEqual(tar.getmember("./usr/bin/tool-link").linkname, "tool")
            self.assertEqual(tar.extractfile("./usr/bin/tool").read(), ELF)

    def test_missing_source_member_and_unselected_link_target_reject(self):
        authenticated = self.authenticated()
        with self.assertRaisesRegex(ValueError, "required initrd package data absent"):
            candidate.selected_source_plan(authenticated,
                selected_files=("usr/bin/missing",), mount_directories=(),
                elf_entrypoints=())
        with self.assertRaisesRegex(ValueError, "selected link target absent"):
            candidate.selected_source_plan(authenticated,
                selected_files=("usr/bin/tool-link",), mount_directories=(),
                elf_entrypoints=())
        with self.assertRaisesRegex(ValueError, "absolute initrd link"):
            self.plan(self.authenticated(source_package(link="/usr/bin/tool")))

    def test_selected_shell_script_rejects_before_output(self):
        authenticated = self.authenticated(tool=b"#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "not ELF"):
            self.plan(authenticated)
        self.assertFalse(self.artifact.exists())

    def test_tampered_archive_and_claims_reject(self):
        authenticated = self.authenticated()
        with (mock.patch.object(candidate.preflight, "authenticated_archives",
                                return_value=authenticated),
              mock.patch.object(candidate, "selected_source_plan", side_effect=self.plan)):
            candidate.assemble(self.metadata, self.archives, self.artifact, self.workspace)
            archive = self.artifact / candidate.ARCHIVE
            original = archive.read_bytes()
            archive.write_bytes(original[:-1] + b"X")
            with self.assertRaisesRegex(ValueError, "archive differs"):
                candidate.verify(self.metadata, self.archives, self.artifact)
            archive.write_bytes(original)
            manifest = self.artifact / candidate.MANIFEST
            record = json.loads(manifest.read_bytes())
            record["private_mode_approved"] = True
            manifest.write_bytes(candidate.canonical_bytes(record))
            with self.assertRaisesRegex(ValueError, "manifest differs"):
                candidate.verify(self.metadata, self.archives, self.artifact)

    def test_artifact_permissions_and_owner_are_required(self):
        with (mock.patch.object(candidate.preflight, "authenticated_archives",
                                return_value=self.authenticated()),
              mock.patch.object(candidate, "selected_source_plan", side_effect=self.plan)):
            candidate.assemble(self.metadata, self.archives, self.artifact, self.workspace)
            for path, label, changed_mode, original_mode in (
                (self.artifact, "directory", 0o755, 0o700),
                (self.artifact / candidate.ARCHIVE, "archive", 0o644, 0o600),
                (self.artifact / candidate.MANIFEST, "manifest", 0o644, 0o600),
            ):
                with self.subTest(path=path):
                    path.chmod(changed_mode)
                    with self.assertRaisesRegex(ValueError, f"{label} ownership"):
                        candidate.verify(self.metadata, self.archives, self.artifact)
                    path.chmod(original_mode)
            info = (self.artifact / candidate.ARCHIVE).stat()
            foreign = SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1,
                                      st_nlink=info.st_nlink)
            with self.assertRaisesRegex(ValueError, "archive ownership"):
                candidate.check_artifact_metadata(foreign, directory=False,
                                                  label="initrd BaseTrees archive")

    def test_archive_metadata_change_during_read_rejects(self):
        with (mock.patch.object(candidate.preflight, "authenticated_archives",
                                return_value=self.authenticated()),
              mock.patch.object(candidate, "selected_source_plan", side_effect=self.plan)):
            candidate.assemble(self.metadata, self.archives, self.artifact, self.workspace)
            archive = self.artifact / candidate.ARCHIVE
            before = archive.stat()
            real_digest = candidate.hashlib.file_digest

            def change_metadata_after_read(stream, algorithm):
                result = real_digest(stream, algorithm)
                os.utime(archive, ns=(before.st_atime_ns,
                                      before.st_mtime_ns + 1_000_000_000))
                return result

            with mock.patch.object(candidate.hashlib, "file_digest",
                                   side_effect=change_metadata_after_read):
                with self.assertRaisesRegex(ValueError, "archive changed during verification"):
                    candidate.verify(self.metadata, self.archives, self.artifact)

    def test_authentication_error_and_existing_artifact_fail_closed(self):
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               side_effect=ValueError("bad signed snapshot")):
            with self.assertRaisesRegex(ValueError, "bad signed snapshot"):
                candidate.assemble(self.metadata, self.archives,
                                   self.artifact, self.workspace)
        self.assertFalse(self.artifact.exists())
        self.artifact.mkdir()
        (self.artifact / "sentinel").write_text("keep")
        with (mock.patch.object(candidate.preflight, "authenticated_archives",
                                return_value=self.authenticated()),
              mock.patch.object(candidate, "selected_source_plan", side_effect=self.plan)):
            with self.assertRaises(FileExistsError):
                candidate.assemble(self.metadata, self.archives,
                                   self.artifact, self.workspace)
        self.assertEqual((self.artifact / "sentinel").read_text(), "keep")

    def test_static_allowlist_excludes_administration_and_scripts(self):
        paths = set(candidate.SELECTED_FILES)
        self.assertEqual(len(paths), len(candidate.SELECTED_FILES))
        self.assertNotIn("usr/bin/bash", paths)
        self.assertNotIn("usr/lib/systemd/systemd-sulogin-shell", paths)
        self.assertFalse(any(path.endswith((".sh", ".py")) for path in paths))
        self.assertFalse(any(path.startswith(("etc/ssh/", "usr/lib/udev/rules.d/",
                                               "usr/lib/systemd/system-generators/systemd-debug-"))
                             for path in paths))

    def test_native_probe_shell_blocks_parse(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows"
                    / "gcp-initrd-basetree-probe.yml").read_text()
        blocks = workflow.split("        run: |\n")[1:]
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            lines = []
            for line in block.splitlines():
                if line and not line.startswith("          "):
                    break
                lines.append(line[10:] if line else "")
            checked = subprocess.run(["bash", "-n"], input="\n".join(lines) + "\n",
                                     text=True, capture_output=True, check=False)
            self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
