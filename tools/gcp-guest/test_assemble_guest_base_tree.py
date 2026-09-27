"""Synthetic, script-free rejection tests for the root BaseTrees archive."""

import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import assemble_guest_base_tree as candidate


def ar_member(name, data):
    header = (f"{name}/".ljust(16) + "0".ljust(12) + "0".ljust(6)
              + "0".ljust(6) + "100644".ljust(8) + str(len(data)).ljust(10)
              + "`\n").encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def package(members, *, root_owner=(0, 0), root_mode=0o755):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as tar:
        root = tarfile.TarInfo("./")
        root.type = tarfile.DIRTYPE
        root.uid, root.gid = root_owner
        root.mode = root_mode
        tar.addfile(root)
        for kind, path, data, mode, owner in members:
            member = tarfile.TarInfo("./" + path)
            member.uid, member.gid = owner
            member.mode = mode
            if kind == "directory":
                member.type = tarfile.DIRTYPE
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = data
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = "./" + data
            elif kind == "special":
                member.type = tarfile.CHRTYPE
            else:
                member.size = len(data)
            tar.addfile(member, io.BytesIO(data) if kind == "file" else None)
    return (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
            + ar_member("control.tar.xz", lzma.compress(b"inert control scripts"))
            + ar_member("data.tar.xz", output.getvalue()))


def identity(name, data):
    digest = hashlib.sha256(data).hexdigest()
    return {"name": name, "version": "1", "architecture": "amd64",
            "size": len(data), "sha256": digest,
            "filename": f"pool/main/{name}/{name}_1_amd64.deb",
            "path": f"debs/{digest}.deb"}


class BaseTreeAssemblyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="guest-base-tree-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.output = self.workspace / "candidate"
        self.metadata = self.workspace / "metadata"
        self.archives = self.workspace / "archives"
        self.metadata.mkdir()
        self.archives.mkdir()

    def authenticated(self, named):
        return [(identity(name, data), data) for name, data in named]

    def assemble(self, named):
        authenticated = self.authenticated(named)
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=authenticated):
            report = candidate.assemble(self.metadata, self.archives,
                                        self.output, self.workspace)
            checked = candidate.verify(self.metadata, self.archives, self.output)
        self.assertEqual(report["archive_sha256"], checked["archive_sha256"])
        return report

    @staticmethod
    def baseline():
        return package([
            ("directory", "usr", None, 0o755, (0, 0)),
            ("directory", "usr/bin", None, 0o755, (0, 0)),
            ("file", "usr/bin/tool", b"signed package bytes", 0o4755, (0, 0)),
            ("hardlink", "usr/bin/alias", "usr/bin/tool", 0o4755, (0, 0)),
            ("symlink", "usr/bin/tool-link", "tool", 0o777, (0, 0)),
        ])

    def test_exact_numeric_ownership_links_and_audited_mode_transform(self):
        report = self.assemble([("alpha", self.baseline())])
        self.assertEqual(report["status"], candidate.STATUS)
        self.assertEqual(report["transformed_regular_mode_count"], 2)
        for field in ("package_scripts_executed", "image_built",
                      "boot_verified", "private_mode_approved"):
            self.assertFalse(report[field])
        manifest_bytes = (self.output / candidate.MANIFEST).read_bytes()
        manifest = json.loads(manifest_bytes)
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(manifest_bytes).hexdigest())
        entries = {row["path"]: row for row in manifest["entries"]}
        self.assertEqual(entries["usr/bin/tool"]["source_mode"], 0o4755)
        self.assertEqual(entries["usr/bin/tool"]["output_mode"], 0o755)
        self.assertEqual(entries["usr/bin/tool"]["mode_transform"],
                         "clear_regular_setuid_setgid")
        self.assertEqual(entries["usr/bin/alias"]["target"], "usr/bin/tool")
        self.assertEqual(entries["usr/bin/alias"]["kind"], "hardlink")
        with tarfile.open(self.output / candidate.ARCHIVE, mode="r:") as tar:
            paths = [member.name for member in tar]
            self.assertLess(paths.index("./usr/bin/tool"), paths.index("./usr/bin/alias"))
            self.assertEqual(tar.getmember("./usr/bin/tool").mode, 0o755)
            self.assertEqual(tar.getmember("./usr/bin/alias").linkname,
                             "./usr/bin/tool")
            self.assertEqual(tar.getmember("./usr/bin/tool").uid, 0)
            self.assertEqual(tar.getmember("./usr/bin/tool").uname, "")
        self.assertEqual({item.name for item in self.output.iterdir()},
                         {candidate.ARCHIVE, candidate.MANIFEST})

    def test_reproducible_archive_bytes(self):
        data = self.baseline()
        first = self.assemble([("alpha", data)])
        second_output = self.workspace / "second"
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=self.authenticated([("alpha", data)])):
            second = candidate.assemble(self.metadata, self.archives,
                                        second_output, self.workspace)
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        self.assertEqual((self.output / candidate.MANIFEST).read_bytes(),
                         (second_output / candidate.MANIFEST).read_bytes())

    def test_conflicting_shared_directory_owner_rejected_before_output(self):
        alpha = package([("directory", "usr", None, 0o755, (0, 0))])
        beta = package([("directory", "usr", None, 0o755, (7, 7))])
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=self.authenticated([("alpha", alpha), ("beta", beta)])):
            with self.assertRaisesRegex(ValueError, "conflicting numeric"):
                candidate.assemble(self.metadata, self.archives, self.output,
                                   self.workspace)
        self.assertFalse(self.output.exists())

    def test_hardlink_owner_mismatch_rejected_before_output(self):
        data = package([("directory", "usr", None, 0o755, (0, 0)),
                        ("file", "usr/target", b"signed", 0o644, (0, 0)),
                        ("hardlink", "usr/alias", "usr/target", 0o644, (7, 7))])
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=self.authenticated([("alpha", data)])):
            with self.assertRaisesRegex(ValueError, "hardlink owner differs"):
                candidate.assemble(self.metadata, self.archives, self.output,
                                   self.workspace)
        self.assertFalse(self.output.exists())

    def test_unsafe_member_and_special_file_rejected_before_output(self):
        base = [("directory", "usr", None, 0o755, (0, 0))]
        for item in (("file", "usr/../../outside", b"bad", 0o644, (0, 0)),
                     ("special", "usr/device", None, 0o644, (0, 0)),
                     ("symlink", "usr/escape", "../../outside", 0o777, (0, 0))):
            with self.subTest(item=item):
                with mock.patch.object(candidate.preflight, "authenticated_archives",
                                       return_value=self.authenticated([("alpha", package(base + [item]))])):
                    with self.assertRaises(ValueError):
                        candidate.assemble(self.metadata, self.archives, self.output,
                                           self.workspace)
                self.assertFalse(self.output.exists())

    def test_wrong_archive_root_metadata_rejected(self):
        data = package([], root_owner=(1, 0))
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=self.authenticated([("alpha", data)])):
            with self.assertRaisesRegex(ValueError, "root directory metadata differs"):
                candidate.assemble(self.metadata, self.archives, self.output,
                                   self.workspace)
        self.assertFalse(self.output.exists())

    def test_changed_archive_or_manifest_rejected(self):
        data = self.baseline()
        authenticated = self.authenticated([("alpha", data)])
        self.assemble([("alpha", data)])
        archive = self.output / candidate.ARCHIVE
        original = archive.read_bytes()
        archive.write_bytes(original[:-1] + b"X")
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=authenticated):
            with self.assertRaisesRegex(ValueError, "manifest differs"):
                candidate.verify(self.metadata, self.archives, self.output)
        archive.write_bytes(original)
        manifest = self.output / candidate.MANIFEST
        record = json.loads(manifest.read_bytes())
        record["private_mode_approved"] = True
        manifest.write_bytes(candidate.canonical_bytes(record))
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=authenticated):
            with self.assertRaisesRegex(ValueError, "manifest differs"):
                candidate.verify(self.metadata, self.archives, self.output)

    def test_extra_field_or_wrong_boolean_type_rejected(self):
        data = self.baseline()
        authenticated = self.authenticated([("alpha", data)])
        self.assemble([("alpha", data)])
        manifest = self.output / candidate.MANIFEST
        original = manifest.read_bytes()
        for change in ({"unreviewed_trust": True},
                       {"signed_snapshot_rechecked": 1},
                       {"schema_version": 2}):
            with self.subTest(change=change):
                record = json.loads(original)
                record.update(change)
                manifest.write_bytes(candidate.canonical_bytes(record))
                with mock.patch.object(candidate.preflight, "authenticated_archives",
                                       return_value=authenticated):
                    with self.assertRaisesRegex(ValueError, "manifest (differs|exceeds)"):
                        candidate.verify(self.metadata, self.archives, self.output)
        manifest.write_bytes(original)

    def test_hardlink_check_is_independent_of_inventory_order(self):
        candidate.require_hardlinks({"usr/bin/tool": (2, 7),
                                     "usr/bin/alias": (2, 7)},
                                    [("usr/bin/alias", "usr/bin/tool")])
        with self.assertRaisesRegex(ValueError, "hardlink differs"):
            candidate.require_hardlinks({"usr/bin/tool": (2, 7),
                                         "usr/bin/alias": (2, 8)},
                                        [("usr/bin/alias", "usr/bin/tool")])

    def test_native_probe_shell_block_parses(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows"
                    / "gcp-builder-closure-probe.yml").read_text()
        beginning = workflow.index("      - name: Fetch exact source commit and locked Debian payloads\n")
        start = workflow.index("        run: |\n", beginning) + len("        run: |\n")
        end = workflow.index("      - name: Diagnostic packaged mkosi sandbox", start)
        script = "\n".join(line[10:] if line.startswith("          ") else line
                           for line in workflow[start:end].splitlines()) + "\n"
        checked = subprocess.run(["bash", "-n"], input=script, text=True,
                                 capture_output=True, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_authentication_failure_and_existing_output_fail_closed(self):
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               side_effect=ValueError("bad signed snapshot")):
            with self.assertRaisesRegex(ValueError, "bad signed snapshot"):
                candidate.assemble(self.metadata, self.archives, self.output,
                                   self.workspace)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        (self.output / "sentinel").write_text("keep")
        with mock.patch.object(candidate.preflight, "authenticated_archives",
                               return_value=self.authenticated([("alpha", self.baseline())])):
            with self.assertRaises(FileExistsError):
                candidate.assemble(self.metadata, self.archives, self.output,
                                   self.workspace)
        self.assertEqual((self.output / "sentinel").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
