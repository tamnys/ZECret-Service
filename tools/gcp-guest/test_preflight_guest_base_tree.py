"""Synthetic metadata gaps; the signed snapshot is rechecked by native CI."""

import hashlib
import io
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import preflight_guest_base_tree as preflight
import stage_guest_payload


def ar_member(name, data):
    header = (f"{name}/".ljust(16) + "0".ljust(12) + "0".ljust(6)
              + "0".ljust(6) + "100644".ljust(8) + str(len(data)).ljust(10)
              + "`\n").encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def archive_with_owner(uid):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as tar:
        for path in (".", "./usr", "./usr/lib", "./etc"):
            item = tarfile.TarInfo(path)
            item.type = tarfile.DIRTYPE
            item.mode = 0o755
            item.uid = uid
            tar.addfile(item)
        os_release = tarfile.TarInfo("./usr/lib/os-release")
        os_release.uid = uid
        os_release.mode = 0o644
        content = b"ID=debian\n"
        os_release.size = len(content)
        tar.addfile(os_release, io.BytesIO(content))
        link = tarfile.TarInfo("./etc/os-release")
        link.type = tarfile.SYMTYPE
        link.linkname = "../usr/lib/os-release"
        link.uid = uid
        link.mode = 0o777
        tar.addfile(link)
    return (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
            + ar_member("control.tar.xz", lzma.compress(b"control", format=lzma.FORMAT_XZ))
            + ar_member("data.tar.xz", lzma.compress(output.getvalue(), format=lzma.FORMAT_XZ)))


class BaseTreePreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="base-tree-preflight-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.metadata = self.root / "metadata"
        self.archives = self.root / "archives"
        self.metadata.mkdir()
        self.archives.mkdir()
        self.archive = archive_with_owner(os.getuid() + 1)
        digest = hashlib.sha256(self.archive).hexdigest()
        self.identity = {"name": "systemd", "version": "1", "architecture": "amd64",
                         "filename": "pool/main/s/systemd_1_amd64.deb",
                         "size": len(self.archive), "sha256": digest,
                         "path": f"debs/{digest}.deb"}
        (self.archives / (digest + ".deb")).write_bytes(self.archive)
        self.stage = self.root / "stage"
        with mock.patch.object(stage_guest_payload, "signed_packages",
                               return_value=[("systemd", self.archive)]):
            stage_guest_payload.stage(self.metadata, self.archives, self.stage, self.root)
        self.sysusers = self.root / "zrpc.conf"
        self.sysusers.write_text("u zrpc-wrapper -\n")

    def test_reports_real_owner_and_missing_boot_input_gaps(self):
        with (mock.patch.object(preflight, "authenticated_archives",
                                return_value=[(self.identity, self.archive)]),
              mock.patch.object(preflight.prepare, "INITRD_PACKAGES", {"systemd"}),
              mock.patch.object(preflight, "SYSUSERS", self.sysusers)):
            report = preflight.preflight(self.metadata, self.archives, self.stage)
        self.assertEqual(report["status"], preflight.STATUS)
        source = next(row for row in report["root_archive_entries"]
                      if row["path"] == "usr/lib/os-release")
        staged = next(row for row in report["staged_root_entries"]
                      if row["path"] == "usr/lib/os-release")
        self.assertEqual(source["uid"], os.getuid() + 1)
        self.assertEqual(staged["uid"], os.getuid())
        self.assertEqual(next(row for row in report["staged_root_entries"]
                              if row["path"] == ".")["mode"], 0o700)
        self.assertIn({"path": "usr/lib/os-release", "expected_type": "file",
                       "expected_executable": False, "result": "non_root_owner"},
                      report["root_required_inputs"])
        self.assertTrue(any(gap.get("path") ==
                            f"boot/vmlinuz-{preflight.prepare.KERNEL_VERSION}"
                            and gap["result"] == "missing_from_package_data"
                            for gap in report["gaps"]))
        self.assertFalse(report["image_built"])
        self.assertFalse(report["boot_verified"])
        self.assertFalse(report["private_mode_approved"])

    def test_rejects_changed_staged_mode(self):
        (self.stage / "usr/lib/os-release").chmod(0o666)
        with (mock.patch.object(preflight, "authenticated_archives",
                                return_value=[(self.identity, self.archive)]),
              mock.patch.object(preflight.prepare, "INITRD_PACKAGES", {"systemd"}),
              mock.patch.object(preflight, "SYSUSERS", self.sysusers)):
            with self.assertRaisesRegex(ValueError, "staged payload type or mode differs"):
                preflight.preflight(self.metadata, self.archives, self.stage)

    def test_rejects_unreviewed_staged_file(self):
        (self.stage / "etc/unreviewed.conf").write_text("unexpected\n")
        with (mock.patch.object(preflight, "authenticated_archives",
                                return_value=[(self.identity, self.archive)]),
              mock.patch.object(preflight.prepare, "INITRD_PACKAGES", {"systemd"}),
              mock.patch.object(preflight, "SYSUSERS", self.sysusers)):
            with self.assertRaisesRegex(ValueError, "missing or unreviewed paths"):
                preflight.preflight(self.metadata, self.archives, self.stage)

    def test_archive_hash_identity_checked_before_inventory(self):
        with mock.patch.object(preflight.guest, "authenticated_packages",
                               return_value=[self.identity]):
            self.assertEqual(preflight.authenticated_archives(
                self.metadata, self.archives)[0][1], self.archive)
            path = self.archives / (self.identity["sha256"] + ".deb")
            path.write_bytes(self.archive[:-1] + b"X")
            with self.assertRaisesRegex(ValueError, "reviewed lock"):
                preflight.authenticated_archives(self.metadata, self.archives)


if __name__ == "__main__":
    unittest.main()
