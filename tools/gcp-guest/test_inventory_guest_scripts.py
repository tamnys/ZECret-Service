"""Synthetic parser and identity tests; signature checks are exercised in CI."""

import hashlib
import io
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import inventory_guest_scripts as inventory


def ar_member(name, data):
    header = (f"{name}/".ljust(16) + "0".ljust(12) + "0".ljust(6)
              + "0".ljust(6) + "100644".ljust(8) + str(len(data)).ljust(10)
              + "`\n").encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def control_tar(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        for name, data, kind in members:
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name in {"./postinst", "./preinst", "./config"} else 0o644
            if kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = data.decode()
                archive.addfile(entry)
            else:
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
    return lzma.compress(output.getvalue(), format=lzma.FORMAT_XZ)


def deb(members, *, version=b"2.0\n", extra=b""):
    return (inventory.AR_MAGIC + ar_member("debian-binary", version)
            + ar_member("control.tar.xz", control_tar(members))
            + ar_member("data.tar.xz", b"inert-data") + extra)


class ControlInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="guest-control-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.metadata = self.root / "metadata"
        self.archives = self.root / "archives"
        self.metadata.mkdir()
        self.archives.mkdir()
        self.members = [
            ("./control", b"Package: fixture\n", "file"),
            ("./postinst", b"#!/bin/sh\nexit 0\n", "file"),
            ("./triggers", b"interest /usr/share/icons\n", "file"),
        ]

    def test_classifies_and_hashes_inert_files(self):
        archive = deb(self.members)
        control_sha, rows = inventory.control_entries(archive)
        self.assertEqual(control_sha,
                         hashlib.sha256(inventory.control_tar(archive)).hexdigest())
        self.assertEqual([(row["name"], row["kind"]) for row in rows], [
            ("control", "metadata"), ("postinst", "maintainer_script"),
            ("triggers", "trigger_declarations"),
        ])
        self.assertEqual(rows[1]["sha256"], hashlib.sha256(self.members[1][1]).hexdigest())
        self.assertEqual(rows[1]["mode"], 0o755)

    def test_rejects_wrong_ar_shape_or_control_member(self):
        cases = [
            ("bad ar", b"bad"),
            ("wrong version", deb(self.members, version=b"1.0\n")),
            ("duplicate ar member", deb(self.members, extra=ar_member("control.tar.xz", b""))),
            ("invalid xz", inventory.AR_MAGIC + ar_member("debian-binary", b"2.0\n")
             + ar_member("control.tar.xz", b"not-xz")
             + ar_member("data.tar.xz", b"inert-data")),
            ("truncated ar", deb(self.members)[:-1]),
            ("duplicate control", deb(self.members + [self.members[1]])),
            ("unsafe control path", deb(self.members + [("./../postrm", b"bad", "file")])),
            ("unknown control member", deb(self.members + [("./runme", b"bad", "file")])),
            ("control symlink", deb(self.members[:-2] + [("./postinst", b"/bin/sh", "symlink")])),
            ("missing control", deb(self.members[1:])),
        ]
        for label, archive in cases:
            with self.subTest(label=label), self.assertRaises(ValueError):
                inventory.control_entries(archive)
        with mock.patch.object(inventory, "MAX_CONTROL_TAR_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds reviewed shape"):
                inventory.control_entries(deb(self.members))

    def test_authentication_and_archive_identity_precede_inventory(self):
        archive = deb(self.members)
        digest = hashlib.sha256(archive).hexdigest()
        identity = {"name": "fixture", "version": "1", "architecture": "amd64",
                    "filename": "pool/main/f/fixture_1_amd64.deb",
                    "size": len(archive), "sha256": digest,
                    "path": f"debs/{digest}.deb"}
        (self.archives / (digest + ".deb")).write_bytes(archive)
        with mock.patch.object(inventory.guest, "authenticated_packages",
                               return_value=[identity]):
            report = inventory.inventory(self.metadata, self.archives)
            self.assertEqual(report["status"], inventory.STATUS)
            self.assertEqual(report["package_count"], 1)
            self.assertEqual(report["maintainer_script_count"], 1)
            self.assertEqual(report["trigger_file_count"], 1)
            self.assertFalse(report["package_scripts_executed"])
            self.assertFalse(report["private_mode_approved"])
            with mock.patch.object(inventory.guest, "authenticated_packages",
                                   side_effect=ValueError("bad signed snapshot")):
                with self.assertRaisesRegex(ValueError, "bad signed snapshot"):
                    inventory.inventory(self.metadata, self.archives)
            (self.archives / (digest + ".deb")).write_bytes(archive[:-1] + b"X")
            with self.assertRaisesRegex(ValueError, "reviewed lock"):
                inventory.inventory(self.metadata, self.archives)
            (self.archives / (digest + ".deb")).write_bytes(archive[:-1])
            with self.assertRaisesRegex(ValueError, "size differs"):
                inventory.inventory(self.metadata, self.archives)


if __name__ == "__main__":
    unittest.main()
