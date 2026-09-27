"""Synthetic rejection tests for the offline builder APT candidate checker."""

import hashlib
import io
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_builder_closure as closure


def ar_member(name, data):
    header = (
        name.ljust(16).encode() + b"0".ljust(12) + b"0".ljust(6)
        + b"0".ljust(6) + b"100644".ljust(8)
        + str(len(data)).encode().ljust(10) + b"`\n"
    )
    return header + data + (b"\n" if len(data) % 2 else b"")


def apt_archive(paths):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        for path, data in paths:
            member = tarfile.TarInfo(path)
            if isinstance(data, str):
                member.type = tarfile.SYMTYPE
                member.linkname = data
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    return b"!<arch>\n" + ar_member("debian-binary/", b"2.0\n") + ar_member("data.tar.xz/", buffer.getvalue())


class BuilderClosureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="gcp-builder-closure-synthetic-", dir=os.environ.get("CODEX_TMP_DIR"),
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_signed_archive_metadata_and_bytes_are_both_required(self):
        archives = self.root / "debs"
        archives.mkdir()
        data = b"!<arch>\n" + b"synthetic"
        digest = hashlib.sha256(data).hexdigest()
        entry = {
            "name": "apt", "version": "3.0.3", "architecture": "amd64",
            "filename": "pool/main/a/apt/apt_3.0.3_amd64.deb",
            "size": len(data), "sha256": digest,
        }
        record = {"Filename": entry["filename"], "Size": str(len(data)), "SHA256": digest}
        archive = archives / f"{digest}.deb"
        archive.write_bytes(data)
        self.assertEqual(closure.indexed_archive(entry, record, archives, keep_bytes=True), data)
        with self.assertRaisesRegex(ValueError, "signed index"):
            closure.indexed_archive({**entry, "version": "3.0.4"}, None, archives)
        archive.write_bytes(data + b"changed")
        with self.assertRaisesRegex(ValueError, "archive differs"):
            closure.indexed_archive(entry, record, archives)
        archive.unlink()
        source = self.root / "elsewhere.deb"
        source.write_bytes(data)
        archive.symlink_to(source)
        with self.assertRaisesRegex(ValueError, "redirected"):
            closure.indexed_archive(entry, record, archives)

    def test_apt_get_must_be_unique_regular_file_at_exact_path(self):
        self.assertEqual(closure.apt_get_from_deb(apt_archive([
            ("./usr/bin/apt-get", b"reviewed-resolver"),
        ])), b"reviewed-resolver")
        for paths in (
            [("../usr/bin/apt-get", b"misplaced")],
            [("./usr/bin/apt-get", b"first"), ("./usr/bin/apt-get", b"second")],
        ):
            with self.subTest(paths=paths), self.assertRaisesRegex(ValueError, "unique regular apt-get"):
                closure.apt_get_from_deb(apt_archive(paths))
        with self.assertRaisesRegex(ValueError, "apt ar header"):
            closure.apt_get_from_deb(b"!<arch>\n" + b"malformed")

    def test_signed_elf_provider_requires_same_directory_regular_target(self):
        prefix = "./usr/lib/x86_64-linux-gnu/"
        signed = apt_archive([
            (prefix + "libexample.so.1", "libexample.so.1.2"),
            (prefix + "libexample.so.1.2", b"\x7fELFsynthetic"),
        ])
        self.assertEqual(closure.package_elf(signed, "libexample.so.1"), b"\x7fELFsynthetic")
        for archive, message in (
            (apt_archive([(prefix + "libexample.so.1", "/usr/lib/libexample.so.1")]), "escapes"),
            (apt_archive([(prefix + "libexample.so.1", "../libexample.so.1")]), "escapes"),
            (apt_archive([(prefix + "libexample.so.1", "libexample.so.1.2")]), "regular target"),
            (apt_archive([(prefix + "libexample.so.1", b"not-elf")]), "not ELF"),
            (apt_archive([(prefix + "libexample.so.1", b"\x7fELFone"),
                          (prefix + "libexample.so.1", b"\x7fELFtwo")]), "duplicate"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                closure.package_elf(archive, "libexample.so.1")

    def test_loader_rejects_ambient_missing_and_duplicate_objects(self):
        loader = Path("/proc/self/fd/3")
        library = Path("/proc/self/fd/4")
        good = ("\t/proc/self/fd/4 (0x000000400284c000)\n"
                "\t/lib64/ld-linux-x86-64.so.2 => /proc/self/fd/3 (0x0000004000000000)\n")
        result = lambda body: subprocess.CompletedProcess([], 0, body, "")
        closure.check_loader_report(result(good), loader, [library])
        for body, message in (
            (good.replace("/proc/self/fd/4", "/lib/x86_64-linux-gnu/libc.so.6"), "unrecognized"),
            (good.splitlines(keepends=True)[1], "missing or ambient"),
            (good + "\t/proc/self/fd/4 (0x000000400284c000)\n", "missing or ambient"),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, message):
                closure.check_loader_report(result(body), loader, [library])

    def test_archive_elf_is_sealed_across_loader_inspection_and_use(self):
        with closure.sealed_elf_bytes(b"\x7fELFsynthetic") as (path, fd):
            self.assertEqual(path.read_bytes(), b"\x7fELFsynthetic")
            with self.assertRaises(OSError):
                os.write(fd, b"change")

    def test_apt_plan_rejects_removal_duplicate_and_wrong_version(self):
        good = "Inst apt (3.0.3 snapshot.debian.org [amd64])\n"
        result = lambda body, code=0, error="": subprocess.CompletedProcess([], code, body, error)
        self.assertEqual(closure.parse_apt_plan(result(good)), {"apt": ("3.0.3", "amd64")})
        for output, message in (
            (good + "Remv mkosi [25.3-7]\n", "removal"),
            (good + good, "duplicate"),
            ("Inst apt (3.0.3 other.host [amd64])\n", "unrecognized"),
        ):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, message):
                closure.parse_apt_plan(result(output))
        with self.assertRaisesRegex(ValueError, "simulation failed"):
            closure.parse_apt_plan(result(good, code=1))

    def test_reviewed_lock_and_resolver_bytes_reject_substitution(self):
        lock = self.root / "closure.json"
        data = closure.LOCK.read_bytes()
        lock.write_bytes(data.replace(b"apt-resolved", b"apt-forged--", 1))
        with self.assertRaisesRegex(ValueError, "source-reviewed candidate"):
            closure.verify(self.root / "missing-release", self.root / "missing-index",
                           self.root / "missing-debs", self.root / "missing-apt",
                           self.root, lock_path=lock)
        apt_get = self.root / "apt-get"
        apt_get.write_bytes(b"bad")
        resolver = {"executable_sha256": hashlib.sha256(b"good").hexdigest(),
                    "executable_size": 4}
        with patch.object(closure, "INDEX_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "APT resolver differs"):
                closure.apt_plan(lzma.compress(b"data"), self.root, apt_get,
                                 resolver, [], "https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                                 {})


if __name__ == "__main__":
    unittest.main()
