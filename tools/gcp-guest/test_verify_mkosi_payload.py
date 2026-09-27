"""Synthetic package-shape tests; they do not establish Debian provenance."""

import hashlib
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_mkosi_payload as payload


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def ar_member(name, data):
    header = (
        name.ljust(16).encode() + b"0".ljust(12) + b"0".ljust(6)
        + b"0".ljust(6) + b"100644".ljust(8)
        + str(len(data)).encode().ljust(10) + b"`\n"
    )
    return header + data + (b"\n" if len(data) % 2 else b"")


def make_deb(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        for name, (data, mode) in (files.items() if isinstance(files, dict) else files):
            member = tarfile.TarInfo("./" + name)
            member.mode = mode
            if isinstance(data, tuple):
                member.type = tarfile.SYMTYPE
                member.linkname = data[0]
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    return (b"!<arch>\n" + ar_member("debian-binary/", b"2.0\n")
            + ar_member("data.tar.xz/", buffer.getvalue()))


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            "mkosi/__main__.py": ("file", 0o644, sha256(b"main")),
            "mkosi/resources/default.conf": ("file", 0o644, sha256(b"config")),
            "kernel-install/50-mkosi.install": ("file", 0o755, sha256(b"kernel50")),
            "kernel-install/51-mkosi-addon.install": ("file", 0o755, sha256(b"kernel51")),
        }
        self.scripts = {name: sha256(name.encode()) for name in payload.CONSOLE_SCRIPTS}
        self.files = {
            payload.PACKAGE_MODULES + "__main__.py": (b"main", 0o644),
            payload.PACKAGE_MODULES + "resources/default.conf": (b"config", 0o644),
            "usr/lib/kernel/install.d/50-mkosi.install": (b"kernel50", 0o755),
            "usr/lib/kernel/install.d/51-mkosi-addon.install": (b"kernel51", 0o755),
            payload.DIST_INFO + "entry_points.txt": (b"entrypoints", 0o644),
        }
        for name in payload.GENERATED_MAN_PAGES:
            self.files[payload.PACKAGE_MODULES + "resources/man/" + name] = (b"man", 0o644)
        for name in self.scripts:
            self.files[name] = (name.encode(), 0o755)

    def compare(self, files=None, source=None):
        return payload.compare_payload(
            self.source if source is None else source,
            make_deb(self.files if files is None else files),
            console_scripts=self.scripts,
            entry_points_sha256=sha256(b"entrypoints"),
        )

    def test_exact_source_and_generated_entry_points_are_diagnostic_only(self):
        report = self.compare()
        self.assertEqual(report["source_files_matched"], 2)
        self.assertEqual(report["python_modules_matched"], 1)
        self.assertEqual(set(report["generated_man_pages"]), payload.GENERATED_MAN_PAGES)

    def test_changed_or_missing_source_resource_rejected(self):
        cases = [
            ({**self.files, payload.PACKAGE_MODULES + "__main__.py": (b"changed", 0o644)},
             "implementation differs"),
            ({key: value for key, value in self.files.items()
              if key != payload.PACKAGE_MODULES + "resources/default.conf"},
             "source or generated man pages missing"),
            ({**self.files, payload.PACKAGE_MODULES + "new.py": (b"unreviewed", 0o644)},
             "unexpected packaged mkosi implementation"),
        ]
        for files, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.compare(files)

    def test_generated_man_page_is_neither_source_code_nor_executable(self):
        page = payload.PACKAGE_MODULES + "resources/man/mkosi.1"
        files = {**self.files, page: (b"man", 0o755)}
        with self.assertRaisesRegex(ValueError, "man page is executable"):
            self.compare(files)
        del files[page]
        with self.assertRaisesRegex(ValueError, "source or generated man pages missing"):
            self.compare(files)

    def test_entry_point_and_other_executable_paths_rejected(self):
        cases = [
            ({**self.files, "usr/bin/mkosi": (b"changed", 0o755)}, "console script differs"),
            ({**self.files, payload.DIST_INFO + "entry_points.txt": (b"changed", 0o644)},
             "entry points differ"),
            ({**self.files, "usr/share/doc/mkosi/unreviewed": (b"shell", 0o755)},
             "executable set differs"),
            ({**self.files, "usr/lib/python3/dist-packages/other.py": (b"import", 0o644)},
             "unexpected Python path"),
        ]
        for files, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.compare(files)

    def test_traversal_duplicate_link_and_missing_kernel_script_rejected(self):
        for name, value, message in (
            ("usr/bin/../bin/inject", (b"x", 0o644), "traversing"),
            (payload.PACKAGE_MODULES + "link.py", (("../../outside",), 0o777), "link or special"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                self.compare({**self.files, name: value})
        repeated = list(self.files.items()) + [(payload.PACKAGE_MODULES + "__main__.py", (b"main", 0o644))]
        with self.assertRaisesRegex(ValueError, "duplicate or traversing"):
            self.compare(repeated)
        files = {key: value for key, value in self.files.items()
                 if key != "usr/lib/kernel/install.d/50-mkosi.install"}
        with self.assertRaisesRegex(ValueError, "executable set differs"):
            self.compare(files)


if __name__ == "__main__":
    unittest.main()
