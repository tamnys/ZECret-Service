"""Synthetic input rejection and opt-in signed-cache account tests."""

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from test_stage_builder_toolchain import package
import build_guest_accounts as accounts


class AccountInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gcp-guest-accounts-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.project = self.root / "zrpc.conf"
        self.project.write_text("u zrpc-wrapper -\n")

    def source_inputs(self, *, extra=None, missing=None):
        identities = []
        for name, paths in accounts.REQUIRED.items():
            members = []
            for path in sorted(paths - ({missing} if missing else set())):
                content = b"signed synthetic input\n"
                if path.endswith("passwd.master"):
                    content = b"root:*:0:0:root:/root:/bin/bash\n"
                elif path.endswith("group.master"):
                    content = b"root:*:0:\n"
                members.append(("file", "./" + path, content,
                                0o755 if path == "usr/bin/systemd-sysusers" else 0o644))
            if extra is not None and name == "systemd":
                members.append(("file", "./" + extra, b"u unexpected -\n", 0o644))
            data = package(members)
            digest = hashlib.sha256(data).hexdigest()
            (self.archives / (digest + ".deb")).write_bytes(data)
            identities.append({"name": name, "version": "1", "architecture": "amd64",
                               "filename": f"pool/main/{name}/{name}_1_amd64.deb",
                               "size": len(data), "sha256": digest,
                               "path": f"debs/{digest}.deb"})
        return identities

    def read(self, **kwargs):
        identities = self.source_inputs(**kwargs)
        with (mock.patch.object(accounts.guest, "authenticated_packages",
                                return_value=identities),
              mock.patch.object(accounts, "PROJECT_SYSUSERS", self.project)):
            return accounts.authenticated_inputs(self.root, self.archives)

    def test_exact_signed_package_input_set_is_recorded(self):
        selected, receipt = self.read()
        self.assertEqual(len(selected), 12)
        self.assertEqual(len(receipt), 12)
        self.assertEqual(selected[("project", "usr/lib/sysusers.d/zrpc.conf")],
                         b"u zrpc-wrapper -\n")
        self.assertTrue(all("sha256" in item and "size" in item for item in receipt))

    def test_unreviewed_or_missing_sysusers_input_fails(self):
        with self.assertRaisesRegex(ValueError, "unreviewed package sysusers input"):
            self.read(extra="usr/lib/sysusers.d/extra.conf")
        with self.assertRaisesRegex(ValueError, "signed account inputs missing"):
            self.read(missing="usr/lib/sysusers.d/systemd-network.conf")

    def test_archive_and_project_mutation_fail(self):
        identities = self.source_inputs()
        archive = self.archives / (identities[0]["sha256"] + ".deb")
        original = archive.read_bytes()
        archive.write_bytes(original[:-1] + b"X")
        with (mock.patch.object(accounts.guest, "authenticated_packages",
                                return_value=identities),
              mock.patch.object(accounts, "PROJECT_SYSUSERS", self.project)):
            with self.assertRaisesRegex(ValueError, "reviewed lock"):
                accounts.authenticated_inputs(self.root, self.archives)
        archive.write_bytes(original)
        self.project.unlink()
        self.project.symlink_to("missing.conf")
        with (mock.patch.object(accounts.guest, "authenticated_packages",
                                return_value=identities),
              mock.patch.object(accounts, "PROJECT_SYSUSERS", self.project)):
            with self.assertRaisesRegex(ValueError, "project sysusers input missing"):
                accounts.authenticated_inputs(self.root, self.archives)

    def test_master_identity_check_rejects_changed_generated_id(self):
        self.assertEqual(accounts.master_ids(b"root:*:0:0:root:/root:/bin/bash\n",
                                             7, (2, 3)), {"root": (0, 0)})
        for data in (b"root:*:0:0:root:/root:/bin/bash\nroot:*:1:1::::\n",
                     b"root:x:0:0:root:/root:/bin/bash\n",
                     b"root:*:not-an-id:0:root:/root:/bin/bash\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                accounts.master_ids(data, 7, (2, 3))


class SignedCacheAccountTests(unittest.TestCase):
    def test_x86_64_signed_inputs_and_negative_account_mutations(self):
        metadata = os.environ.get("ZRPC_GUEST_METADATA")
        archives = os.environ.get("ZRPC_GUEST_ARCHIVES")
        if not metadata and not archives:
            self.skipTest("native signed-cache paths not supplied")
        if not metadata or not archives:
            self.fail("both native signed-cache paths are required")
        with tempfile.TemporaryDirectory(prefix="gcp-guest-account-native-",
                                         dir=os.environ.get("CODEX_TMP_DIR")) as temporary:
            workspace = Path(temporary)
            output = workspace / "accounts"
            receipt = accounts.build(Path(metadata), Path(archives), workspace, output)
            self.assertTrue(receipt["independent_generation_runs_matched"])
            self.assertFalse(receipt["installed_rootfs_accounts_compared"])
            self.assertFalse(receipt["private_mode_approved"])
            accounts.audit_rootfs.audit_accounts(output)
            verified = accounts.verify(Path(metadata), Path(archives), workspace, output)
            self.assertEqual(verified["status"],
                             "diagnostic-verified-guest-account-artifact-unbuilt")
            for index, relative in enumerate(("receipt.json", "etc/passwd")):
                with self.subTest(artifact_file=relative):
                    altered = workspace / f"artifact-mutation-{index}"
                    shutil.copytree(output, altered)
                    path = altered / relative
                    path.chmod(0o600)
                    path.write_bytes(path.read_bytes() + b"X")
                    path.chmod(0o400 if relative.endswith("shadow") else 0o444)
                    with self.assertRaisesRegex(ValueError, "account artifact bytes differ"):
                        accounts.verify(Path(metadata), Path(archives), workspace, altered)
            altered = workspace / "artifact-mode-mutation"
            shutil.copytree(output, altered)
            (altered / "etc/passwd").chmod(0o600)
            with self.assertRaisesRegex(ValueError, "account artifact file type or mode differs"):
                accounts.compare_artifact(altered, output)
            for index, (relative, old, new) in enumerate((
                ("passwd", b"systemd-network:x:991:991:", b"systemd-network:x:0:991:"),
                ("shadow", b"zrpc-wrapper:!*:", b"zrpc-wrapper:$6$unlocked:"),
                ("group", b"systemd-resolve:x:990:", b"systemd-resolve:x:0:"),
                ("group", b"messagebus:x:992:", b"messagebus:x:0:"),
                ("group", b"disk:x:6:\n", b"disk:x:6:zrpc-wrapper\n"),
                ("passwd", b"root:x:0:", b"root:x:1:"),
            )):
                with self.subTest(index=index):
                    altered = workspace / f"altered-{index}"
                    shutil.copytree(output, altered)
                    path = altered / "etc" / relative
                    contents = path.read_bytes()
                    self.assertIn(old, contents)
                    path.chmod(0o600)
                    path.write_bytes(contents.replace(old, new, 1))
                    with self.assertRaises(ValueError):
                        accounts.audit_rootfs.audit_accounts(altered)


if __name__ == "__main__":
    unittest.main()
