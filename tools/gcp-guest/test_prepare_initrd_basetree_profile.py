"""Synthetic source-binding tests; they do not exercise mkosi or a boot."""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

import assemble_initrd_base_tree as initrd_input
import export_rust_inputs as rust_inputs
import fetch_guest_closure as guest
import preflight_initrd_build as preflight
import stage_builder_toolchain as builder
import prepare_initrd_basetree_profile as profile


REAL_BIND = profile.bind_selected_modules
REAL_SOURCE_CHECK = profile.verified_source_closure
profile.initrd_input = initrd_input
profile.rust_inputs = rust_inputs
profile.guest = guest
profile.preflight = preflight
profile.builder = builder


def synthetic_elf():
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    data[16:18] = b"\x02\x00"
    data[18:20] = b"\x3e\x00"
    return bytes(data)


class InitrdBaseTreeProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="initrd-profile-test-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.artifact = self.workspace / "artifact"
        self.artifact.mkdir()
        self.archive = self.artifact / profile.ARCHIVE
        self.archive.write_bytes(b"synthetic signed data-only tar")
        self.archive.chmod(0o600)
        self.bundle = self.workspace / "rust-bundle"
        (self.bundle / "artifacts").mkdir(parents=True)
        self.binary = synthetic_elf()
        self.mount = synthetic_elf() + b"signed mount bytes"
        self.mount_mode = 0o4755
        self.early_init = self.bundle / "artifacts/zrpc-gcp-early-init"
        self.early_init.write_bytes(self.binary)
        self.mount_identity = self.write_mount_package(self.mount, self.mount_mode)
        self.output = self.workspace / "profile"
        self.revision = "a" * 40
        self.preflight = {
            "status": "blocked",
            "reason": "pinned mkosi CPIO build and post-build audit have not been executed",
            "source_bound_archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "source_bound_manifest_sha256": "b" * 64,
            "mkosi_source_commit": "c" * 40,
            "rust_source_commit": self.revision,
            "rust_receipt_sha256": "d" * 64,
            "early_init_sha256": hashlib.sha256(self.binary).hexdigest(),
            "package_control_scripts_executed": False,
            "network_used_for_build": False,
            "mkosi_executed": False,
            "initrd_built": False,
            "boot_verified": False,
            "private_mode_approved": False,
        }
        patch_preflight = mock.patch.object(profile.preflight, "preflight",
                                            return_value=self.preflight)
        def committed_source(_revision, path):
            return (Path(profile.__file__).read_bytes() if path.endswith(
                "prepare_initrd_basetree_profile.py") else
                Path(profile.__file__).with_name(Path(path).name).read_bytes())
        patch_source = mock.patch.object(profile.rust_inputs, "git_bytes",
                                         side_effect=committed_source)
        patch_binding = mock.patch.object(profile, "bind_selected_modules",
                                          return_value=None)
        patch_bound_script = mock.patch.object(
            profile, "_BOUND_SCRIPT", Path(profile.__file__).read_bytes())
        patch_packages = mock.patch.object(profile.guest, "authenticated_packages",
                                           side_effect=lambda _: [self.mount_identity])
        patch_mount_sha = mock.patch.object(
            profile, "MOUNT_ELF_SHA256", hashlib.sha256(self.mount).hexdigest())
        patch_mount_size = mock.patch.object(profile, "MOUNT_ELF_SIZE", len(self.mount))
        patch_preflight.start()
        patch_source.start()
        patch_binding.start()
        patch_bound_script.start()
        patch_packages.start()
        patch_mount_sha.start()
        patch_mount_size.start()
        self.addCleanup(patch_preflight.stop)
        self.addCleanup(patch_source.stop)
        self.addCleanup(patch_binding.stop)
        self.addCleanup(patch_bound_script.stop)
        self.addCleanup(patch_packages.stop)
        self.addCleanup(patch_mount_sha.stop)
        self.addCleanup(patch_mount_size.stop)

    def write_mount_package(self, mount, mode):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w:xz") as archive:
            member = tarfile.TarInfo("./usr/bin/mount")
            member.uid = member.gid = 0
            member.mode = mode
            member.size = len(mount)
            archive.addfile(member, io.BytesIO(mount))
        data = payload.getvalue()
        header = (b"data.tar.xz/".ljust(16) + b"0".ljust(12) + b"0".ljust(6)
                  + b"0".ljust(6) + b"100644  " + str(len(data)).encode().ljust(10)
                  + b"`\n")
        package = b"!<arch>\n" + header + data + (b"\n" if len(data) & 1 else b"")
        digest = hashlib.sha256(package).hexdigest()
        (self.workspace / (digest + ".deb")).write_bytes(package)
        return {"name": "mount", "version": "synthetic", "architecture": "amd64",
                "filename": "pool/synthetic/mount.deb", "size": len(package),
                "sha256": digest, "path": "debs/" + digest + ".deb"}

    def prepare(self):
        return profile.prepare_profile(self.workspace, self.workspace,
                                       self.artifact, self.bundle, self.revision,
                                       self.output, self.workspace)

    def verify(self):
        return profile.verify_profile(self.workspace, self.workspace,
                                      self.artifact, self.bundle, self.revision,
                                      self.output, self.workspace)

    @staticmethod
    def rewrite(path, data):
        original_mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(original_mode)

    def test_profile_snapshots_archive_and_receipted_early_init_without_packages(self):
        first = self.prepare()
        self.assertEqual(first, self.verify())
        self.assertEqual(first["source_bound_archive_sha256"],
                         self.preflight["source_bound_archive_sha256"])
        for field in ("package_install_configured", "package_control_scripts_executed",
                      "mkosi_executed", "initrd_built", "selective_cpio_audit_passed",
                      "boot_verified", "private_mode_approved"):
            self.assertIs(first[field], False)
        config = (self.output / profile.CONFIG).read_text()
        for line in ("Distribution=custom", "Format=cpio", "Output=initrd",
                     "CompressOutput=zstd", "MakeInitrd=yes", "Packages=",
                     "WithNetwork=no", "CacheOnly=always",
                     "Incremental=no", "SourceDateEpoch=0"):
            self.assertIn(line + "\n", config)
        self.assertIn("BaseTrees=" + str(self.output / profile.INPUT) + "\n", config)
        self.assertIn("ExtraTrees=" + str(self.output / profile.INIT_TREE) + "\n", config)
        self.assertIn("FinalizeScripts=" + str(self.output / profile.SANITIZER)
                      + "," + str(self.output / profile.AUDIT) + "\n", config)
        for forbidden in ("PackageDirectories=", "PostInstallationScripts=",
                          "BuildScripts=", "Initrds="):
            self.assertNotIn(forbidden, config)
        self.assertEqual({item.name for item in self.output.iterdir()},
                         {"input", profile.INIT_TREE, profile.SANITIZER, profile.AUDIT,
                          profile.CONFIG, profile.MANIFEST})
        self.assertEqual((self.output / profile.INPUT).read_bytes(), self.archive.read_bytes())
        with tarfile.open(self.output / profile.INIT_TREE) as archive:
            members = archive.getmembers()
            self.assertEqual([member.name for member in members],
                             ["init", "usr/bin/mount"])
            self.assertEqual((members[0].uid, members[0].gid, members[0].mode),
                             (0, 0, 0o555))
            self.assertEqual(archive.extractfile(members[0]).read(), self.binary)
            self.assertEqual((members[1].uid, members[1].gid, members[1].mode),
                             (0, 0, self.mount_mode))
            self.assertEqual(archive.extractfile(members[1]).read(), self.mount)
        manifest = json.loads((self.output / profile.MANIFEST).read_bytes())
        self.assertEqual(manifest["early_init_sha256"],
                         hashlib.sha256(self.binary).hexdigest())
        self.assertEqual(manifest["mount_elf_sha256"],
                         hashlib.sha256(self.mount).hexdigest())
        self.assertEqual(manifest["mount_elf_size"], len(self.mount))
        self.assertEqual(manifest["source_bound_archive_size"], len(self.archive.read_bytes()))
        audit = (self.output / profile.AUDIT).read_bytes()
        self.assertIn(self.preflight["early_init_sha256"].encode(), audit)
        self.assertIn(hashlib.sha256(self.mount).hexdigest().encode(), audit)
        self.assertNotIn(b"__STAGED_INIT_SHA256__", audit)
        self.assertNotIn(b"__STAGED_MOUNT_SHA256__", audit)
        self.assertEqual(manifest["initrd_audit_sha256"],
                         hashlib.sha256(audit).hexdigest())
        sanitizer = (self.output / profile.SANITIZER).read_bytes()
        self.assertIn(hashlib.sha256(self.mount).hexdigest().encode(), sanitizer)
        self.assertIn(str(len(self.mount)).encode(), sanitizer)
        self.assertNotIn(b"__STAGED_MOUNT_SHA256__", sanitizer)
        self.assertNotIn(b"__STAGED_MOUNT_SIZE__", sanitizer)
        self.assertEqual(manifest["mount_sanitizer_sha256"],
                         hashlib.sha256(sanitizer).hexdigest())
        self.assertFalse(manifest["boot_verified"])
        self.assertFalse(manifest["private_mode_approved"])

    def test_bad_source_or_rust_receipt_never_creates_profile(self):
        with mock.patch.object(profile.preflight, "preflight",
                               side_effect=ValueError("signed source changed")):
            with self.assertRaisesRegex(ValueError, "signed source changed"):
                self.prepare()
        self.assertFalse(self.output.exists())
        self.preflight["private_mode_approved"] = True
        with self.assertRaisesRegex(ValueError, "changed non-accepting state"):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.preflight["private_mode_approved"] = False
        with mock.patch.object(profile.rust_inputs, "git_bytes", return_value=b"changed"):
            with self.assertRaisesRegex(ValueError, "sanitize-mount.py differs"):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_mount_archive_or_runtime_change_rejects_before_staging(self):
        archive = self.workspace / (self.mount_identity["sha256"] + ".deb")
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "builder archive size differs"):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.mount_identity = self.write_mount_package(self.mount, 0o755)
        with self.assertRaisesRegex(ValueError, "signed mount ELF differs"):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.mount_identity = self.write_mount_package(self.mount, self.mount_mode)
        without_mount_library = tuple(
            path for path in profile.initrd_input.ELF_RUNTIME
            if not path.endswith("/libmount.so.1"))
        with mock.patch.object(profile.initrd_input, "ELF_RUNTIME", without_mount_library):
            with self.assertRaisesRegex(ValueError, "runtime dependency absent"):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_changed_preflight_source_rejects_before_local_import(self):
        source = self.workspace / "source"
        source.mkdir()
        committed = {}
        for relative in profile.SOURCE_FILES:
            data = (profile.MODULE_DIR / Path(relative).name).read_bytes()
            (source / Path(relative).name).write_bytes(data)
            committed[relative] = data
        tampered = source / "preflight_initrd_build.py"
        tampered.write_bytes(tampered.read_bytes() + b"\n# forged signed result\n")

        def git_output(arguments):
            if arguments == ["rev-parse", "HEAD"]:
                return (self.revision + "\n").encode()
            if arguments[0] == "show":
                return committed[arguments[1].split(":", 1)[1]]
            raise AssertionError("unexpected Git operation")

        with (mock.patch.object(profile, "source_git_output", side_effect=git_output),
              mock.patch.object(profile, "verified_source_closure",
                                side_effect=lambda revision: REAL_SOURCE_CHECK(revision, source)),
              mock.patch.object(profile, "bind_selected_modules", side_effect=REAL_BIND),
              mock.patch.object(profile.preflight, "preflight",
                                side_effect=AssertionError("preflight ran before source binding"))):
            with self.assertRaisesRegex(ValueError, "preflight_initrd_build.py"):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_source_or_profile_mutation_rejects(self):
        self.prepare()
        self.preflight["source_bound_archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "archive differs"):
            self.verify()
        self.preflight["source_bound_archive_sha256"] = hashlib.sha256(
            self.archive.read_bytes()).hexdigest()
        self.preflight["early_init_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Rust /init changed"):
            self.verify()
        self.preflight["early_init_sha256"] = hashlib.sha256(self.binary).hexdigest()
        for path, replacement, message in (
            (self.output / profile.INPUT, b"changed", "archive differs"),
            (self.output / profile.INIT_TREE, b"changed", "/init tree differs"),
            (self.output / profile.SANITIZER, b"changed", "mount sanitizer differs"),
            (self.output / profile.AUDIT, b"changed", "audit differs"),
            (self.output / profile.CONFIG,
             (self.output / profile.CONFIG).read_bytes().replace(b"Packages=\n",
                                                               b"Packages=udev\n"),
             "(config differs|exceeds bound)"),
            (self.output / profile.MANIFEST,
             profile.initrd_input.canonical_bytes({
                 **json.loads((self.output / profile.MANIFEST).read_bytes()),
                 "boot_verified": True}),
             "(manifest differs|exceeds bound)"),
        ):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                self.rewrite(path, replacement)
                with self.assertRaisesRegex(ValueError, message):
                    self.verify()
                self.rewrite(path, original)
        self.assertIn("File exists", self.prepare_existing_error())
        self.assertEqual(self.verify()["status"], profile.STATUS)

    def prepare_existing_error(self):
        with self.assertRaises(FileExistsError) as error:
            self.prepare()
        return str(error.exception)

    def test_added_input_and_changed_rust_bytes_reject(self):
        self.prepare()
        (self.output / "mkosi.build").write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "unreviewed inputs"):
            self.verify()
        (self.output / "mkosi.build").unlink()
        self.early_init.write_bytes(self.binary[:-1] + b"X")
        with self.assertRaisesRegex(ValueError, "Rust /init changed"):
            self.verify()

    def test_build_rejects_before_ambient_builder_execution(self):
        self.prepare()
        with mock.patch.object(profile.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "reviewed runnable builder toolchain"):
                profile.build_cpio(self.workspace, self.workspace, self.artifact,
                                   self.bundle, self.revision, self.output,
                                   self.workspace)
            run.assert_not_called()
        self.assertFalse((self.workspace / "profile-output").exists())

    @staticmethod
    def newc(name, mode, content=b"", nlink=1, uid=0, gid=0):
        name_bytes = name.encode() + b"\0"
        fields = (1, mode, uid, gid, nlink, 0, len(content),
                  0, 0, 0, 0, len(name_bytes), 0)
        header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        lead = header + name_bytes
        return (lead + bytes(-len(lead) % 4) + content +
                bytes(-len(content) % 4))

    def test_post_cpio_reader_extracts_without_following_links(self):
        archive = (self.newc("etc", stat.S_IFDIR | 0o755, nlink=2)
                   + self.newc("etc/os-release", stat.S_IFLNK | 0o777,
                               b"../usr/lib/os-release")
                   + self.newc("init", stat.S_IFREG | 0o555, self.binary)
                   + self.newc("TRAILER!!!", 0))
        root = self.workspace / "extract"
        root.mkdir()
        inventory = {}
        self.assertEqual(profile.extract_cpio(io.BytesIO(archive), root,
                                              inventory=inventory), 3)
        self.assertEqual((root / "init").read_bytes(), self.binary)
        self.assertEqual((root / "etc/os-release").readlink(),
                         Path("../usr/lib/os-release"))
        self.assertEqual(inventory, {
            "etc": {"kind": "directory", "uid": 0, "gid": 0, "mode": 0o755},
            "etc/os-release": {"kind": "symlink", "uid": 0, "gid": 0,
                               "mode": 0o777, "target": "../usr/lib/os-release"},
            "init": {"kind": "file", "uid": 0, "gid": 0, "mode": 0o555,
                     "size": len(self.binary),
                     "sha256": hashlib.sha256(self.binary).hexdigest()},
        })
        for changed in (
            self.newc("../escape", stat.S_IFREG | 0o644, b"x") +
            self.newc("TRAILER!!!", 0),
            self.newc("init", stat.S_IFREG | 0o555, self.binary) +
            self.newc("init", stat.S_IFREG | 0o555, self.binary) +
            self.newc("TRAILER!!!", 0),
            self.newc("init", stat.S_IFREG | 0o555, self.binary) +
            self.newc("TRAILER!!!", 0) + b"payload",
        ):
            changed_root = self.workspace / ("changed-" + str(len(list(
                self.workspace.glob("changed-*")))))
            changed_root.mkdir()
            with self.assertRaises(ValueError):
                profile.extract_cpio(io.BytesIO(changed), changed_root)

    def test_post_cpio_reader_names_unsafe_member_without_accepting_it(self):
        cases = (
            ("etc/shadow\ncontrol", stat.S_IFREG | 0o640, 1, 0, 42,
             "nonroot_gid", "path='etc/shadow\\ncontrol'"),
            ("usr/bin/hardlink", stat.S_IFREG | 0o755, 2, 0, 0,
             "non_directory_hardlink", "path='usr/bin/hardlink'"),
        )
        for index, (name, mode, nlink, uid, gid, violation, escaped_name) in enumerate(cases):
            with self.subTest(name=name):
                root = self.workspace / f"unsafe-{index}"
                root.mkdir()
                archive = (self.newc(name, mode, nlink=nlink, uid=uid, gid=gid)
                           + self.newc("TRAILER!!!", 0))
                with self.assertRaisesRegex(ValueError, "member path or metadata is unsafe") as error:
                    profile.extract_cpio(io.BytesIO(archive), root)
                message = str(error.exception)
                self.assertIn(escaped_name, message)
                self.assertIn(f"violations={violation}", message)
                self.assertIn(f"uid={uid} gid={gid} nlink={nlink} mode={mode:#o}", message)
                self.assertNotIn("\n", message)


if __name__ == "__main__":
    unittest.main()
