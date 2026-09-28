"""Fail-closed local handoff checks; no mounts, keys, or images are created."""

from pathlib import Path
import hashlib
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import native_full_image_harness as harness
import prepare_guest_disk_basetree_profile as disk


class LayoutTests(unittest.TestCase):
    def test_rejects_source_outside_workspace_before_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            source = root / "source"
            source.mkdir()
            scratch = workspace / "scratch"
            scratch.mkdir()
            staged = workspace / "staged"
            staged.mkdir()
            args = types.SimpleNamespace(workspace=workspace, source=source,
                                         scratch=scratch, staged=staged,
                                         revision="a" * 40)
            with mock.patch.object(harness, "mount") as mounted:
                with self.assertRaisesRegex(ValueError, "separate workspace siblings"):
                    harness.build(args)
                mounted.assert_not_called()

    def test_rejects_scratch_outside_workspace_before_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            source = workspace / "source"
            source.mkdir()
            staged = workspace / "staged"
            staged.mkdir()
            scratch = root / "scratch"
            scratch.mkdir()
            args = types.SimpleNamespace(workspace=workspace, source=source,
                                         scratch=scratch, staged=staged,
                                         revision="a" * 40)
            with mock.patch.object(harness, "mount") as mounted:
                with self.assertRaisesRegex(ValueError, "separate workspace siblings"):
                    harness.build(args)
                mounted.assert_not_called()

    def test_rejects_source_scratch_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            staged = root / "staged"
            source.mkdir()
            staged.mkdir()
            with self.assertRaisesRegex(ValueError, "must be disjoint"):
                harness.checked_layout(root, source, source, staged)


class SigningTests(unittest.TestCase):
    def test_missing_signing_mount_blocks_before_any_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = types.SimpleNamespace(workspace=root, source=root / "source",
                                         scratch=root / "scratch", staged=root / "staged",
                                         revision="a" * 40)
            with (mock.patch.object(harness, "checked_layout",
                                    return_value=(root / "overlay", root / "apt")),
                  mock.patch.object(harness, "checked_source"),
                  mock.patch.object(harness, "checked_namespace"),
                  mock.patch.object(harness, "checked_staged_builder"),
                  mock.patch.object(harness, "SIGNING_MOUNT", root / "missing"),
                  mock.patch.object(harness, "mount") as mounted):
                with self.assertRaisesRegex(ValueError, "fixed signing mount is missing"):
                    harness.build(args)
                mounted.assert_not_called()

    def test_non_tmpfs_signing_mount_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            mount = Path(temporary)
            original_stat = Path.stat

            def fake_stat(path, *args, **kwargs):
                if path == mount:
                    return types.SimpleNamespace(st_uid=0,
                                                 st_mode=stat.S_IFDIR | 0o700)
                return original_stat(path, *args, **kwargs)

            mountinfo = f"1 0 0:1 / {mount} rw - ext4 /dev/fake rw\n"
            with (mock.patch.object(harness, "SIGNING_MOUNT", mount),
                  mock.patch("os.path.ismount", return_value=True),
                  mock.patch.object(Path, "stat", fake_stat)):
                with self.assertRaisesRegex(ValueError, "exact tmpfs mount"):
                    harness.checked_signing_mount(mount, mountinfo)

    def test_permissive_signing_mount_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            mount = Path(temporary)
            original_stat = Path.stat

            def fake_stat(path, *args, **kwargs):
                if path == mount:
                    return types.SimpleNamespace(st_uid=0,
                                                 st_mode=stat.S_IFDIR | 0o755)
                return original_stat(path, *args, **kwargs)

            with (mock.patch.object(harness, "SIGNING_MOUNT", mount),
                  mock.patch("os.path.ismount", return_value=True),
                  mock.patch.object(Path, "stat", fake_stat)):
                with self.assertRaisesRegex(ValueError, "root-owned private"):
                    harness.checked_signing_mount(mount)


class StagedBuilderTests(unittest.TestCase):
    def test_poisoned_python_rejected_before_chroot_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            scratch = root / "scratch"
            scratch.mkdir()
            (scratch / "builder-archives").mkdir(mode=0o700)
            staged = root / "staged"
            (staged / "usr/bin").mkdir(parents=True)
            python = staged / "usr/bin/python3"
            python.write_bytes(b"poison!")
            python.chmod(0o755)
            expected = {
                "usr": {"kind": "directory", "staged_mode": 0o755},
                "usr/bin": {"kind": "directory", "staged_mode": 0o755},
                "usr/bin/python3": {"kind": "file", "staged_mode": 0o755,
                                    "size": 7,
                                    "sha256": hashlib.sha256(b"trusted").hexdigest()},
            }
            lock = {"snapshot": "https://snapshot.debian.org/",
                    "packages": [{"name": "python3"}]}
            manifest = {"schema_version": 1, "status": disk.builder.STATUS,
                        "builder_closure_lock_sha256": "a" * 64,
                        "snapshot": lock["snapshot"], "package_count": 1,
                        "entries": [expected[path] for path in sorted(expected)],
                        "signed_snapshot_rechecked": False,
                        "package_scripts_executed": False,
                        "runtime_execution_verified": False,
                        "complete_builder_toolchain": False,
                        "image_built": False, "private_mode_approved": False}
            (staged / disk.builder.MANIFEST).write_bytes(
                disk.root_profile.canonical_bytes(manifest))
            (staged / disk.builder.MANIFEST).chmod(0o600)
            fake_builder = types.SimpleNamespace(
                DIRECTORY_FLAGS=disk.builder.DIRECTORY_FLAGS,
                MANIFEST=disk.builder.MANIFEST, STATUS=disk.builder.STATUS,
                locked_archive=lambda entry, descriptor: b"reviewed",
                payload_entries=lambda packages: ({}, expected))
            fake_disk = types.SimpleNamespace(
                builder_fetch=types.SimpleNamespace(
                    reviewed_lock=lambda path: (lock, "a" * 64, None)),
                builder_closure=types.SimpleNamespace(LOCK=Path("reviewed-lock")),
                guest=disk.guest, builder=fake_builder,
                root_profile=disk.root_profile,
                inspect_staged_builder=disk.inspect_staged_builder)
            args = types.SimpleNamespace(workspace=root, source=source,
                                         scratch=scratch, staged=staged,
                                         revision="a" * 40)
            with (mock.patch.object(harness, "checked_layout",
                                    return_value=(source / ".codex-tmp", scratch / "apt")),
                  mock.patch.object(harness, "checked_source"),
                  mock.patch.object(harness, "checked_namespace"),
                  mock.patch.object(harness, "checked_preimport_tree"),
                  mock.patch.object(harness.importlib, "import_module",
                                    return_value=fake_disk),
                  mock.patch.object(harness, "checked_signing_mount") as signing,
                  mock.patch.object(harness, "mount") as mounted,
                  mock.patch.object(harness, "run_in_builder") as executed):
                with self.assertRaisesRegex(ValueError, "staged builder file differs"):
                    harness.build(args)
                signing.assert_not_called()
                mounted.assert_not_called()
                executed.assert_not_called()

    def test_assume_unchanged_source_edit_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            module = source / "tools/gcp-guest/local_module.py"
            module.parent.mkdir(parents=True)
            module.write_text("VALUE = 1\n")
            locks = [source / "deploy/gcp/builder-closure.lock.json",
                     source / "deploy/gcp/builder-direct-packages.lock.json"]
            for lock in locks:
                lock.parent.mkdir(parents=True, exist_ok=True)
                lock.write_text("{}\n")

            def git(*arguments):
                return subprocess.run(
                    ["/usr/bin/git", "-C", str(source), *arguments], check=True,
                    capture_output=True).stdout.strip()

            git("init", "-q")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-q", "-m", "synthetic source")
            revision = git("rev-parse", "HEAD").decode()
            module.write_text("VALUE = 2\n")
            git("update-index", "--assume-unchanged", "tools/gcp-guest/local_module.py")
            self.assertEqual(git("status", "--porcelain"), b"")
            args = types.SimpleNamespace(workspace=root, source=source,
                                         scratch=root / "scratch", staged=root / "staged",
                                         revision=revision)
            with (mock.patch.object(harness, "checked_layout",
                                    return_value=(source / ".codex-tmp", root / "apt")),
                  mock.patch.object(harness, "checked_source"),
                  mock.patch.object(harness, "checked_namespace"),
                  mock.patch.object(harness.importlib, "import_module") as imported,
                  mock.patch.object(harness, "mount") as mounted,
                  mock.patch.object(harness, "run_in_builder") as executed):
                with self.assertRaisesRegex(ValueError, "preflight source bytes differ"):
                    harness.build(args)
                imported.assert_not_called()
                mounted.assert_not_called()
                executed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
