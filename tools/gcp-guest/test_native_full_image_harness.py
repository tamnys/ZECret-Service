"""Fail-closed local handoff checks; no mounts, keys, or images are created."""

from pathlib import Path
import hashlib
import socket
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import native_full_image_harness as harness
import prepare_guest_disk_basetree_profile as disk


def mount_record(target, options="rw"):
    escaped = str(target).replace("\\", "\\134").replace(" ", "\\040")
    return f"2 1 0:2 / {escaped} {options} - tmpfs tmpfs rw\n"


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


class BoundTreeTests(unittest.TestCase):
    def test_live_mountinfo_accepts_unmounted_bound_trees(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots = tuple(Path(temporary) / name for name in
                          ("source", "scratch", "staged"))
            for root in roots:
                root.mkdir()
            harness.checked_bound_mounts(*roots)

    def test_nested_and_root_mounts_are_rejected_for_each_bound_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots = tuple(Path(temporary) / name for name in
                          ("source", "scratch", "staged"))
            for root in roots:
                root.mkdir()
            baseline = mount_record(Path("/"))
            harness.checked_bound_mounts(*roots, mountinfo=baseline)
            for root in roots:
                for target in (root, root / "nested mount"):
                    with self.subTest(target=target):
                        with self.assertRaisesRegex(ValueError, "contains a mountpoint"):
                            harness.checked_bound_mounts(
                                *roots, mountinfo=baseline + mount_record(target))

    def test_malformed_mountinfo_fails_closed(self):
        roots = (Path("/workspace/source"), Path("/workspace/scratch"),
                 Path("/workspace/staged"))
        for contents in ("", "2 1 0:2 / / rw tmpfs tmpfs rw\n",
                         "x 1 0:2 / / rw - tmpfs tmpfs rw\n",
                         "2 1 0:2 / /\\777 rw - tmpfs tmpfs rw\n",
                         "2 1 0:2 / /../tmp rw - tmpfs tmpfs rw\n"):
            with self.subTest(contents=contents):
                with self.assertRaisesRegex(ValueError, "mountinfo"):
                    harness.checked_bound_mounts(*roots, mountinfo=contents)

    def test_socket_paths_are_rejected_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots = tuple(Path(temporary) / name for name in
                          ("source", "scratch", "staged"))
            for root in roots:
                (root / "nested").mkdir(parents=True)
                (root / "ordinary-link").symlink_to("nested", target_is_directory=True)
            harness.checked_bound_sockets(*roots)
            for root in roots:
                path = root / "nested" / "relay.sock"
                with self.subTest(root=root), socket.socket(socket.AF_UNIX) as endpoint:
                    endpoint.bind(str(path))
                    with self.assertRaisesRegex(ValueError, "AF_UNIX socket"):
                        harness.checked_bound_sockets(*roots)
                path.unlink()

    def test_socket_rejected_before_signer_or_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, scratch, staged = (root / name for name in
                                       ("source", "scratch", "staged"))
            for directory in (source, scratch, staged):
                directory.mkdir()
            args = types.SimpleNamespace(workspace=root, source=source, scratch=scratch,
                                         staged=staged, revision="a" * 40)
            socket_path = scratch / "host.sock"
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(socket_path))
                with (mock.patch.object(harness, "checked_layout",
                                        return_value=(source / ".codex-tmp",
                                                      scratch / "apt-scratch")),
                      mock.patch.object(harness, "checked_source"),
                      mock.patch.object(harness, "checked_namespace"),
                      mock.patch.object(harness, "checked_staged_builder"),
                      mock.patch.object(harness, "checked_signing_mount") as signer,
                      mock.patch.object(harness, "mount") as mounted):
                    with self.assertRaisesRegex(ValueError, "AF_UNIX socket"):
                        harness.build(args)
                    signer.assert_not_called()
                    mounted.assert_not_called()

    def test_mount_rejected_before_staged_inspection_or_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = types.SimpleNamespace(workspace=root, source=root / "source",
                                         scratch=root / "scratch", staged=root / "staged",
                                         revision="a" * 40)
            with (mock.patch.object(harness, "checked_layout",
                                    return_value=(args.source / ".codex-tmp",
                                                  args.scratch / "apt-scratch")),
                  mock.patch.object(harness, "checked_bound_mounts",
                                    side_effect=ValueError("bound builder tree contains a mountpoint")),
                  mock.patch.object(harness, "checked_source") as source,
                  mock.patch.object(harness, "checked_staged_builder") as builder,
                  mock.patch.object(harness, "mount") as mounted):
                with self.assertRaisesRegex(ValueError, "contains a mountpoint"):
                    harness.build(args)
                source.assert_not_called()
                builder.assert_not_called()
                mounted.assert_not_called()


class BindMountTests(unittest.TestCase):
    def test_mountinfo_policy_does_not_require_ismount(self):
        target = Path("/workspace/staged")
        with (mock.patch("os.path.ismount", side_effect=AssertionError("ismount used")),
              mock.patch("os.statvfs", return_value=types.SimpleNamespace(f_flag=0))):
            harness.checked_bind_mount(target, False, mountinfo=mount_record(target))
        with (mock.patch("os.path.ismount", side_effect=AssertionError("ismount used")),
              mock.patch("os.statvfs", return_value=types.SimpleNamespace(
                  f_flag=harness.os.ST_RDONLY))):
            harness.checked_bind_mount(target, True,
                                       mountinfo=mount_record(target, "ro"))

    def test_missing_stacked_or_wrong_policy_mount_is_rejected(self):
        target = Path("/workspace/staged")
        baseline = mount_record(Path("/"))
        cases = (
            baseline,
            baseline + mount_record(target / "nested"),
            baseline + mount_record(target) + mount_record(target),
            baseline + mount_record(target, "ro"),
            baseline + mount_record(target, "ro,rw"),
            baseline + mount_record(target, "rw") + "malformed\n",
        )
        with mock.patch("os.statvfs", return_value=types.SimpleNamespace(f_flag=0)):
            for contents in cases:
                with self.subTest(contents=contents):
                    with self.assertRaises(ValueError):
                        harness.checked_bind_mount(target, False, mountinfo=contents)

    def test_statvfs_disagreement_is_rejected(self):
        target = Path("/workspace/staged")
        with mock.patch("os.statvfs", return_value=types.SimpleNamespace(
                f_flag=harness.os.ST_RDONLY)):
            with self.assertRaisesRegex(ValueError, "write policy"):
                harness.checked_bind_mount(target, False,
                                           mountinfo=mount_record(target))


class StagedMountTargetTests(unittest.TestCase):
    def test_empty_used_targets_and_package_symlink_are_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            (staged / "workspace").mkdir()
            (staged / "usr").mkdir()
            (staged / "bin").symlink_to("usr", target_is_directory=True)
            harness.checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)

    def test_nonempty_or_redirected_used_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            target = staged / "workspace"
            target.mkdir()
            (target / "host.sock").write_text("unreviewed")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                harness.checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)
            (target / "host.sock").unlink()
            target.rmdir()
            target.symlink_to("usr", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "not a real directory"):
                harness.checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)

    def test_existing_mount_on_used_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, scratch, staged = (root / name for name in
                                       ("source", "scratch", "staged"))
            for directory in (source, scratch, staged, staged / "workspace"):
                directory.mkdir()
            harness.checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)
            with self.assertRaisesRegex(ValueError, "contains a mountpoint"):
                harness.checked_bound_mounts(
                    source, scratch, staged,
                    mountinfo=mount_record(staged / "workspace"))

    def test_unused_reserved_target_must_be_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            (staged / "zrpc-source").mkdir()
            with self.assertRaisesRegex(ValueError, "unused staged builder mount target"):
                harness.checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)
            with socket.socket(socket.AF_UNIX) as endpoint:
                endpoint.bind(str(staged / "zrpc-source" / "host.sock"))
                with self.assertRaisesRegex(ValueError, "unused staged builder mount target"):
                    harness.checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)


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
                  mock.patch.object(harness, "checked_bound_mounts"),
                  mock.patch.object(harness, "checked_bound_sockets"),
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
                MOUNTED_SCRATCH=disk.MOUNTED_SCRATCH,
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
                  mock.patch.object(harness, "checked_bound_mounts"),
                  mock.patch.object(harness, "checked_bound_sockets"),
                  mock.patch.object(harness.importlib, "import_module") as imported,
                  mock.patch.object(harness, "mount") as mounted,
                  mock.patch.object(harness, "run_in_builder") as executed):
                with self.assertRaisesRegex(ValueError, "preflight source bytes differ"):
                    harness.build(args)
                imported.assert_not_called()
                mounted.assert_not_called()
                executed.assert_not_called()


class PreflightTests(unittest.TestCase):
    def args(self, root):
        source, scratch, staged = (root / name for name in
                                   ("source", "scratch", "staged"))
        for directory in (source, scratch, staged):
            directory.mkdir()
        return types.SimpleNamespace(
            workspace=root, source=source, scratch=scratch, staged=staged,
            revision="a" * 40, user="user:[1]", mnt="mnt:[2]",
            net="net:[3]", pid="pid:[4]")

    def test_production_handoff_preflight_never_reads_key_or_runs_outer_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary))
            original_stat = Path.stat

            def mapped_root_stat(path, *arguments, **keywords):
                if path == args.scratch / "apt-scratch/tmp":
                    return types.SimpleNamespace(st_uid=0,
                                                 st_mode=stat.S_IFDIR | 0o700)
                return original_stat(path, *arguments, **keywords)

            with (mock.patch.object(harness, "checked_layout",
                                    return_value=(args.source / ".codex-tmp",
                                                  args.scratch / "apt-scratch")) as layout,
                  mock.patch.object(Path, "stat", mapped_root_stat),
                  mock.patch.object(harness, "checked_bound_mounts") as mounts,
                  mock.patch.object(harness, "checked_bound_sockets") as sockets,
                  mock.patch.object(harness, "checked_source") as source,
                  mock.patch.object(harness, "checked_namespace") as namespace,
                  mock.patch.object(harness, "checked_staged_builder") as builder,
                  mock.patch.object(harness, "checked_signing_mount") as signer,
                  mock.patch.object(harness, "bind") as bound,
                  mock.patch.object(harness, "mount") as mounted,
                  mock.patch.object(harness, "run_in_builder") as executed):
                report = harness.build(args, preflight_only=True)
            self.assertEqual(report["status"],
                             "diagnostic-production-harness-preflight-unapproved")
            self.assertEqual(report["source_commit"], args.revision)
            for field in ("signing_key_checked", "mkosi_executed",
                          "network_egress_excluded", "image_built",
                          "private_mode_approved"):
                self.assertFalse(report[field])
            self.assertTrue(report["signed_staged_builder_preflight_executed"])
            layout.assert_called_once_with(
                args.workspace, args.source, args.scratch, args.staged,
                input_files=(), input_dirs=harness.PREFLIGHT_INPUT_DIRS)
            self.assertEqual(mounts.call_count, 2)
            self.assertEqual(sockets.call_count, 2)
            source.assert_called_once_with(args.source, args.revision)
            namespace.assert_called_once()
            builder.assert_called_once_with(args.source, args.scratch, args.staged,
                                            args.revision)
            signer.assert_not_called()
            self.assertEqual(executed.call_count, 1)
            command = executed.call_args.args[1]
            self.assertEqual(command[:4], ["/usr/bin/python3", "-I", "-B", "-c"])
            self.assertIn("verify_execution_context", command[4])
            self.assertNotIn("outer_image_runner", " ".join(map(str, command)))
            self.assertFalse((args.staged / "run/zrpc-build-signing").exists())
            self.assertFalse(any(str(harness.SIGNING_MOUNT) in str(call)
                                 for call in bound.call_args_list))
            self.assertEqual(mounted.call_args_list[0],
                             mock.call("-t", "proc", "proc", args.staged / "proc"))
            self.assertEqual(len(mounted.call_args_list), 7)
            self.assertTrue(all(call.args[0] == "--bind"
                                for call in mounted.call_args_list[1:]))

    def test_changed_staged_builder_fails_before_mount_or_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary))
            with (mock.patch.object(harness, "checked_layout",
                                    return_value=(args.source / ".codex-tmp",
                                                  args.scratch / "apt-scratch")),
                  mock.patch.object(harness, "checked_bound_mounts"),
                  mock.patch.object(harness, "checked_bound_sockets"),
                  mock.patch.object(harness, "checked_source"),
                  mock.patch.object(harness, "checked_namespace"),
                  mock.patch.object(harness, "checked_staged_builder",
                                    side_effect=ValueError("staged builder file differs")),
                  mock.patch.object(harness, "checked_signing_mount") as signer,
                  mock.patch.object(harness, "bind") as bound,
                  mock.patch.object(harness, "mount") as mounted,
                  mock.patch.object(harness, "run_in_builder") as executed):
                with self.assertRaisesRegex(ValueError, "staged builder file differs"):
                    harness.build(args, preflight_only=True)
                signer.assert_not_called()
                bound.assert_not_called()
                mounted.assert_not_called()
                executed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
