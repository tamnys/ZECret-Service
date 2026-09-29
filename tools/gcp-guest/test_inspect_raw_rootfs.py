"""Synthetic rootfs inspector negatives; no fixture is a boot or release."""

from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import fetch_guest_closure as guest
import inspect_raw_rootfs as rootfs


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RawRootfsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-raw-rootfs-",
                                                 dir=os.environ.get("CODEX_TMP_DIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.entries = {}
        for relative in sorted(rootfs.REQUIRED_FILES):
            parent = Path(relative).parent
            for ancestor in reversed((parent, *parent.parents)):
                if ancestor == Path("."):
                    continue
                path = self.stage / "rootfs" / ancestor
                path.mkdir(parents=True, exist_ok=True)
                self.entries["rootfs/" + ancestor.as_posix()] = {
                    "type": "directory", "mode": path.stat().st_mode & 0o777}
            path = self.stage / "rootfs" / relative
            data = ((Path(__file__).resolve().parents[2] / "deploy/gcp/guest/rootfs" / relative).read_bytes()
                    if relative in rootfs.ACCOUNT_FILES
                    else b"" if relative == rootfs.MACHINE_ID_FILE
                    else ("approved " + relative + "\n").encode())
            path.write_bytes(data)
            path.chmod(rootfs.ACCOUNT_FILES[relative][2] if relative in rootfs.ACCOUNT_FILES
                       else 0o555 if relative.startswith("usr/lib/zrpc/") else 0o644)
            self.entries["rootfs/" + relative] = {
                "type": "file", "mode": path.stat().st_mode & 0o777,
                "sha256": digest(data)}
        self.entries["rootfs"] = {"type": "directory",
                                  "mode": (self.stage / "rootfs").stat().st_mode & 0o777}
        link = self.stage / "rootfs/etc/systemd/system/default.target"
        link.parent.mkdir(parents=True)
        self.entries["rootfs/etc/systemd"] = {
            "type": "directory", "mode": link.parent.parent.stat().st_mode & 0o777}
        self.entries["rootfs/etc/systemd/system"] = {
            "type": "directory", "mode": link.parent.stat().st_mode & 0o777}
        link.symlink_to("/usr/lib/systemd/system/zrpc.target")
        self.entries["rootfs/etc/systemd/system/default.target"] = {
            "type": "symlink", "target": "/usr/lib/systemd/system/zrpc.target"}
        self.manifest = {"status": "staged-unbuilt-unapproved",
                         "image_built": False, "private_mode_approved": False,
                         "entries": self.entries}

    def test_all_staged_overlay_entries_are_selected(self):
        selected = rootfs.checked_overlay(self.manifest, self.stage)
        self.assertEqual(len(selected), len(self.entries) - 1)
        self.assertEqual(selected["etc/systemd/system/default.target"]["target"],
                         "/usr/lib/systemd/system/zrpc.target")
        self.assertEqual(selected["usr/lib/zrpc/zebrad"]["sha256"],
                         self.entries["rootfs/usr/lib/zrpc/zebrad"]["sha256"])
        self.assertFalse(self.manifest["private_mode_approved"])

    def test_staged_change_missing_critical_and_redirect_reject(self):
        changed = self.stage / "rootfs/etc/zrpc/zebra.toml"
        changed.write_bytes(b"changed settings\n")
        with self.assertRaisesRegex(ValueError, "staged rootfs file bytes differ"):
            rootfs.checked_overlay(self.manifest, self.stage)
        changed.write_bytes(b"approved etc/zrpc/zebra.toml\n")
        absent = self.entries.pop("rootfs/usr/lib/zrpc/zebrad")
        with self.assertRaisesRegex(ValueError, "critical staged rootfs"):
            rootfs.checked_overlay(self.manifest, self.stage)
        self.entries["rootfs/usr/lib/zrpc/zebrad"] = absent
        symlink = self.stage / "rootfs/etc/systemd/system/default.target"
        symlink.unlink()
        symlink.symlink_to("/dev/null")
        with self.assertRaisesRegex(ValueError, "staged rootfs symlink differs"):
            rootfs.checked_overlay(self.manifest, self.stage)

    def test_changed_connection_helper_is_rejected_by_image_inventory(self):
        helper = self.stage / "rootfs/usr/lib/zrpc/zrpc-gcp-disk-id"
        helper.chmod(0o755)
        helper.write_bytes(b"tampered ELF")
        helper.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "staged rootfs file bytes differ"):
            rootfs.checked_overlay(self.manifest, self.stage)

    def test_inode_parser_requires_pinned_reader_and_unambiguous_type(self):
        record = (b"Inode: 20   Type: regular    Mode:  0555   Flags: 0x80000\n"
                  b"User: 0   Group: 0   Project: 0   Size: 9\n")
        with mock.patch.object(rootfs.subprocess, "run", return_value=
                types.SimpleNamespace(returncode=0, stderr=rootfs.READER_BANNER,
                                      stdout=record)):
            parsed = rootfs.run_stat(Path("/synthetic/debugfs"), self.root, "usr/lib/zrpc/zebrad")
        self.assertEqual(parsed["type"], "regular")
        self.assertEqual((parsed["mode"], parsed["size"]), (0o555, 9))
        self.assertEqual((parsed["uid"], parsed["gid"]), (0, 0))
        for stderr, stdout in ((rootfs.READER_BANNER + b"error\n", record),
                               (rootfs.READER_BANNER, record + record)):
            with mock.patch.object(rootfs.subprocess, "run", return_value=
                    types.SimpleNamespace(returncode=0, stderr=stderr, stdout=stdout)):
                with self.assertRaises(ValueError):
                    rootfs.run_stat(Path("/synthetic/debugfs"), self.root,
                                    "usr/lib/zrpc/zebrad")

    def test_signed_debugfs_clock_mtime_requires_exact_raw_fields(self):
        epoch = guest.SIGNED_RELEASE_EPOCH
        header = (b"Inode: 20   Type: regular    Mode:  0644   Flags: 0x80000\n"
                  b"User: 0   Group: 0   Project: 0   Size: 0\n")
        def read(record):
            with mock.patch.object(rootfs.subprocess, "run", return_value=
                    types.SimpleNamespace(returncode=0, stderr=rootfs.READER_BANNER,
                                          stdout=record)):
                return rootfs.run_stat(Path("/synthetic/debugfs"), self.root,
                                       rootfs.generated_usr.CLOCK_EPOCH,
                                       require_mtime=True)
        for suffix in ("", ":00000000"):
            with self.subTest(suffix=suffix):
                line = f" mtime: 0x{epoch:08x}{suffix} -- synthetic date\n".encode()
                self.assertEqual(read(header + line)["mtime_ns"],
                                 epoch * 1_000_000_000)
        nanos = f" mtime: 0x{epoch:08x}:00000004 -- synthetic date\n".encode()
        self.assertEqual(read(header + nanos)["mtime_ns"],
                         epoch * 1_000_000_000 + 1)
        for tail in (b"", nanos + nanos,
                     b" mtime: malformed\n",
                     f" mtime: 0x{epoch:08x}:ee6b2800 -- synthetic date\n".encode()):
            with self.subTest(tail=tail):
                with self.assertRaisesRegex(ValueError, "clock mtime"):
                    read(header + tail)

    def test_superblock_metadata_requires_three_unambiguous_valid_fields(self):
        lines = ["Filesystem UUID:          2a73c4e5-1b2c-4d5e-8f90-a1b2c3d4e5f6",
                 "Filesystem created:       Mon Sep 28 12:34:56 2026",
                 "Directory Hash Seed:      3b84d5f6-2c3d-4e5f-901a-b2c3d4e5f607"]
        expected = {"filesystem_uuid": "2a73c4e5-1b2c-4d5e-8f90-a1b2c3d4e5f6",
                    "filesystem_created_utc": "Mon Sep 28 12:34:56 2026",
                    "directory_hash_seed": "3b84d5f6-2c3d-4e5f-901a-b2c3d4e5f607"}

        def report(output, *, stderr=rootfs.READER_BANNER, returncode=0):
            return types.SimpleNamespace(returncode=returncode, stderr=stderr,
                                         stdout=(output + "\n").encode("ascii"))

        with mock.patch.object(rootfs.subprocess, "run", return_value=report("\n".join(lines))) as run:
            self.assertEqual(rootfs.run_superblock_stats(
                Path("/synthetic/debugfs"), self.root), expected)
            self.assertEqual(run.call_args.args[0],
                             ["/synthetic/debugfs", "-R", "stats -h", str(self.root)])
            self.assertEqual(run.call_args.kwargs["env"]["TZ"], "UTC")
        malformed = ("\n".join(lines[:-1]),
                     "\n".join(lines + [lines[0]]),
                     "\n".join(lines).replace(expected["filesystem_uuid"], "not-a-uuid"),
                     "\n".join(lines).replace(expected["directory_hash_seed"], "<>"),
                     "\n".join(lines).replace("Sep 28", "Feb 30"),
                     "\n".join(lines).replace("Mon Sep", "Tue Sep"))
        for output in malformed:
            with self.subTest(output=output), \
                    mock.patch.object(rootfs.subprocess, "run", return_value=report(output)):
                with self.assertRaises(ValueError):
                    rootfs.run_superblock_stats(Path("/synthetic/debugfs"), self.root)
        for result in (report("\n".join(lines), stderr=rootfs.READER_BANNER + b"error\n"),
                       report("\n".join(lines), returncode=1)):
            with mock.patch.object(rootfs.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(ValueError, "could not read rootfs superblock"):
                    rootfs.run_superblock_stats(Path("/synthetic/debugfs"), self.root)

    def test_inspection_reports_metadata_without_approving_image(self):
        root = self.root / "copied-root.img"
        root.write_bytes(b"synthetic ext4 placeholder")
        raw_sha256 = "a" * 64
        layout = {"status": "diagnostic-gpt-only-unapproved",
                  "raw_disk_sha256": raw_sha256, "raw_disk_bytes": 8192}
        verified = {"status": "diagnostic-raw-root-verity-unapproved",
                    "raw_disk_sha256": raw_sha256, "raw_disk_bytes": 8192,
                    "root_partition_guid": "root-guid",
                    "root_partition_bytes": root.stat().st_size,
                    "verity_userspace_verified": True, "private_mode_approved": False}
        metadata = {"filesystem_uuid": "2a73c4e5-1b2c-4d5e-8f90-a1b2c3d4e5f6",
                    "filesystem_created_utc": "Mon Sep 28 12:34:56 2026",
                    "directory_hash_seed": "3b84d5f6-2c3d-4e5f-901a-b2c3d4e5f607"}
        inventory = {"": {"inode": 2, "type": "directory", "mode": 0o755,
                          "uid": 0, "gid": 0, "size": None}}
        package_report = {"components_checked": {"regular": 1, "directory": 1,
                                                 "symlink": 0, "removed": 1}}
        with mock.patch.object(rootfs.platform, "system", return_value="Linux"), \
                mock.patch.object(rootfs.platform, "machine", return_value="x86_64"), \
                mock.patch.object(rootfs.verity.esp, "workspace_scratch", return_value=self.root), \
                mock.patch.object(rootfs, "checked_overlay", return_value={}), \
                mock.patch.object(rootfs, "authenticated_reader_toolchain",
                                  return_value=(b"ELF", b"loader", (), "b" * 64)), \
                mock.patch.object(rootfs, "checked_reader", return_value="c" * 64), \
                mock.patch.object(rootfs.verity, "partition_images", return_value={
                    "root-x86-64": (root, root.stat().st_size, "root-guid")}), \
                mock.patch.object(rootfs, "sealed_reader_runtime",
                                  return_value=nullcontext((
                                      ("/signed/loader", "/synthetic/debugfs"),
                                      (7, 8), {"LC_ALL": "C"}))), \
                mock.patch.object(rootfs, "inspect_entries", return_value={
                    "file": 0, "directory": 0, "symlink": 0}), \
                mock.patch.object(rootfs.forbidden, "inspect", return_value=inventory) as surfaces, \
                mock.patch.object(rootfs.components, "inspect_authenticated_components",
                                  return_value=package_report) as components, \
                mock.patch.object(rootfs, "run_superblock_stats", return_value=metadata) as stats:
            result = rootfs.inspect(self.root / "disk.raw", raw_sha256, 8192, 512,
                                    layout, verified, self.root / "InRelease",
                                    self.root / "Packages.xz", self.root / "archives",
                                    self.stage, self.manifest, self.root)
        self.assertEqual(stats.call_args.args[1], root)
        self.assertEqual(stats.call_args.kwargs["pass_fds"], (7, 8))
        self.assertEqual(surfaces.call_args.args[:2],
                         (("/signed/loader", "/synthetic/debugfs"), root))
        self.assertEqual(surfaces.call_args.kwargs["pass_fds"], (7, 8))
        self.assertEqual(components.call_args.args[:3],
                         (self.root, self.stage / "packages", {}))
        self.assertEqual(components.call_args.kwargs["workspace"].parent, self.root)
        self.assertTrue(components.call_args.kwargs["workspace"].name.startswith(
            "zrpc-raw-rootfs-"))
        self.assertEqual({key: result[key] for key in metadata}, metadata)
        self.assertEqual(result["root_partition_sha256"], digest(root.read_bytes()))
        self.assertEqual(result["status"], rootfs.STATUS)
        self.assertEqual(result["raw_root_inventory_entries"], 1)
        self.assertEqual(result["authenticated_package_components_checked"],
                         package_report["components_checked"])
        self.assertIs(result["forbidden_surfaces_checked"], True)
        self.assertIs(result["reader_initial_elf_objects_checked"], True)
        self.assertIs(result["reader_dynamic_runtime_independently_sealed"], False)
        self.assertIs(result["boot_verified"], False)
        self.assertIs(result["private_mode_approved"], False)

    def test_changed_raw_bytes_or_symlink_fail_before_diagnostic_result(self):
        selected = rootfs.checked_overlay(self.manifest, self.stage)
        image = self.root / "copied-root.img"
        image.write_bytes(b"synthetic ext4 placeholder")
        file = "etc/zrpc/zebra.toml"
        expected = selected[file]
        poisoned = b"X" * expected["size"]
        fake = self.root / "debugfs"
        fake.write_text("#!/usr/bin/python3\n"
                        "import sys\n"
                        "sys.stderr.buffer.write(b'debugfs 1.47.2 (1-Jan-2025)\\n')\n"
                        f"sys.stdout.buffer.write({poisoned!r})\n")
        fake.chmod(0o755)
        self.assertNotEqual(rootfs.run_cat(fake, image, file,
                                           expected["size"], self.root),
                            expected["sha256"])
        critical = {name: selected[name] for name in ("etc", "etc/zrpc", file)}
        with mock.patch.object(rootfs, "run_stat", side_effect=lambda _r, _i, name, **_kw: {
                "type": "regular" if critical[name]["type"] == "file" else "directory",
                "mode": critical[name].get("mode", 0o777),
                "size": critical[name].get("size", 0),
                "link": None}):
            with self.assertRaisesRegex(ValueError, "raw rootfs file bytes differ"):
                rootfs.inspect_entries(fake, image, critical, self.root)
        with mock.patch.object(rootfs, "run_stat", side_effect=lambda _r, _i, name, **_kw: {
                "type": "symlink" if name == "etc" else
                        "regular" if selected[name]["type"] == "file" else
                        "directory" if selected[name]["type"] == "directory" else "symlink",
                "mode": selected[name].get("mode", 0o777),
                "size": selected[name].get("size", 0),
                "link": selected[name].get("target")}), \
                mock.patch.object(rootfs, "run_cat", side_effect=AssertionError(
                    "redirected parent must reject before extraction")):
            with self.assertRaisesRegex(ValueError, "raw rootfs entry type differs"):
                rootfs.inspect_entries(fake, image, selected, self.root)
        link = "etc/systemd/system/default.target"
        with mock.patch.object(rootfs, "run_stat", return_value={
                "type": "symlink", "mode": 0o777, "size": 9, "link": "/dev/null"}):
            with self.assertRaisesRegex(ValueError, "raw rootfs symlink target differs"):
                rootfs.inspect_entries(fake, image, {link: selected[link]}, self.root)

    def test_final_account_bytes_modes_and_root_owner_are_required(self):
        selected = rootfs.checked_overlay(self.manifest, self.stage)
        file = "etc/shadow"
        account = selected[file]
        final = {"type": "regular", "mode": 0o000, "uid": 0, "gid": 0,
                 "size": account["size"], "link": None}
        with mock.patch.object(rootfs, "run_stat", return_value=final), \
                mock.patch.object(rootfs, "run_cat", return_value=account["sha256"]):
            self.assertEqual(rootfs.inspect_entries(None, None, {file: account}, self.root),
                             {"file": 1, "directory": 0, "symlink": 0})
        for change in ({"mode": 0o400}, {"uid": 1000}, {"gid": 1000}):
            with self.subTest(change=change), \
                    mock.patch.object(rootfs, "run_stat", return_value={**final, **change}), \
                    mock.patch.object(rootfs, "run_cat", side_effect=AssertionError(
                        "account metadata must reject before extraction")):
                with self.assertRaisesRegex(ValueError, "raw rootfs file metadata differs"):
                    rootfs.inspect_entries(None, None, {file: account}, self.root)
        with mock.patch.object(rootfs, "run_stat", return_value=final), \
                mock.patch.object(rootfs, "run_cat", return_value="0" * 64):
            with self.assertRaisesRegex(ValueError, "raw rootfs file bytes differ"):
                rootfs.inspect_entries(None, None, {file: account}, self.root)

    def test_machine_id_cannot_be_replaced_or_owned_by_guest_service(self):
        relative = rootfs.MACHINE_ID_FILE
        path = self.stage / "rootfs" / relative
        source = self.entries["rootfs/" + relative]
        self.assertEqual(rootfs.checked_overlay(self.manifest, self.stage)[relative]["size"], 0)
        path.write_bytes(b"uninitialized\n")
        source["sha256"] = digest(path.read_bytes())
        with self.assertRaisesRegex(ValueError, "generic read-only machine-id differs"):
            rootfs.checked_overlay(self.manifest, self.stage)
        path.write_bytes(b"")
        source["sha256"] = rootfs.EMPTY_SHA256
        selected = rootfs.checked_overlay(self.manifest, self.stage)[relative]
        observed = {"type": "regular", "mode": 0o644, "uid": 0, "gid": 0,
                    "size": 0, "link": None}
        with mock.patch.object(rootfs, "run_stat", return_value=observed), \
                mock.patch.object(rootfs, "run_cat", return_value=rootfs.EMPTY_SHA256):
            self.assertEqual(rootfs.inspect_entries(None, None, {relative: selected}, self.root),
                             {"file": 1, "directory": 0, "symlink": 0})
        with mock.patch.object(rootfs, "run_stat", return_value={**observed, "uid": 101}), \
                mock.patch.object(rootfs, "run_cat", side_effect=AssertionError(
                    "machine-id owner must reject before extraction")):
            with self.assertRaisesRegex(ValueError, "raw rootfs file metadata differs"):
                rootfs.inspect_entries(None, None, {relative: selected}, self.root)

    def test_long_overlay_symlink_uses_bounded_inode_target_reader(self):
        relative = "etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service"
        target = "/usr/lib/systemd/system/systemd-networkd-wait-online.service"
        self.assertEqual(len(target.encode()), 60)
        image = self.root / "root.ext4"
        image.write_bytes(b"synthetic ext4 placeholder")
        inode = {"inode": 80, "type": "symlink", "mode": 0o777,
                 "uid": 0, "gid": 0, "size": 60, "link": None}
        selected = {relative: {"type": "symlink", "target": target}}
        with mock.patch.object(rootfs, "run_stat", return_value=inode), \
                mock.patch.object(rootfs.forbidden, "_unit_target", return_value=target) as read:
            self.assertEqual(rootfs.inspect_entries(None, image, selected, self.root),
                             {"file": 0, "directory": 0, "symlink": 1})
            read.assert_called_once_with(None, image, inode, self.root,
                                         image.stat().st_size, env=rootfs.ENV, pass_fds=())
        with mock.patch.object(rootfs, "run_stat", return_value=inode), \
                mock.patch.object(rootfs.forbidden, "_unit_target", return_value="/dev/null"):
            with self.assertRaisesRegex(ValueError, "raw rootfs symlink target differs"):
                rootfs.inspect_entries(None, image, selected, self.root)

    def test_mismatched_verity_evidence_rejects_before_partition_read(self):
        layout = {"status": "diagnostic-gpt-only-unapproved",
                  "raw_disk_sha256": "a" * 64, "raw_disk_bytes": 8192}
        verified = {"status": "diagnostic-raw-root-verity-unapproved",
                    "raw_disk_sha256": "a" * 64, "raw_disk_bytes": 8192,
                    "verity_userspace_verified": False, "private_mode_approved": False}
        with mock.patch.object(rootfs.verity, "partition_images", side_effect=AssertionError(
                "unverified root must not be inspected")):
            with self.assertRaisesRegex(ValueError, "matching verified disk reports"):
                rootfs.inspect(self.root / "disk.raw", "a" * 64, 8192, 512,
                               layout, verified, self.root / "InRelease",
                               self.root / "Packages.xz", self.root / "archives",
                               self.stage, self.manifest, self.root)

    def test_installed_reader_must_match_authenticated_package_member(self):
        signed = b"\x7fELFsource-bound-debugfs"
        installed = self.root / "debugfs"
        installed.write_bytes(signed)
        installed.chmod(0o755)
        real_fstat = os.fstat

        def root_owned(fd):
            observed = real_fstat(fd)
            return types.SimpleNamespace(**{key: getattr(observed, key) for key in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns")}, st_uid=0)

        with mock.patch.object(rootfs, "READER", installed), \
                mock.patch.object(rootfs.os, "fstat", side_effect=root_owned):
            # The real tempfile is user-owned; only change ownership in the
            # test's fstat view, without changing the production reader check.
            self.assertEqual(rootfs.checked_reader(signed), digest(signed))
            installed.write_bytes(b"X" * len(signed))
            with self.assertRaisesRegex(ValueError, "installed debugfs differs"):
                rootfs.checked_reader(signed)

    def test_reader_uses_sealed_loader_objects_for_every_query(self):
        paths = iter((Path("/proc/self/fd/" + str(fd)), fd)
                     for fd in range(10, 12 + len(rootfs.READER_ELF_PROVIDERS)))
        toolchain = (b"program", b"loader",
                     tuple(b"library" for _ in rootfs.READER_ELF_PROVIDERS), "a" * 64)
        result = types.SimpleNamespace(returncode=0, stderr="", stdout="checked")
        with mock.patch.object(rootfs.verity.closure, "sealed_elf_bytes",
                               side_effect=lambda _: nullcontext(next(paths))), \
                mock.patch.object(rootfs.subprocess, "run", return_value=result) as run, \
                mock.patch.object(rootfs.verity.closure, "check_loader_report") as checked:
            with rootfs.sealed_reader_runtime(toolchain, self.root) as (reader, fds, env):
                self.assertEqual(fds, tuple(range(10, 12 + len(rootfs.READER_ELF_PROVIDERS))))
                self.assertEqual(reader[0], "/proc/self/fd/11")
                self.assertEqual(reader[-1], "/proc/self/fd/10")
                self.assertEqual(rootfs.forbidden.reader_command(
                    reader, "-R", "stats -h", "/root.img")[-4:],
                    ["/proc/self/fd/10", "-R", "stats -h", "/root.img"])
                self.assertEqual(env["PATH"], reader[reader.index("--library-path") + 1])
                self.assertTrue(Path(env["PATH"]).is_dir())
            self.assertEqual(run.call_args.args[0][-2:],
                             ["--list", "/proc/self/fd/10"])
            self.assertEqual(run.call_args.kwargs["pass_fds"], list(fds))
            checked.assert_called_once()

        paths = iter((Path("/proc/self/fd/" + str(fd)), fd)
                     for fd in range(10, 12 + len(rootfs.READER_ELF_PROVIDERS)))
        with mock.patch.object(rootfs.verity.closure, "sealed_elf_bytes",
                               side_effect=lambda _: nullcontext(next(paths))), \
                mock.patch.object(rootfs.subprocess, "run", return_value=result), \
                mock.patch.object(rootfs.verity.closure, "check_loader_report",
                                  side_effect=ValueError("ambient object")):
            with self.assertRaisesRegex(ValueError, "ambient object"):
                with rootfs.sealed_reader_runtime(toolchain, self.root):
                    self.fail("unchecked reader became available")

    def test_reader_runtime_requires_every_signed_provider_and_index(self):
        names = {"e2fsprogs", "libc6", *(name for _, name in rootfs.READER_ELF_PROVIDERS)}
        entries = [{"name": name, "version": "reviewed", "architecture": "amd64",
                    "filename": "pool/" + name + ".deb", "size": 42,
                    "sha256": digest(name.encode())} for name in sorted(names)]
        lock = {"schema_version": 1, "status": "apt-resolved-candidate-unbuilt-unapproved",
                "snapshot": "https://snapshot.debian.org/archive/debian/20260918T000000Z/",
                "inrelease_sha256": "a" * 64, "signed_release_date_epoch": 123,
                "packages_index_sha256": "b" * 64, "packages": entries}
        binary = b"\x7fELFsource-bound-debugfs"
        with mock.patch.object(rootfs.verity.debian_snapshot, "bounded_regular_bytes",
                               side_effect=lambda *_: json.dumps(lock).encode()), \
                mock.patch.object(rootfs.verity.closure, "LOCK_BYTES", 0), \
                mock.patch.object(rootfs.verity.closure, "LOCK_SHA256", ""), \
                mock.patch.object(rootfs.verity.debian_snapshot, "require_snapshot_age"), \
                mock.patch.object(rootfs.verity.debian_snapshot, "authenticated_index_bytes",
                                  return_value=(123, ("b" * 64, 5), b"index")) as index, \
                mock.patch.object(rootfs.verity.debian_snapshot, "package_records",
                                  return_value={(name, "reviewed", "amd64"): {"signed": True}
                                                for name in names}), \
                mock.patch.object(rootfs.verity.closure, "indexed_archive",
                                  side_effect=lambda item, *_args, **_kwargs:
                                  item["name"].encode()) as archive, \
                mock.patch.object(rootfs.verity.esp, "regular_member_from_deb",
                                  return_value=binary), \
                mock.patch.object(rootfs.verity.closure, "package_elf",
                                  side_effect=lambda _archive, soname:
                                  ("ELF:" + soname).encode()):
            # The test lock remains source-hash bound while individual rows vary.
            rootfs.verity.closure.LOCK_BYTES = len(json.dumps(lock).encode())
            rootfs.verity.closure.LOCK_SHA256 = digest(json.dumps(lock).encode())
            toolchain = rootfs.authenticated_reader_toolchain(
                self.root / "InRelease", self.root / "Packages.xz", self.root / "archives")
            self.assertEqual(toolchain[0], binary)
            self.assertEqual(toolchain[1], b"ELF:ld-linux-x86-64.so.2")
            self.assertEqual(len(toolchain[2]), len(rootfs.READER_ELF_PROVIDERS))
            self.assertEqual(toolchain[3], next(item for item in entries
                                                 if item["name"] == "e2fsprogs")["sha256"])
            self.assertEqual({call.args[0]["name"] for call in archive.call_args_list}, names)
            index.return_value = (123, ("0" * 64, 5), b"index")
            with self.assertRaisesRegex(ValueError, "signed debugfs index differs"):
                rootfs.authenticated_reader_toolchain(
                    self.root / "InRelease", self.root / "Packages.xz", self.root / "archives")
            index.return_value = (123, ("b" * 64, 5), b"index")
            lock["packages"] = entries[:-1]
            rootfs.verity.closure.LOCK_BYTES = len(json.dumps(lock).encode())
            rootfs.verity.closure.LOCK_SHA256 = digest(json.dumps(lock).encode())
            with self.assertRaisesRegex(ValueError, "runtime provider missing"):
                rootfs.authenticated_reader_toolchain(
                    self.root / "InRelease", self.root / "Packages.xz", self.root / "archives")


if __name__ == "__main__":
    unittest.main()
