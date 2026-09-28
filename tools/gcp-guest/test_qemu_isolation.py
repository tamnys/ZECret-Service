"""Fail-closed checks for the native QEMU observation namespace supervisor."""

import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import qemu_isolation as isolation


class QemuIsolationTests(unittest.TestCase):
    def test_explicit_positive_inputs_have_no_implicit_budget(self):
        for value in ("", "0", "-1", "01", "1.0", "+1"):
            with self.assertRaises(Exception):
                isolation.positive(value)
        self.assertEqual(isolation.positive("123456789"), 123456789)

    def test_inherited_socket_and_nonstandard_file_descriptor_block(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaisesRegex(ValueError, "inherited socket"):
                isolation.no_inherited_descriptors()
        finally:
            left.close()
            right.close()
        with tempfile.TemporaryFile() as stream:
            with self.assertRaisesRegex(ValueError, "unexpected inherited descriptor"):
                isolation.no_inherited_descriptors()

    def test_parent_liveness_pipe_handles_invisible_ancestor_pid(self):
        # The PID-namespace init sees its ancestor-namespace parent as PID 0.
        # A live writer is observable without relying on that invisible PID.
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            isolation.parent_alive(read_fd)
            os.close(write_fd)
            write_fd = -1
            with self.assertRaisesRegex(ValueError, "parent exited"):
                isolation.parent_alive(read_fd)
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_host_root_requires_initial_user_namespace_mapping(self):
        mapping = {"/proc/self/uid_map": "0 0 4294967295\n",
                   "/proc/self/gid_map": "0 0 4294967295\n"}
        with (mock.patch.object(Path, "read_text", autospec=True,
                                side_effect=lambda path: mapping[str(path)]),
              mock.patch.object(isolation, "namespace", return_value="user:[1]"),
              mock.patch.object(isolation.os, "readlink", return_value="user:[1]")):
            isolation.initial_user_namespace()
            mapping["/proc/self/gid_map"] = "0 100000 65536\n"
            with self.assertRaisesRegex(ValueError, "initial user namespace"):
                isolation.initial_user_namespace()

    def test_stage_mode_and_fresh_output_are_required_before_adaptation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stage"
            root.mkdir(mode=0o700)
            signed = root / "signed-qemu"
            signed.write_bytes(b"signed bytes remain untouched")
            output = root / "observe"
            with mock.patch.object(isolation, "mountpoints", return_value=[]):
                isolation.prepare_stage(root, output)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            self.assertEqual(signed.read_bytes(), b"signed bytes remain untouched")
            self.assertTrue(output.is_dir())
            self.assertEqual(list(output.iterdir()), [])
            self.assertEqual(list((root / "proc").iterdir()), [])
            self.assertEqual(list((root / "dev").iterdir()), [])
            with mock.patch.object(isolation, "mountpoints", return_value=[]):
                with self.assertRaisesRegex(ValueError, "original 0700"):
                    isolation.prepare_stage(root, output)

    def test_stage_rejects_existing_output_and_redirected_device_mountpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stage"
            root.mkdir(mode=0o700)
            output = root / "observe"
            output.mkdir()
            with mock.patch.object(isolation, "mountpoints", return_value=[]):
                with self.assertRaisesRegex(ValueError, "fresh stage-root child"):
                    isolation.prepare_stage(root, output)
            output.rmdir()
            (root / "dev").symlink_to(directory)
            with mock.patch.object(isolation, "mountpoints", return_value=[]):
                with self.assertRaisesRegex(ValueError, "empty real directory"):
                    isolation.prepare_stage(root, output)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_stage_rejects_preexisting_submount(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stage"
            root.mkdir(mode=0o700)
            with mock.patch.object(isolation, "mountpoints",
                                   return_value=[(str(root / "dev"), False)]):
                with self.assertRaisesRegex(ValueError, "already contains a mount"):
                    isolation.prepare_stage(root, root / "observe")

    def test_global_mount_state_allows_only_output_to_be_writable(self):
        root = Path("/stage")
        output = root / "observe"
        required = [str(root), str(output), str(root / "dev"),
                    *(str(root / "dev" / name) for name in isolation.DEVICE_NAMES),
                    str(root / "proc")]
        entries = [(path, path == str(output)) for path in required]

        def statvfs(path):
            return mock.Mock(f_flag=0 if path == output else os.ST_RDONLY)

        with (mock.patch.object(isolation, "mountpoints", return_value=entries),
              mock.patch.object(isolation.os, "statvfs", side_effect=statvfs)):
            isolation.check_mounts(root, output, require_proc=True)
        with (mock.patch.object(isolation, "mountpoints",
                                return_value=entries + [("/tmp", True)]),
              mock.patch.object(isolation.os, "statvfs", side_effect=statvfs)):
            with self.assertRaisesRegex(ValueError, "writable mount differs"):
                isolation.check_mounts(root, output, require_proc=True)
        with (mock.patch.object(isolation, "mountpoints", return_value=entries),
              mock.patch.object(isolation.os, "statvfs",
                                side_effect=lambda path: mock.Mock(f_flag=os.ST_RDONLY))):
            with self.assertRaisesRegex(ValueError, "output is read-only"):
                isolation.check_mounts(root, output, require_proc=True)

    def test_new_network_allows_only_loopback_routes(self):
        ipv4 = "Iface\tDestination\nlo\t0000007F\n"
        ipv6 = "00000000000000000000000000000001 80 lo\n"
        content = {"/proc/net/route": ipv4,
                   "/proc/net/ipv6_route": ipv6}
        with (mock.patch.object(isolation.socket, "if_nameindex",
                                return_value=[(1, "lo")]),
              mock.patch.object(Path, "read_text", autospec=True,
                                side_effect=lambda path: content[str(path)])):
            isolation.no_network()
            content["/proc/net/route"] = "Iface\tDestination\n"
            content["/proc/net/ipv6_route"] = ""
            isolation.no_network()
            content["/proc/net/route"] = ipv4
            content["/proc/net/ipv6_route"] = ipv6
            content["/proc/net/route"] += "eth0\t00000000\n"
            with self.assertRaisesRegex(ValueError, "non-loopback IPv4 routes"):
                isolation.no_network()
            content["/proc/net/route"] = ipv4
            content["/proc/net/ipv6_route"] += "00000000000000000000000000000000 00 eth0\n"
            with self.assertRaisesRegex(ValueError, "non-loopback IPv6 routes"):
                isolation.no_network()
            content["/proc/net/ipv6_route"] = ipv6
            with mock.patch.object(isolation.socket, "if_nameindex",
                                   return_value=[(1, "lo"), (2, "eth0")]):
                with self.assertRaisesRegex(ValueError, "unexpected interface"):
                    isolation.no_network()

    def test_mountinfo_mode_and_path_escapes_are_parsed(self):
        line = "1 0 0:1 / /stage\\040space ro - tmpfs tmpfs ro\n"
        with mock.patch.object(Path, "read_text", return_value=line):
            self.assertEqual(isolation.mountpoints(), [("/stage space", False)])
        line = "1 0 0:1 / /stage rw,ro - tmpfs tmpfs rw\n"
        with mock.patch.object(Path, "read_text", return_value=line):
            with self.assertRaisesRegex(ValueError, "unambiguous access mode"):
                isolation.mountpoints()


if __name__ == "__main__":
    unittest.main()
