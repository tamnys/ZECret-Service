#!/usr/bin/env python3
"""Run the optional synthetic boot observer in private, read-only Linux namespaces.

This is a local diagnostic boundary for a native x86_64 Linux runner. It does
not build an image, access a cloud service, or approve a guest for private mode.
The observer authenticates the staged toolchain and disk before launching QEMU.
"""

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import re
import signal
import socket
import stat
import sys
import threading


CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 1
SYS_MOUNT_SETATTR_X86_64 = 442
PR_SET_PDEATHSIG = 1
DEVICE_NAMES = ("null", "zero", "urandom")
MOUNT_ESCAPED = re.compile(r"\\([0-7]{3})")

libc = ctypes.CDLL(None, use_errno=True)


class MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64),
                ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64),
                ("userns_fd", ctypes.c_uint64)]


def syscall_result(value, operation):
    if value != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"{operation}: {os.strerror(error)}")


def unshare(flags):
    syscall_result(libc.unshare(ctypes.c_int(flags)), "unshare")


def mount(source, target, filesystem=None, flags=0, data=None):
    encoded = lambda value: os.fsencode(value) if value is not None else None
    syscall_result(libc.mount(encoded(source), encoded(target),
                              encoded(filesystem), ctypes.c_ulong(flags),
                              encoded(data)), "mount " + str(target))


def mount_readonly(path, *, recursive=False, readonly=True):
    attr = MountAttr(MOUNT_ATTR_RDONLY if readonly else 0,
                     0 if readonly else MOUNT_ATTR_RDONLY, 0, 0)
    result = libc.syscall(ctypes.c_long(SYS_MOUNT_SETATTR_X86_64),
                          ctypes.c_int(-100), os.fsencode(path),
                          ctypes.c_uint(AT_RECURSIVE if recursive else 0),
                          ctypes.byref(attr), ctypes.sizeof(attr))
    syscall_result(result, "mount_setattr " + str(path))


def namespace(name):
    return os.readlink("/proc/self/ns/" + name)


def no_inherited_descriptors():
    if threading.active_count() != 1:
        raise ValueError("isolation supervisor must be single-threaded")
    for name in os.listdir("/proc/self/fd"):
        if not name.isdecimal():
            raise ValueError("unrecognized inherited descriptor")
        descriptor = int(name)
        try:
            mode = os.fstat(descriptor).st_mode
        except OSError as error:
            # listdir can include its own already-closed directory descriptor.
            if error.errno == 9:
                continue
            raise
        if stat.S_ISSOCK(mode):
            raise ValueError("inherited socket descriptor")
        if descriptor > 2:
            raise ValueError("unexpected inherited descriptor")


def no_network():
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("network namespace has an unexpected interface")
    routes = Path("/proc/net/route").read_text().splitlines()
    # A fresh netns can have no IPv4 main table, so proc emits no header.
    if routes and routes[0].split()[:1] != ["Iface"]:
        raise ValueError("network namespace IPv4 route header is missing")
    for row in routes[1:]:
        fields = row.split()
        if not fields or fields[0] != "lo":
            raise ValueError("network namespace has non-loopback IPv4 routes")
    routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    for row in routes6:
        fields = row.split()
        if not fields or fields[-1] != "lo":
            raise ValueError("network namespace has non-loopback IPv6 routes")


def actual_path(value, *, directory):
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_symlink():
        raise ValueError("isolation input must be an absolute real path: " + str(path))
    mode = path.stat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise ValueError("isolation input has wrong file type: " + str(path))
    return path


def positive(value):
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError("expected an explicit positive decimal integer")
    return int(value)


def host_identity(uid, gid):
    try:
        pwd.getpwuid(uid)
        grp.getgrgid(gid)
    except KeyError as error:
        raise ValueError("QEMU UID/GID must exist on the host runner") from error


def initial_user_namespace():
    # Initial Linux user namespace is the full identity map. A root process
    # in a mapped child namespace is not a host-root supervisor.
    expected = ["0", "0", "4294967295"]
    for name in ("uid_map", "gid_map"):
        if Path("/proc/self/" + name).read_text().split() != expected:
            raise ValueError("QEMU isolation requires the initial user namespace")
    if namespace("user") != os.readlink("/proc/1/ns/user"):
        raise ValueError("QEMU isolation user namespace differs from runner init")


def parent_alive(read_fd):
    """Close the fork/prctl race across PID namespaces without using getppid.

    PID namespace init sees its ancestor-namespace parent as PID 0. The
    parent holds the pipe's only writer; after PR_SET_PDEATHSIG is installed,
    EOF means it died before that prctl could arrange a signal.
    """
    try:
        result = os.read(read_fd, 1)
    except BlockingIOError:
        return
    if result == b"":
        raise ValueError("isolation parent exited before observer start")
    raise ValueError("unexpected isolation parent pipe data")


def mountpoints():
    points = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise ValueError("malformed mountinfo")
        path = MOUNT_ESCAPED.sub(lambda match: chr(int(match.group(1), 8)),
                                 fields[4])
        options = fields[5].split(",")
        if not ({"ro", "rw"} & set(options)) or {"ro", "rw"} <= set(options):
            raise ValueError("mountinfo lacks an unambiguous access mode")
        points.append((path, "rw" in options))
    return points


def no_prior_stage_mounts(root):
    prefix = str(root) + "/"
    if any(path == str(root) or path.startswith(prefix) for path, _ in mountpoints()):
        raise ValueError("staged toolchain already contains a mount")


def check_mounts(root, output, *, require_proc):
    entries = mountpoints()
    writable = [path for path, rw in entries if rw]
    if writable != [str(output)]:
        raise ValueError("writable mount differs from dedicated observation output")
    required = {str(root), str(output), str(root / "dev"),
                *(str(root / "dev" / name) for name in DEVICE_NAMES)}
    if require_proc:
        required.add(str(root / "proc"))
    present = {path for path, _ in entries}
    if not required <= present:
        raise ValueError("minimal staged mounts are incomplete")
    if os.statvfs(output).f_flag & os.ST_RDONLY:
        raise ValueError("observation output is read-only")
    if not os.statvfs(root).f_flag & os.ST_RDONLY:
        raise ValueError("staged toolchain root is writable")


def ensure_empty_mountpoint(path):
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
            raise ValueError("staged mountpoint is not an empty real directory: " + str(path))
    else:
        path.mkdir(mode=0o700)


def prepare_stage(root, output):
    no_prior_stage_mounts(root)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError("signed stage root must retain its original 0700 mode")
    if output != root / "observe" or output.exists() or output.is_symlink():
        raise ValueError("observation output must be a fresh stage-root child")
    for name in ("observe", "proc", "dev"):
        ensure_empty_mountpoint(root / name)
    os.chmod(root, 0o755)
    os.chmod(root / "proc", 0o755)
    os.chmod(root / "dev", 0o755)
    if stat.S_IMODE(root.stat().st_mode) != 0o755:
        raise ValueError("staged root is not traversable by QEMU UID")


def stage_mounts(root, output):
    mount(str(root), str(root), flags=MS_BIND)
    mount(str(output), str(output), flags=MS_BIND)
    mount("tmpfs", str(root / "dev"), "tmpfs", MS_NOSUID | MS_NOEXEC,
          "mode=0755")
    for name in DEVICE_NAMES:
        source = Path("/dev") / name
        if source.is_symlink() or not stat.S_ISCHR(source.stat().st_mode):
            raise ValueError("host device is not a real character device: " + name)
        target = root / "dev" / name
        target.touch(mode=0o600, exist_ok=False)
        mount(str(source), str(target), flags=MS_BIND)
    # The recursive operation covers pre-existing host submounts too. The
    # output bind is the only mount made writable again, at one exact path.
    mount_readonly("/", recursive=True)
    mount_readonly(str(output), readonly=False)
    check_mounts(root, output, require_proc=False)


def observer_argv(args, parent_net):
    script = Path(__file__).with_name("boot_observe_qemu.py").resolve(strict=True)
    command = [sys.executable, "-I", "-B", str(script), "run"]
    for flag, value in (("toolchain-root", args.toolchain_root),
                        ("toolchain-report", args.toolchain_report),
                        ("disk", args.disk), ("disk-report", args.disk_report),
                        ("output", args.output), ("memory-mib", args.memory_mib),
                        ("vcpus", args.vcpus),
                        ("deadline-seconds", args.deadline_seconds),
                        ("qemu-uid", args.qemu_uid),
                        ("qemu-gid", args.qemu_gid),
                        ("parent-net-ns", parent_net)):
        command.extend(("--" + flag, str(value)))
    for offset in args.capture_at_seconds:
        command.extend(("--capture-at-seconds", str(offset)))
    return command


def run(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("QEMU isolation requires native x86_64 Linux")
    if os.geteuid() != 0 or os.getuid() != 0:
        raise ValueError("QEMU isolation requires host root")
    initial_user_namespace()
    no_inherited_descriptors()
    host_identity(args.qemu_uid, args.qemu_gid)
    root = actual_path(args.toolchain_root, directory=True)
    actual_path(args.toolchain_report, directory=False)
    actual_path(args.disk, directory=False)
    actual_path(args.disk_report, directory=False)
    output = Path(args.output)
    if output != root / "observe":
        raise ValueError("observation output must be stage-root/observe")
    parent = {name: namespace(name) for name in ("mnt", "net", "pid")}
    unshare(CLONE_NEWNS | CLONE_NEWNET)
    if namespace("mnt") == parent["mnt"] or namespace("net") == parent["net"]:
        raise ValueError("mount/network namespace did not change")
    mount(None, "/", flags=MS_REC | MS_PRIVATE)
    no_network()
    prepare_stage(root, output)
    stage_mounts(root, output)
    unshare(CLONE_NEWPID)
    alive_read, alive_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    child = os.fork()
    if child == 0:
        try:
            os.close(alive_write)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            syscall_result(libc.prctl(ctypes.c_int(PR_SET_PDEATHSIG),
                                      ctypes.c_ulong(signal.SIGKILL), 0, 0, 0),
                           "prctl parent-death signal")
            parent_alive(alive_read)
            os.close(alive_read)
            if os.getpid() != 1 or namespace("pid") == parent["pid"]:
                raise ValueError("PID namespace did not change")
            mount("proc", str(root / "proc"), "proc",
                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2")
            no_network()
            no_inherited_descriptors()
            check_mounts(root, output, require_proc=True)
            command = observer_argv(args, parent["net"])
            os.execve(sys.executable, command,
                      {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                       "PYTHONDONTWRITEBYTECODE": "1"})
        except (OSError, ValueError) as error:
            print(json.dumps({"status": "blocked", "reason": str(error)},
                             sort_keys=True), flush=True)
        os._exit(1)

    os.close(alive_read)

    def forward(_signum, _frame):
        try:
            # Namespace PID 1 ignores ordinary default-action signals from
            # an ancestor namespace; SIGKILL always terminates it and QEMU.
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, forward)
    try:
        while True:
            try:
                _, status = os.waitpid(child, 0)
                break
            except InterruptedError:
                continue
    finally:
        os.close(alive_write)
    return os.waitstatus_to_exitcode(status)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    running = sub.add_parser("run")
    for name in ("toolchain-root", "toolchain-report", "disk", "disk-report",
                 "output"):
        running.add_argument("--" + name, type=Path, required=True)
    for name in ("memory-mib", "vcpus", "deadline-seconds", "qemu-uid",
                 "qemu-gid"):
        running.add_argument("--" + name, type=positive, required=True)
    running.add_argument("--capture-at-seconds", type=positive, action="append",
                         default=[])
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)},
                         sort_keys=True), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
