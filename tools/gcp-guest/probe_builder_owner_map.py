#!/usr/bin/env python3
"""Probe or run under a parent-written guest-owner map on the native builder.

The no-command mode is a capability diagnostic only. Command mode establishes
the same namespace boundary before handing off to the exact-head disk probe.
Neither mode authenticates build tools or approves a private-mode release.
"""

import argparse
import errno
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys


# Exact-head source-tar inventory from native run 36372582561: uid 0,
# gids 0 and 42. The child maps no other parent identities.
UID_MAP = "0 0 1\n"
GID_MAP = "0 0 1\n42 42 1\n"


def namespace(kind):
    return os.readlink(f"/proc/self/ns/{kind}")


def write_proc(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        encoded = data.encode("ascii")
        if os.write(descriptor, encoded) != len(encoded):
            raise OSError("short namespace map write")
    finally:
        os.close(descriptor)


def wait_success(pid):
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise ValueError("child namespace probe failed")


def check_child(parent, parent_net_fd, scratch, command):
    observed = {kind: namespace(kind) for kind in ("user", "mnt", "net", "pid")}
    if any(observed[kind] == parent[kind] for kind in observed):
        raise ValueError("child namespace was not isolated")
    uid_map = sorted(tuple(int(value) for value in row.split())
                     for row in Path("/proc/self/uid_map").read_text().splitlines())
    gid_map = sorted(tuple(int(value) for value in row.split())
                     for row in Path("/proc/self/gid_map").read_text().splitlines())
    if (namespace("pid") != os.readlink("/proc/1/ns/pid")
            or uid_map != [(0, 0, 1)]
            or gid_map != [(0, 0, 1), (42, 42, 1)]
            or Path("/proc/self/setgroups").read_text().strip() != "deny"
            or os.geteuid() != 0):
        raise ValueError("child owner mapping or PID-specific proc differs")
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise ValueError("child has a non-loopback interface")
    ipv4 = Path("/proc/net/route").read_text().splitlines()
    ipv6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if (any(row.split()[0] != "lo" for row in ipv4[1:])
            or any(row.split()[-1] != "lo" for row in ipv6)):
        raise ValueError("child has a non-loopback route")
    if os.readlink(f"/proc/self/fd/{parent_net_fd}") != parent["net"]:
        raise ValueError("inherited descriptor is not the parent network")
    try:
        os.setns(parent_net_fd, 0)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise ValueError("parent network reentry failed for an unproven reason") from error
    else:
        raise ValueError("child reentered the parent network namespace")

    target = scratch / "owner-map-canary"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(descriptor, 0, 42)
        observed = os.fstat(descriptor)
        if (observed.st_uid, observed.st_gid) != (0, 42):
            raise ValueError("mapped guest ownership was not preserved")
    finally:
        os.close(descriptor)
        target.unlink()
    if command:
        os.execve(command[0], command, {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        })
    print(json.dumps({
        "status": "diagnostic-parent-written-guest-owner-map-permitted-unbuilt",
        "native_x86_64_linux": True,
        "user_mount_network_pid_namespaces_separated": True,
        "only_guest_uid_0_and_gids_0_42_mapped": True,
        "guest_gid_42_chown_succeeded": True,
        "parent_network_setns_denied_eperm": True,
        "builder_toolchain_authenticated": False,
        "mkosi_executed": False,
        "disk_image_built": False,
        "private_mode_approved": False,
    }, sort_keys=True), flush=True)


def child(ready_fd, proceed_fd, parent, parent_net_fd, scratch, command):
    os.unshare(os.CLONE_NEWUSER)
    os.write(ready_fd, b"R")
    if os.read(proceed_fd, 1) != b"G":
        raise ValueError("parent did not install guest owner mapping")
    os.unshare(os.CLONE_NEWNS | os.CLONE_NEWNET | os.CLONE_NEWPID)
    pid = os.fork()
    if pid:
        wait_success(pid)
        return
    subprocess.run(["/usr/bin/mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["/usr/bin/mount", "-t", "proc", "proc", "/proc"], check=True)
    check_child(parent, parent_net_fd, scratch, command)


def parent(scratch, command):
    if (platform.system() != "Linux" or platform.machine() != "x86_64"
            or os.geteuid() != 0 or not hasattr(os, "unshare")
            or not hasattr(os, "setns")):
        raise ValueError("native x86_64 host-root Python with namespace support required")
    if (scratch.parent != Path("/var/tmp") or not scratch.name.startswith("zrpc-owner-map-")
            or scratch.exists() or scratch.is_symlink()):
        raise ValueError("fresh scoped owner-map scratch required")
    scratch.mkdir(mode=0o700)
    parent_namespaces = {kind: namespace(kind)
                         for kind in ("user", "mnt", "net", "pid")}
    parent_net_fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    proceed_read, proceed_write = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        os.close(proceed_write)
        try:
            child(ready_write, proceed_read, parent_namespaces,
                  parent_net_fd, scratch, command)
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            print(json.dumps({"status": "blocked", "reason": str(error),
                              "disk_image_built": False,
                              "private_mode_approved": False}), flush=True)
            os._exit(1)
        os._exit(0)
    os.close(ready_write)
    os.close(proceed_read)
    try:
        if os.read(ready_read, 1) != b"R":
            raise ValueError("child user namespace was not created")
        write_proc(f"/proc/{pid}/uid_map", UID_MAP)
        write_proc(f"/proc/{pid}/setgroups", "deny\n")
        write_proc(f"/proc/{pid}/gid_map", GID_MAP)
        os.write(proceed_write, b"G")
        os.close(proceed_write)
        proceed_write = -1
        try:
            wait_success(pid)
        finally:
            pid = -1
    finally:
        os.close(ready_read)
        if proceed_write >= 0:
            os.close(proceed_write)
        os.close(parent_net_fd)
        if pid >= 0:
            os.waitpid(pid, 0)
        scratch.rmdir()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if command and command[:2] != ["/usr/bin/bash", "-c"]:
            raise ValueError("only the diagnostic bash builder handoff is supported")
        parent(args.scratch, command)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "disk_image_built": False,
                          "private_mode_approved": False}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
