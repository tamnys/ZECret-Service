#!/usr/bin/env python3
"""Check native builder namespace capabilities without building an image.

This is a public-runner feasibility probe. It does not authenticate the runner,
the build tools, a guest artifact, or a private-mode release.
"""

import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


NAMESPACES = ("user", "mnt", "net", "pid")


def namespace(kind):
    return os.readlink(f"/proc/self/ns/{kind}")


def loopback_only():
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("child network namespace has a non-loopback interface")
    ipv4 = Path("/proc/net/route").read_text().splitlines()
    if ipv4:
        if not ipv4[0].split() or ipv4[0].split()[0] != "Iface":
            raise ValueError("child IPv4 route table is malformed")
        ipv4 = ipv4[1:]
    if any(len(row.split()) != 11 or row.split()[0] != "lo" for row in ipv4):
        raise ValueError("child network namespace has a non-loopback IPv4 route")
    ipv6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if any(len(row.split()) != 10 or row.split()[-1] != "lo" for row in ipv6):
        raise ValueError("child network namespace has a non-loopback IPv6 route")


def child(arguments):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("native x86_64 Linux child required")
    parent = dict(zip(NAMESPACES, arguments.parent_namespaces, strict=True))
    observed = {kind: namespace(kind) for kind in NAMESPACES}
    if any(observed[kind] == parent[kind] for kind in NAMESPACES):
        raise ValueError("user, mount, network, and PID namespaces must all differ")
    if os.geteuid() != 0 or os.readlink("/proc/1/ns/pid") != observed["pid"]:
        raise ValueError("child root mapping or PID-specific proc mount is absent")
    if Path("/proc/self/uid_map").read_text().split() != [
        "0", str(arguments.parent_uid), "1"
    ] or Path("/proc/self/gid_map").read_text().split() != [
        "0", str(arguments.parent_gid), "1"
    ]:
        raise ValueError("child user mapping is broader than the runner identity")
    loopback_only()

    parent_net_fd = arguments.parent_net_fd
    os.fstat(parent_net_fd)
    if os.readlink(f"/proc/self/fd/{parent_net_fd}") != parent["net"]:
        raise ValueError("inherited namespace descriptor is not the parent network")
    if not hasattr(os, "setns"):
        raise ValueError("runner Python lacks os.setns for the reentry check")
    try:
        os.setns(parent_net_fd, 0)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise ValueError("parent network reentry failed for an unproven reason") from error
    else:
        raise ValueError("child reentered the parent network namespace")

    scratch = Path(arguments.scratch)
    if scratch.resolve(strict=True) != scratch or scratch.is_symlink():
        raise ValueError("mount probe scratch is redirected")
    subprocess.run(["mount", "--bind", str(scratch), str(scratch)], check=True)
    try:
        if subprocess.run(["mountpoint", "-q", str(scratch)], check=False).returncode != 0:
            raise ValueError("child bind mount did not take effect")
    finally:
        subprocess.run(["umount", str(scratch)], check=True)

    print(json.dumps({
        "status": "diagnostic-child-userns-capabilities-present-unbuilt",
        "native_x86_64_linux": True,
        "user_mount_network_pid_namespaces_separated": True,
        "host_root_only_uid_gid_mapping": True,
        "pid_specific_proc_mounted": True,
        "only_loopback_interface_and_routes_observed": True,
        "parent_network_setns_denied_eperm": True,
        "bind_mount_in_child_succeeded": True,
        "builder_toolchain_authenticated": False,
        "mkosi_executed": False,
        "disk_image_built": False,
        "network_confinement_for_full_build_verified": False,
        "private_mode_approved": False,
    }, sort_keys=True))


def parent(arguments):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("native x86_64 Linux runner required")
    if arguments.parent_mode == "unprivileged" and os.geteuid() == 0:
        raise ValueError("unprivileged probe parent unexpectedly has root")
    if arguments.parent_mode == "root" and os.geteuid() != 0:
        raise ValueError("root probe parent lacks the explicit root identity")
    scratch = Path(arguments.scratch)
    if not scratch.is_absolute() or scratch.exists() or scratch.is_symlink():
        raise ValueError("fresh absolute mount probe scratch required")
    scratch.mkdir(mode=0o700)
    parent_namespaces = [namespace(kind) for kind in NAMESPACES]
    parent_net_fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        # The public runner rejected an unprivileged map and a privileged
        # map of the runner UID. Deliver only this public, exact-HEAD script
        # as a command argument; the child need not traverse the runner-owned
        # checkout while this host-root-only namespace is being evaluated.
        source = Path(__file__).read_text()
        command = [
            "/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net",
            "--pid", "--fork", "--mount-proc", "--kill-child",
            "--propagation", "private", "--", sys.executable, "-I", "-B",
            "-c", source, "child", "--scratch",
            str(scratch), "--parent-net-fd", str(parent_net_fd),
            "--parent-uid", str(os.geteuid()), "--parent-gid", str(os.getegid()),
            "--parent-namespaces", *parent_namespaces,
        ]
        outcome = subprocess.run(command, pass_fds=(parent_net_fd,), check=False)
        if outcome.returncode:
            raise ValueError("child namespace probe failed")
    finally:
        os.close(parent_net_fd)
        scratch.rmdir()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("parent", "child"))
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--parent-mode", choices=("unprivileged", "root"),
                        default="unprivileged")
    parser.add_argument("--parent-net-fd", type=int)
    parser.add_argument("--parent-uid", type=int)
    parser.add_argument("--parent-gid", type=int)
    parser.add_argument("--parent-namespaces", nargs=4)
    arguments = parser.parse_args(argv)
    try:
        if arguments.mode == "parent":
            parent(arguments)
        else:
            if (arguments.parent_net_fd is None or arguments.parent_uid is None
                    or arguments.parent_gid is None or arguments.parent_namespaces is None):
                raise ValueError("parent namespace evidence is missing")
            child(arguments)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "mkosi_executed": False, "disk_image_built": False,
                          "network_confinement_for_full_build_verified": False,
                          "private_mode_approved": False}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
