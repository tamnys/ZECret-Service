#!/usr/bin/env python3
"""Probe staged CPIO builder inputs in a native diagnostic runner.

This checks selected executable bytes against the staged Debian payload receipt
and observes the current network namespace. This observation does not prove
network confinement against a privileged runner that can re-enter host namespaces.
The caller must authenticate the
signed snapshot, lock, and staged tree separately. This does not run mkosi,
establish a complete builder closure, build an initrd, or approve a release.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))
import stage_builder_toolchain as staged
import verify_builder_closure as closure


STATUS = "diagnostic-initrd-builder-capability-unbuilt"
TOOLS = {
    "usr/bin/mkosi": "mkosi",
    "usr/bin/mkosi-sandbox": "mkosi",
    "usr/bin/cpio": "cpio",
    "usr/bin/zstd": "zstd",
    "usr/bin/python3.13": "python3.13-minimal",
}
INTERPRETER_LINK = "usr/bin/python3"
INTERPRETER_PACKAGE = "python3-minimal"
INTERPRETER_TARGET = "python3.13"
OPEN_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
OPEN_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate builder receipt key")
        result[key] = value
    return result


def selected_records(manifest):
    if (not isinstance(manifest, dict) or manifest.get("status") != staged.STATUS
            or manifest.get("builder_closure_lock_sha256") != closure.LOCK_SHA256
            or any(manifest.get(field) is not False for field in (
                "signed_snapshot_rechecked", "package_scripts_executed",
                "runtime_execution_verified", "complete_builder_toolchain",
                "image_built", "private_mode_approved"))):
        raise ValueError("builder receipt differs from non-accepting staged closure")
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError("builder receipt lacks payload inventory")
    selected = {}
    for record in entries:
        if not isinstance(record, dict):
            raise ValueError("builder receipt has malformed payload entry")
        path = record.get("path")
        if path not in TOOLS and path != INTERPRETER_LINK:
            continue
        if path in selected:
            raise ValueError("builder receipt duplicates a selected executable")
        if path == INTERPRETER_LINK:
            if (record.get("kind") != "symlink"
                    or record.get("packages") != [INTERPRETER_PACKAGE]
                    or record.get("target") != INTERPRETER_TARGET):
                raise ValueError("selected Python interpreter link differs")
            selected[path] = record
            continue
        if (record.get("kind") != "file"
                or record.get("packages") != [TOOLS[path]]
                or not isinstance(record.get("sha256"), str)
                or len(record["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in record["sha256"])
                or type(record.get("size")) is not int or record["size"] <= 0
                or type(record.get("staged_mode")) is not int
                or record["staged_mode"] & 0o111 == 0):
            raise ValueError("selected builder executable identity is invalid")
        selected[path] = record
    if set(selected) != set(TOOLS) | {INTERPRETER_LINK}:
        raise ValueError("selected builder executable is absent from staged closure")
    return selected


def selected_file(root_fd, path, record):
    directory = os.dup(root_fd)
    try:
        for component in path.split("/")[:-1]:
            child = os.open(component, OPEN_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.rsplit("/", 1)[-1], OPEN_FILE,
                             dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size != record["size"]
                    or stat.S_IMODE(before.st_mode) != record["staged_mode"]):
                raise ValueError("selected builder executable metadata changed")
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(descriptor)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                     item.st_mtime_ns, item.st_ctime_ns)
            if digest != record["sha256"] or identity(before) != identity(after):
                raise ValueError("selected builder executable differs from staged payload")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def selected_link(root_fd, path, record):
    directory = os.dup(root_fd)
    try:
        for component in path.split("/")[:-1]:
            child = os.open(component, OPEN_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        name = path.rsplit("/", 1)[-1]
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISLNK(info.st_mode)
                or os.readlink(name, dir_fd=directory) != record["target"]):
            raise ValueError("selected Python interpreter link changed")
    finally:
        os.close(directory)


def network_observation(parent, current, interfaces, ipv4, ipv6):
    if (not parent.startswith("net:[") or not parent.endswith("]")
            or current == parent or not current.startswith("net:[")
            or not current.endswith("]")):
        raise ValueError("outer network namespace was not separated")
    if [name for _, name in interfaces] != ["lo"]:
        raise ValueError("outer network namespace has non-loopback interfaces")
    lines = ipv4.splitlines()
    if lines:
        if not lines[0].split() or lines[0].split()[0] != "Iface":
            raise ValueError("IPv4 route table is malformed")
        lines = lines[1:]
    for line in lines:
        fields = line.split()
        if len(fields) != 11 or fields[0] != "lo":
            raise ValueError("outer network namespace has a non-loopback IPv4 route")
    for line in ipv6.splitlines():
        fields = line.split()
        if len(fields) != 10 or fields[-1] != "lo":
            raise ValueError("outer network namespace has a non-loopback IPv6 route")
    return current


def probe(root, parent_network_namespace):
    root_fd = os.open(root, OPEN_DIRECTORY)
    try:
        receipt = os.open(staged.MANIFEST, OPEN_FILE, dir_fd=root_fd)
        try:
            info = os.fstat(receipt)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("staged builder receipt is redirected")
            with os.fdopen(receipt, "rb") as stream:
                receipt = -1
                manifest = json.load(stream, object_pairs_hook=unique_object)
        finally:
            if receipt >= 0:
                os.close(receipt)
        selected = selected_records(manifest)
        for path, record in selected.items():
            if path == INTERPRETER_LINK:
                selected_link(root_fd, path, record)
            else:
                selected_file(root_fd, path, record)
    finally:
        os.close(root_fd)
    current = network_observation(
        parent_network_namespace, os.readlink("/proc/self/ns/net"),
        socket.if_nameindex(), Path("/proc/net/route").read_text(),
        Path("/proc/net/ipv6_route").read_text(),
    )
    return {
        "status": STATUS,
        "selected_executables": sorted(selected),
        "selected_executable_bytes_match_staged_receipt": True,
        "observed_network_namespace": current,
        "observed_only_loopback_interface_and_routes": True,
        "network_confinement_verified": False,
        "signed_snapshot_rechecked_by_this_probe": False,
        "complete_builder_toolchain": False,
        "mkosi_executed_by_this_probe": False,
        "initrd_built": False,
        "image_built": False,
        "private_mode_approved": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-network-namespace", required=True)
    args = parser.parse_args(argv)
    try:
        report = probe(Path("/"), args.parent_network_namespace)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        report = {"status": "blocked", "reason": str(error),
                  "network_confinement_verified": False,
                  "complete_builder_toolchain": False,
                  "initrd_built": False, "image_built": False,
                  "private_mode_approved": False}
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
