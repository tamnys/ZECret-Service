#!/usr/bin/env python3
"""Compare raw ext4 package components with the authenticated guest closure.

The caller supplies the source-checked overlay and an already authenticated
raw-ext4 reader. This module derives bytes and metadata from every exact
Debian archive, then checks package code, runtime, and policy paths without
accepting observed image values as expectations. It grants no boot or private
mode approval.
"""

from pathlib import PurePosixPath
import re

import assemble_guest_base_tree as base_tree
import inspect_raw_forbidden as forbidden
import preflight_guest_base_tree as preflight
import prepare


# Package members in these locations can execute, load at runtime, or set
# process/service policy. Documentation, locale, and package-manager state do
# not participate in this identity check. Executable members elsewhere do.
COMPONENT_PREFIXES = (
    "etc/", "usr/bin/", "usr/sbin/", "usr/lib/", "usr/lib64/",
    "usr/libexec/", "bin/", "sbin/", "lib/", "lib64/",
    "usr/share/dbus-1/", "usr/share/pam/", "usr/share/polkit-1/",
    "usr/share/systemd/", "usr/share/udev/", "usr/share/keyrings/",
    "usr/share/ca-certificates/", "usr/share/zoneinfo/",
)
NAMESPACE_LINKS = frozenset({"bin", "sbin", "lib", "lib64", "usr/lib64"})
CODE_ROOTS = ("usr/local", "opt")
CRITICAL_COMPONENTS = frozenset({
    "usr/bin/mount", "usr/bin/udevadm",
    "usr/lib/systemd/systemd", "usr/lib/systemd/systemd-networkd",
    "usr/lib/systemd/systemd-journald", "usr/lib/systemd/systemd-logind",
    "usr/lib/systemd/systemd-resolved", "usr/lib/systemd/systemd-udevd",
    "usr/lib/systemd/system/systemd-networkd.service",
    "usr/lib/systemd/system/systemd-resolved.service",
})
# Exact production mkosi.conf RemoveFiles entries, also checked against
# prepare.ROOT_REMOVE_FILES so a recipe change cannot silently widen a skip.
REVIEWED_REMOVALS = frozenset({
    "usr/sbin/unix_chkpwd", "usr/bin/umount", "usr/bin/su",
    "usr/sbin/losetup", "usr/sbin/swapon", "usr/sbin/swapoff",
    "usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "var/cache/ldconfig/aux-cache", "var/log/alternatives.log",
    "opt", "usr/local", "etc/opt",
    "etc/systemd/system/getty.target.wants",
    "etc/systemd/system/sysinit.target.wants",
    "etc/systemd/system/systemd-journald.service.wants",
    "etc/systemd/system/timers.target.wants",
    "etc/systemd/user",
    "etc/systemd/system/sockets.target.wants/systemd-journald-audit.socket",
    "etc/systemd/system/sockets.target.wants/systemd-pcrextend.socket",
})
PACKAGE_METADATA_ROOTS = ("var/lib/dpkg", "var/lib/apt", "var/cache/apt")
# These source-bound overlay paths may replace Debian package members. The
# caller must pass inspect_raw_rootfs.checked_overlay's verified inventory;
# that inspector separately compares their final raw-ext4 identities.
REVIEWED_OVERLAY_REPLACEMENTS = frozenset({
    "etc/passwd", "etc/group", "etc/shadow", "etc/resolv.conf",
    "etc/systemd/system/default.target",
})
MOUNT_PATH = "usr/bin/mount"
MOUNT_SOURCE_MODE = 0o4755
MOUNT_FINAL_MODE = 0o555  # tools/gcp-guest/sanitize-mount.py
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _reviewed_removals():
    configured = frozenset(path.removeprefix("/") for path in prepare.ROOT_REMOVE_FILES)
    if configured != REVIEWED_REMOVALS:
        raise ValueError("root RemoveFiles differs from reviewed package exceptions")
    return configured


def _component(path, row):
    return (_sensitive_path(path)
            or (row["kind"] in {"file", "hardlink"}
                and bool(row["source_mode"] & 0o111)))


def _sensitive_path(path):
    return (path in NAMESPACE_LINKS
            or path.startswith(COMPONENT_PREFIXES)
            or any(path == root or path.startswith(root + "/")
                   for root in CODE_ROOTS)
            or any(path == root or path.startswith(root + "/")
                   for root in forbidden.UNIT_DIRS))


def expected_components(authenticated, verified_overlay):
    """Build a source-derived plan from preflight.authenticated_archives data.

    `verified_overlay` is the return value of checked_overlay, never a list of
    image-observed exceptions. The public wrapper below performs authentication.
    """
    if type(verified_overlay) is not dict:
        raise ValueError("verified source overlay inventory required")
    removals = _reviewed_removals()
    _, source_rows = base_tree.source_plan(authenticated)
    source = {row["path"]: row for row in source_rows}
    if len(source) != len(source_rows) or "." not in source:
        raise ValueError("authenticated package payload inventory is malformed")
    selected = {}
    overlaid = []
    for path, row in source.items():
        if not _component(path, row) or path in removals:
            continue
        if path in (*CODE_ROOTS, *forbidden.UNIT_DIRS) and row["kind"] != "directory":
            raise ValueError("signed package code or unit directory is redirected: " + path)
        if path in verified_overlay:
            overlay = verified_overlay[path]
            if (row["kind"] == "directory"
                    and overlay.get("type") == "directory"
                    and overlay.get("mode") == row["output_mode"]
                    and (row["uid"], row["gid"]) == (0, 0)):
                selected[path] = row
                continue
            if (path not in REVIEWED_OVERLAY_REPLACEMENTS
                    or overlay.get("type") not in {"file", "symlink"}):
                raise ValueError("unreviewed source overlay replaces package component: " + path)
            overlaid.append(path)
            continue
        selected[path] = row
    if not CRITICAL_COMPONENTS <= selected.keys():
        raise ValueError("critical package executable, runtime, or policy member absent")
    for path in tuple(selected):
        for parent in PurePosixPath(path).parents:
            name = parent.as_posix()
            if name == ".":
                break
            row = source.get(name)
            if row is None or row["kind"] != "directory":
                raise ValueError("package component parent is missing or redirected: " + path)
            overlay = verified_overlay.get(name)
            if overlay is not None and (overlay.get("type") != "directory"
                                        or overlay.get("mode") != row["output_mode"]
                                        or (row["uid"], row["gid"]) != (0, 0)):
                raise ValueError("source overlay changes package component parent: " + name)
            selected[name] = row
    expected = {}
    for path, row in sorted(selected.items()):
        kind = "file" if row["kind"] == "hardlink" else row["kind"]
        mode = row["output_mode"]
        if path == MOUNT_PATH:
            if (row["kind"] != "file" or row["packages"] != ["mount"]
                    or (row["uid"], row["gid"]) != (0, 0)
                    or row["source_mode"] != MOUNT_SOURCE_MODE):
                raise ValueError("signed mount helper differs from reviewed mode exception")
            mode = MOUNT_FINAL_MODE
        elif row["source_mode"] != mode:
            raise ValueError("unreviewed package component mode transform: " + path)
        item = {"type": {"file": "regular", "directory": "directory",
                          "symlink": "symlink"}[kind],
                "mode": mode, "uid": row["uid"], "gid": row["gid"]}
        if kind == "file":
            item.update(size=row["size"], sha256=row["sha256"])
        elif kind == "symlink":
            item.update(size=len(row["target"].encode("ascii")), target=row["target"])
        expected[path] = item
    if removals & expected.keys():
        raise ValueError("removed package path remains required")
    return {"entries": expected, "removed": tuple(sorted(removals)),
            "overlaid": tuple(sorted(overlaid))}


def inspect_components(plan, verified_overlay, inventory, lookup_inode,
                       hash_file, read_link=None):
    """Check a plan using a raw-ext4 reader; `None` means proven absence.

    `lookup_inode` returns type, mode, and numeric owner fields, or None only
    when the signed reader proves the path absent. Directory size may be None;
    regular files and symlinks require their exact size. `hash_file` reads
    exactly `size` bytes from a regular inode and returns its SHA-256 digest.
    `read_link` may read a long symlink that debugfs does not report inline.
    `inventory` is the complete no-follow raw tree returned by the signed
    reader. Source-bound overlay paths are checked separately by its caller.
    """
    if type(verified_overlay) is not dict or type(inventory) is not dict:
        raise ValueError("verified overlay and complete raw inventory required")
    planned = plan["entries"].keys() | verified_overlay.keys()
    if not planned <= inventory.keys():
        raise ValueError("raw inventory is missing an authenticated component or overlay")
    for root in PACKAGE_METADATA_ROOTS:
        if any(path == root or path.startswith(root + "/") for path in inventory):
            raise ValueError("package-manager metadata remains in raw rootfs: " + root)
    unplanned = []
    for path, entry in inventory.items():
        if (type(path) is not str or type(entry) is not dict
                or type(entry.get("type")) is not str
                or type(entry.get("mode")) is not int):
            raise ValueError("raw inventory entry is malformed")
        if ((_sensitive_path(path)
             or (entry["type"] == "file" and bool(entry["mode"] & 0o111)))
                and path not in planned):
            unplanned.append(path)
    if unplanned:
        raise ValueError("unplanned security-sensitive raw rootfs entries: "
                         + repr(sorted(unplanned)))
    checked = {"regular": 0, "directory": 0, "symlink": 0, "removed": 0}
    for path in plan["removed"]:
        if lookup_inode(path) is not None:
            raise ValueError("removed package path remains in raw rootfs: " + path)
        checked["removed"] += 1
    for path, expected in sorted(plan["entries"].items(),
                                 key=lambda item: (item[0].count("/"), item[0])):
        inode = lookup_inode(path)
        if inode is None or type(inode) is not dict:
            raise ValueError("package component missing from raw rootfs: " + path)
        kind = expected["type"]
        if (inode.get("type") != kind
                or any(type(inode.get(field)) is not int for field in
                       ("mode", "uid", "gid"))
                or (inode["mode"], inode["uid"], inode["gid"]) !=
                   (expected["mode"], expected["uid"], expected["gid"])):
            raise ValueError("raw package component type, mode, or owner differs: " + path)
        if kind == "regular":
            if type(inode.get("size")) is not int or inode["size"] != expected["size"]:
                raise ValueError("raw package component size differs: " + path)
            digest = hash_file(path, expected["size"])
            if type(digest) is not str or not HEX_SHA256.fullmatch(digest) \
                    or digest != expected["sha256"]:
                raise ValueError("raw package component bytes differ: " + path)
        elif kind == "symlink":
            if type(inode.get("size")) is not int or inode["size"] != expected["size"]:
                raise ValueError("raw package symlink size differs: " + path)
            target = inode.get("link")
            if target is None:
                if read_link is None:
                    raise ValueError("raw package symlink target was not read: " + path)
                target = read_link(path, expected["size"])
            if target != expected["target"]:
                raise ValueError("raw package symlink target differs: " + path)
        checked[kind] += 1
    return {"components_checked": checked,
            "overlaid_package_paths": plan["overlaid"]}


def inspect_authenticated_components(metadata, archives, verified_overlay,
                                     inventory, lookup_inode, hash_file,
                                     read_link=None):
    """Authenticate the exact guest closure, derive the plan, and inspect it."""
    authenticated = preflight.authenticated_archives(metadata, archives)
    plan = expected_components(authenticated, verified_overlay)
    return inspect_components(plan, verified_overlay, inventory, lookup_inode,
                              hash_file, read_link)
