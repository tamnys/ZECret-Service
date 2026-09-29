#!/usr/bin/env python3
"""Inventory a copied ext4 root and reject raw surfaces barred by audit-rootfs.py.

The caller supplies the already authenticated debugfs executable and copied,
verity-verified root partition. This check does not approve a boot or release.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
import unicodedata


READER_BANNER = b"debugfs 1.47.2 (1-Jan-2025)\n"
ENV = {"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
       "DEBUGFS_PAGER": "/usr/bin/cat"}

# ext4 directory names have at most 255 bytes; inode and owner IDs are 32-bit,
# file sizes are 64-bit, and debugfs prints a six-digit octal mode. A formatted
# row cannot exceed 319 bytes including separators and newline.
ENTRY_LINE_BYTES = 319
ENTRY = re.compile(
    rb"/([1-9][0-9]{0,9})/([0-7]{6})/(0|[1-9][0-9]{0,9})/"
    rb"(0|[1-9][0-9]{0,9})/([^/\x00-\x1f\x7f]{1,255})/"
    rb"([0-9]{0,20})/\n\Z"
)
FAST_LINK = re.compile(rb'^Fast link dest: "([^"\r\n]*)"\n\Z')
STAT_HEADER = re.compile(
    rb"Inode: ([1-9][0-9]*) +Type: symlink +Mode: +([0-7]{4}) +Flags: 0x[0-9a-f]+\n\Z"
)
STAT_OWNER_SIZE = re.compile(
    rb"User: +([0-9]+) +Group: +([0-9]+) +Project: +[0-9]+ +Size: ([0-9]+)\n\Z"
)
KINDS = {stat.S_IFREG: "file", stat.S_IFDIR: "directory",
         stat.S_IFLNK: "symlink", stat.S_IFCHR: "character",
         stat.S_IFBLK: "block", stat.S_IFIFO: "fifo",
         stat.S_IFSOCK: "socket"}

# Keep these path policies aligned with audit-rootfs.py. That build-time audit
# checks source-tree contents; this module also sees package-provided raw files.
FORBIDDEN_BINARIES = (
    "usr/sbin/sshd", "usr/bin/docker", "usr/bin/containerd", "usr/bin/ctr",
    "usr/bin/google_guest_agent", "usr/bin/google_osconfig_agent",
    "usr/bin/dstack-guest-agent", "usr/bin/sudo", "usr/bin/pkexec",
    "usr/sbin/unix_chkpwd", "usr/bin/umount", "usr/bin/su",
    "usr/sbin/losetup", "usr/sbin/swapon", "usr/sbin/swapoff",
    "usr/lib/dbus-1.0/dbus-daemon-launch-helper",
)
FORBIDDEN_NVME_SURFACE = (
    "etc/nvme/discovery.conf", "usr/sbin/uuidd", "usr/bin/adduser",
    "usr/bin/passwd", "usr/lib/systemd/system/nvmefc-boot-connections.service",
    "usr/lib/systemd/system/nvmf-autoconnect.service",
    "usr/lib/systemd/system/nvmf-connect-nbft.service",
    "usr/lib/systemd/system/nvmf-connect.target",
    "usr/lib/systemd/system/nvmf-connect@.service",
    "usr/lib/systemd/system/uuidd.service",
    "usr/lib/systemd/system/uuidd.socket",
    "usr/lib/udev/rules.d/65-persistent-net-nbft.rules",
    "usr/lib/udev/rules.d/70-nvmf-autoconnect.rules",
    "usr/lib/udev/rules.d/70-nvmf-keys.rules",
    "usr/lib/udev/rules.d/71-nvmf-netapp.rules",
)
APPLIANCE_UNITS = (
    "zrpc-node.service", "zrpc-gcp-quote.service", "zrpc-cookie.service",
    "zrpc-wrapper.service", "zrpc-gcp-disk-trigger.service", "zrpc.target",
)
MASKED_UNITS = (
    "ssh.service", "sshd.service", "ssh.socket",
    "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service",
    "container-getty@.service", "debug-shell.service", "rescue.service",
    "rescue.target", "emergency.service", "emergency.target",
    "systemd-hibernate.service", "systemd-suspend.service",
    "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service",
    "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service",
    "systemd-sysext.socket", "systemd-sysext@.service", "systemd-confext.service",
    "systemd-udev-load-credentials.service", "systemd-network-generator.service",
    "systemd-sysupdate.service", "systemd-sysupdate.timer",
    "systemd-firstboot.service", "systemd-sysusers.service",
    "systemd-user-sessions.service", "cloud-init.service", "cloud-final.service",
    "google-guest-agent.service", "google-osconfig-agent.service",
    "apt-daily.timer", "apt-daily-upgrade.timer",
)
PROTECTED_UNITS = (*APPLIANCE_UNITS, "var-lib-zebra.mount", "multi-user.target",
                   "systemd-resolved.service")
UNIT_DIRS = (
    "etc/systemd/system.control", "run/systemd/system.control",
    "run/systemd/transient", "run/systemd/generator.early",
    "etc/systemd/system", "etc/systemd/system.attached",
    "run/systemd/system", "run/systemd/system.attached",
    "run/systemd/generator", "usr/local/lib/systemd/system",
    "usr/lib/systemd/system", "run/systemd/generator.late",
)
VENDOR_UNITS = "usr/lib/systemd/system"
CONFIGURED_UNITS = "etc/systemd/system"


def _clean_name(raw):
    try:
        name = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("signed debugfs directory name is not UTF-8") from error
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"}
           for character in name):
        raise ValueError("signed debugfs directory name contains control text")
    return name


def _parse_entry(line):
    match = ENTRY.fullmatch(line)
    if match is None:
        raise ValueError("signed debugfs directory listing is malformed")
    inode, raw_mode, uid, gid, raw_name, raw_size = match.groups()
    inode, raw_mode, uid, gid = (int(inode), int(raw_mode, 8), int(uid), int(gid))
    if inode > 0xffffffff or uid > 0xffffffff or gid > 0xffffffff:
        raise ValueError("signed debugfs directory metadata exceeds ext4 width")
    kind = KINDS.get(stat.S_IFMT(raw_mode))
    if kind is None or (kind == "directory") != (raw_size == b""):
        raise ValueError("signed debugfs directory entry type or size is malformed")
    size = int(raw_size) if raw_size else None
    if size is not None and size > 0xffffffffffffffff:
        raise ValueError("signed debugfs file size exceeds ext4 width")
    return _clean_name(raw_name), {
        "inode": inode, "type": kind, "mode": stat.S_IMODE(raw_mode),
        "uid": uid, "gid": gid, "size": size,
    }


@contextmanager
def _debugfs_output(reader, image, command, scratch, image_bytes, *, env, pass_fds):
    # An ext4 dirent occupies at least 12 bytes. Even the longest possible
    # debugfs row is below 8 times its corresponding dirent. Thus eight times
    # the whole image is a conservative per-listing output bound derived from
    # the image, with one extra byte to detect overflow.
    output_limit = image_bytes * 8 + 1

    def bound_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))

    with tempfile.TemporaryFile(mode="w+b", dir=scratch) as output, \
            tempfile.TemporaryFile(mode="w+b", dir=scratch) as errors:
        result = subprocess.run([str(reader), "-R", command, str(image)],
                                stdin=subprocess.DEVNULL, stdout=output,
                                stderr=errors, env=env, pass_fds=pass_fds,
                                preexec_fn=bound_output, check=False)
        errors.seek(0)
        if (result.returncode or os.fstat(errors.fileno()).st_size != len(READER_BANNER)
                or errors.read(len(READER_BANNER) + 1) != READER_BANNER
                or os.fstat(output.fileno()).st_size > image_bytes * 8):
            raise ValueError("signed debugfs failed or emitted unexpected diagnostics")
        output.seek(0)
        yield output


def list_directory(reader, image, inode, parent_inode, scratch, image_bytes,
                   *, env=ENV, pass_fds=()):
    """Read one inode directory, requiring exact debugfs -p framing and dots."""
    entries = {}
    with _debugfs_output(reader, image, f"ls -p <{inode}>", scratch,
                         image_bytes, env=env, pass_fds=pass_fds) as output:
        while True:
            line = output.readline(ENTRY_LINE_BYTES + 1)
            if line == b"\n":
                if output.read(1):
                    raise ValueError("signed debugfs directory listing has trailing output")
                break
            if not line:
                raise ValueError("signed debugfs directory listing lacks terminator")
            if len(line) > ENTRY_LINE_BYTES:
                raise ValueError("signed debugfs directory row exceeds ext4 format")
            name, entry = _parse_entry(line)
            if name in entries:
                raise ValueError("signed debugfs directory contains duplicate names")
            entries[name] = entry
    if (entries.get(".", {}).get("inode") != inode
            or entries.get("..", {}).get("inode") != parent_inode
            or entries["."]["type"] != "directory"
            or entries[".."]["type"] != "directory"):
        raise ValueError("signed debugfs directory parent identity differs")
    return entries


def _unit_target(reader, image, entry, scratch, image_bytes, *, env, pass_fds):
    """Read a unit alias by inode, never by a path that debugfs could follow."""
    links, headers, owners = [], [], []
    with _debugfs_output(reader, image, f"stat <{entry['inode']}>", scratch,
                         image_bytes, env=env, pass_fds=pass_fds) as output:
        for line in output:
            if match := FAST_LINK.fullmatch(line):
                links.append(match.group(1))
            if match := STAT_HEADER.fullmatch(line):
                headers.append((int(match.group(1)), int(match.group(2), 8)))
            if match := STAT_OWNER_SIZE.fullmatch(line):
                owners.append(tuple(int(group) for group in match.groups()))
    if (len(links) != 1 or len(headers) != 1 or len(owners) != 1
            or len(links[0]) != entry["size"]
            or headers[0] != (entry["inode"], entry["mode"])
            or owners[0] != (entry["uid"], entry["gid"], entry["size"])):
        raise ValueError("signed debugfs unit symlink target is ambiguous")
    return _clean_name(links[0])


def reject_xattrs(reader, image, inode, scratch, image_bytes, *, env=ENV, pass_fds=()):
    """Require an empty extended-attribute list for one exact ext4 inode.

    Pinned debugfs 1.47.2 emits empty stdout for an inode without xattrs.
    Any output, including an unrecognized diagnostic, fails closed. Reading
    by inode avoids following a package or unit symlink.
    """
    with _debugfs_output(reader, image, f"ea_list <{inode}>", scratch,
                         image_bytes, env=env, pass_fds=pass_fds) as output:
        if output.read(1):
            raise ValueError("raw ext4 inode has unreviewed extended attributes: "
                             + str(inode))


def _children(inventory, parent):
    prefix = parent + "/" if parent else ""
    return {path[len(prefix):]: entry for path, entry in inventory.items()
            if path.startswith(prefix) and "/" not in path[len(prefix):] and path != parent}


def _protected_unit_additions(units):
    names = {"service.d", "target.d"}
    for unit in units:
        names.update(f"{unit}.{suffix}" for suffix in ("d", "wants", "requires", "upholds"))
        stem, kind = unit.rsplit(".", 1)
        for index, character in enumerate(stem):
            if character == "-":
                names.add(f"{stem[:index + 1]}.{kind}.d")
    return names


def _check_units(inventory):
    for relative in UNIT_DIRS:
        parts = relative.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            if prefix in inventory and inventory[prefix]["type"] != "directory":
                raise ValueError("system unit load path redirected: " + prefix)
    for relative in (VENDOR_UNITS, CONFIGURED_UNITS):
        if inventory.get(relative, {}).get("type") != "directory":
            raise ValueError("system unit directory missing: " + relative)
    for unit in APPLIANCE_UNITS:
        entry = inventory.get(VENDOR_UNITS + "/" + unit, {})
        if entry.get("type") != "file" or entry["mode"] & 0o022:
            raise ValueError("appliance unit missing or mutable: " + unit)

    configured = _children(inventory, CONFIGURED_UNITS)
    dropins = configured.get("systemd-resolved.service.d", {})
    if (dropins.get("type") != "directory"
            or set(_children(inventory, CONFIGURED_UNITS + "/systemd-resolved.service.d"))
            != {"10-no-credentials.conf"}):
        raise ValueError("resolved credential override differs")
    dropin = inventory[CONFIGURED_UNITS + "/systemd-resolved.service.d/10-no-credentials.conf"]
    if dropin["type"] != "file" or dropin["mode"] != 0o644:
        raise ValueError("resolved credential override differs")
    wants = configured.get("multi-user.target.wants", {})
    if (wants.get("type") != "directory"
            or set(_children(inventory, CONFIGURED_UNITS + "/multi-user.target.wants"))
            != {"systemd-networkd.service", "systemd-resolved.service"}):
        raise ValueError("appliance boot dependencies differ")
    expected_links = {
        CONFIGURED_UNITS + "/default.target": "/usr/lib/systemd/system/zrpc.target",
        CONFIGURED_UNITS + "/multi-user.target.wants/systemd-networkd.service":
            "/usr/lib/systemd/system/systemd-networkd.service",
        CONFIGURED_UNITS + "/multi-user.target.wants/systemd-resolved.service":
            "/usr/lib/systemd/system/systemd-resolved.service",
    }
    for path, target in expected_links.items():
        if inventory.get(path, {}).get("type") != "symlink" or inventory[path].get("target") != target:
            raise ValueError("appliance unit symlink differs: " + path)
    for unit in MASKED_UNITS:
        path = CONFIGURED_UNITS + "/" + unit
        if (inventory.get(path, {}).get("type") != "symlink"
                or inventory[path].get("target") != "/dev/null"):
            raise ValueError("administrative unit unmasked: " + unit)

    effective = {}
    for relative in UNIT_DIRS:
        for name, entry in _children(inventory, relative).items():
            if name.endswith((".service", ".target")) and name not in effective:
                effective[name] = (entry.get("target", "").rsplit("/", 1)[-1]
                                   if entry["type"] == "symlink" else None)
    protected = set(PROTECTED_UNITS)
    while True:
        aliases = {name for name, target in effective.items() if target in protected}
        if aliases <= protected:
            break
        protected.update(aliases)
    additions = _protected_unit_additions(protected)
    for relative in UNIT_DIRS:
        for name, entry in _children(inventory, relative).items():
            if name in additions and not (
                name == "systemd-resolved.service.d" and relative == CONFIGURED_UNITS
                or name == "multi-user.target.wants"
                and relative in {CONFIGURED_UNITS, VENDOR_UNITS}
            ):
                raise ValueError("appliance unit override or dependency present: " + relative + "/" + name)
            if relative != VENDOR_UNITS and name in PROTECTED_UNITS:
                raise ValueError("appliance unit replaced: " + relative + "/" + name)
            if (entry["type"] == "symlink"
                    and relative + "/" + name != CONFIGURED_UNITS + "/default.target"
                    and entry.get("target", "").rsplit("/", 1)[-1] in APPLIANCE_UNITS):
                raise ValueError("unreviewed appliance unit alias: " + relative + "/" + name)


def _check_surfaces(inventory):
    for path in (*FORBIDDEN_BINARIES, *FORBIDDEN_NVME_SURFACE,
                 "etc/kernel/cmdline", "usr/lib/kernel/cmdline",
                 "var/cache/ldconfig/aux-cache", "var/log/alternatives.log"):
        if path in inventory:
            raise ValueError("unapproved administrative or boot input: " + path)
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent in inventory and inventory[parent]["type"] != "directory":
                raise ValueError("administrative or boot path redirected: " + parent)
    efi = inventory.get("efi")
    if efi and (efi["type"] != "directory" or _children(inventory, "efi")):
        raise ValueError("unapproved EFI boot input")
    admin_rules = inventory.get("etc/udev/rules.d")
    if admin_rules and (admin_rules["type"] != "directory"
                        or _children(inventory, "etc/udev/rules.d")):
        raise ValueError("mutable udev override present")
    mount = inventory.get("usr/bin/mount", {})
    if (mount.get("type") != "file" or mount["mode"] != 0o555
            or (mount["uid"], mount["gid"]) != (0, 0)):
        raise ValueError("non-privileged mount metadata differs")
    for path, entry in inventory.items():
        if not path:
            continue
        parts = path.split("/")
        if entry["type"] == "file" and entry["mode"] & 0o6000:
            raise ValueError("setuid/setgid regular file remains: " + path)
        if (parts[-1].endswith((".addon.efi", ".cred", ".raw"))
                and ("boot" in parts[:-1] or "credstore" in parts[:-1])):
            raise ValueError("unapproved boot companion or credential: " + path)
        if (parts[-1].endswith(".extra.d")
                or parts[:2] == ["etc", "extensions"]
                or parts[:3] == ["usr", "lib", "extensions"]):
            raise ValueError("boot extension input remains: " + path)
        if (entry["type"] != "directory"
                and any(part in {"credstore", "credstore.encrypted"} for part in parts)):
            raise ValueError("guest credential store must be empty: " + path)
    _check_units(inventory)


def inspect(reader, image, scratch, *, env=ENV, pass_fds=()):
    """Return path → raw inode metadata after a complete no-follow policy walk.

    The root directory has key ``""``. File metadata has ``inode``, ``type``,
    ``mode`` (permission bits), ``uid``, ``gid`` and ``size``; directory sizes
    are ``None`` because ``ls -p`` omits them. Unit symlinks also have ``target``.
    """
    image = Path(image)
    image_stat = image.stat()
    if not stat.S_ISREG(image_stat.st_mode) or image_stat.st_size <= 0:
        raise ValueError("copied ext4 root image must be a nonempty regular file")
    inventory = {}
    visited = set()
    pending = [("", 2, 2)]
    while pending:
        path, inode, parent_inode = pending.pop()
        if inode in visited:
            raise ValueError("raw ext4 directory inode is linked more than once")
        visited.add(inode)
        entries = list_directory(reader, image, inode, parent_inode, scratch,
                                 image_stat.st_size, env=env, pass_fds=pass_fds)
        current = entries.pop(".")
        entries.pop("..")
        if path:
            prior = inventory[path]
            if any(current[key] != prior[key] for key in ("inode", "type", "mode", "uid", "gid")):
                raise ValueError("raw ext4 directory inode metadata differs: " + path)
        else:
            inventory[""] = current
        for name, entry in entries.items():
            child = path + "/" + name if path else name
            if child in inventory:
                raise ValueError("raw ext4 path is duplicated: " + child)
            inventory[child] = entry
            if entry["type"] == "directory":
                pending.append((child, entry["inode"], inode))
            elif entry["type"] == "symlink":
                parent = child.rsplit("/", 1)[0] if "/" in child else ""
                if parent in UNIT_DIRS or child in {
                    CONFIGURED_UNITS + "/multi-user.target.wants/systemd-networkd.service",
                    CONFIGURED_UNITS + "/multi-user.target.wants/systemd-resolved.service",
                }:
                    entry["target"] = _unit_target(
                        reader, image, entry, scratch, image_stat.st_size,
                        env=env, pass_fds=pass_fds)
    _check_surfaces(inventory)
    for inode in sorted({entry["inode"] for entry in inventory.values()}):
        reject_xattrs(reader, image, inode, scratch, image_stat.st_size,
                      env=env, pass_fds=pass_fds)
    return inventory
