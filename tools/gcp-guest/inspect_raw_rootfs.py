#!/usr/bin/env python3
"""Compare the exact raw ext4 root with the source-bound guest overlay.

The production outer runner calls this only after its signed staged-builder
check, immutable input inventory, and userspace dm-verity verification. The
installed debugfs executable must match the member of the exact signed Debian
package, then reads a copied root partition without mounting it. This module
does not independently seal its dynamic runtime or prove a successful boot.
No result from this module approves an image or private mode.
"""

import hashlib
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import platform
import re
import resource
import stat
import subprocess
import tempfile

import inspect_raw_verity as verity


STATUS = "diagnostic-raw-root-overlay-bytes-matched-unapproved"
READER = Path("/usr/sbin/debugfs")
# Observed from e2fsprogs 1.47.2-3+b12 in the source-reviewed Debian snapshot.
READER_BANNER = b"debugfs 1.47.2 (1-Jan-2025)\n"
STAT_HEADER = re.compile(
    r"Inode: ([1-9][0-9]*) +Type: (regular|directory|symlink) +Mode: +([0-7]{4}) +Flags: 0x[0-9a-f]+"
)
STAT_OWNER_SIZE = re.compile(r"(?m)^User: +([0-9]+) +Group: +([0-9]+) +Project: +[0-9]+ +Size: ([0-9]+)$")
FAST_LINK = re.compile(r'(?m)^Fast link dest: "([^"\n]*)"$')
SAFE_PATH = re.compile(r"[A-Za-z0-9_./@+-]+\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ACCOUNT_FILES = {
    "etc/passwd": (1100, "f42d295b4a2ad2a9d9a82865bc4ba6043fafe03e77e5b57e7081a8d67450c2ff", 0o644, 0o644),
    "etc/group": (661, "c2209f60f6d80a4b10479c1ba9e2df7877bb8a648911a45629f0dc6d86bb1b00", 0o644, 0o644),
    "etc/shadow": (509, "92ec1ef612eb9c38cbe22403a595d268bf38546cadded7d8e0471bf271f15d13", 0o400, 0o000),
}
REQUIRED_FILES = frozenset({
    "etc/fstab", "etc/zrpc/zebra.toml", *ACCOUNT_FILES,
    "usr/lib/zrpc/zrpc-node-wrapper", "usr/lib/zrpc/zrpc-gcp-quote-broker",
    "usr/lib/zrpc/zrpc-gcp-guard", "usr/lib/zrpc/zrpc-gcp-disk-id", "usr/lib/zrpc/zrpc-gcp-cookie",
    "usr/lib/zrpc/zebrad",
    "usr/lib/systemd/system/zrpc-node.service",
    "usr/lib/systemd/system/zrpc-gcp-quote.service",
    "usr/lib/systemd/system/zrpc-cookie.service",
    "usr/lib/systemd/system/zrpc-wrapper.service",
    "usr/lib/systemd/system/zrpc-gcp-disk-trigger.service",
    "usr/lib/udev/rules.d/65-gce-disk-naming.rules",
    "usr/lib/systemd/system/zrpc.target",
})
ENV = {"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
       "DEBUGFS_PAGER": "/usr/bin/cat"}


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _staged_file(stage, relative, expected):
    path = stage / "rootfs" / relative
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != expected["mode"]):
                raise ValueError("staged rootfs file type or mode differs: " + relative)
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after) or digest != expected["sha256"]:
            raise ValueError("staged rootfs file bytes differ: " + relative)
        return before.st_size
    finally:
        os.close(descriptor)


def checked_overlay(manifest, stage):
    """Select every source-bound rootfs entry, including masks and symlinks."""
    if (type(manifest) is not dict
            or manifest.get("status") != "staged-unbuilt-unapproved"
            or manifest.get("image_built") is not False
            or manifest.get("private_mode_approved") is not False
            or type(manifest.get("entries")) is not dict):
        raise ValueError("source-bound candidate manifest required")
    entries = manifest["entries"]
    if (type(entries.get("rootfs")) is not dict
            or entries["rootfs"].get("type") != "directory"):
        raise ValueError("source-bound rootfs overlay is absent")
    selected = {}
    for path, expected in entries.items():
        if not isinstance(path, str) or not path.startswith("rootfs/"):
            continue
        relative = path.removeprefix("rootfs/")
        if (not SAFE_PATH.fullmatch(relative) or relative.startswith("/")
                or any(part in {"", ".", ".."} for part in relative.split("/"))
                or type(expected) is not dict):
            raise ValueError("source-bound rootfs path is unsafe")
        kind = expected.get("type")
        if kind == "directory":
            if (set(expected) != {"type", "mode"}
                    or type(expected["mode"]) is not int):
                raise ValueError("source-bound rootfs directory identity malformed")
            selected[relative] = expected
        elif kind == "symlink":
            if (set(expected) != {"type", "target"}
                    or not isinstance(expected["target"], str)):
                raise ValueError("source-bound rootfs symlink identity malformed")
            selected[relative] = expected
        elif kind == "file":
            if (set(expected) != {"type", "mode", "sha256"}
                    or type(expected["mode"]) is not int
                    or not isinstance(expected["sha256"], str)
                    or not HEX_SHA256.fullmatch(expected["sha256"])):
                raise ValueError("source-bound rootfs file identity malformed")
            selected[relative] = expected
        else:
            raise ValueError("source-bound rootfs entry type differs")
    if not REQUIRED_FILES <= {name for name, item in selected.items()
                             if item["type"] == "file"}:
        raise ValueError("critical staged rootfs executable or configuration is absent")
    for relative in selected:
        parent = Path(relative).parent
        while parent != Path("."):
            if selected.get(parent.as_posix(), {}).get("type") != "directory":
                raise ValueError("staged rootfs parent is not an inventoried directory")
            parent = parent.parent
    root = os.lstat(stage / "rootfs")
    if (not stat.S_ISDIR(root.st_mode)
            or stat.S_IMODE(root.st_mode) != entries["rootfs"].get("mode")):
        raise ValueError("staged rootfs root directory differs")
    for relative, expected in sorted(selected.items(),
                                     key=lambda item: (item[0].count("/"), item[0])):
        local = stage / "rootfs" / relative
        observed = os.lstat(local)
        if expected["type"] == "directory":
            if (not stat.S_ISDIR(observed.st_mode)
                    or stat.S_IMODE(observed.st_mode) != expected["mode"]):
                raise ValueError("staged rootfs directory differs: " + relative)
        elif expected["type"] == "symlink":
            if (not stat.S_ISLNK(observed.st_mode)
                    or os.readlink(local) != expected["target"]):
                raise ValueError("staged rootfs symlink differs: " + relative)
        else:
            selected[relative] = {**expected, "size": _staged_file(stage, relative, expected)}
    for name, (size, digest, staged_mode, _) in ACCOUNT_FILES.items():
        if selected.get(name) != {"type": "file", "mode": staged_mode,
                                   "sha256": digest, "size": size}:
            raise ValueError("staged account differs from reviewed source: " + name)
    return selected


def signed_reader_bytes(inrelease, packages_index, archives):
    """Read debugfs from the source-pinned package and Debian-signed index."""
    lock_bytes = verity.debian_snapshot.bounded_regular_bytes(
        verity.esp.LOCK, verity.closure.LOCK_BYTES, "builder closure lock")
    if (len(lock_bytes) != verity.closure.LOCK_BYTES
            or hashlib.sha256(lock_bytes).hexdigest() != verity.closure.LOCK_SHA256):
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=verity.direct.unique_object)
    if (lock.get("schema_version") != 1
            or lock.get("status") != "apt-resolved-candidate-unbuilt-unapproved"):
        raise ValueError("unsupported builder closure lock")
    snapshot_time = datetime.strptime(
        lock["snapshot"].rstrip("/").rsplit("/", 1)[-1], "%Y%m%dT%H%M%SZ",
    ).replace(tzinfo=timezone.utc)
    verity.debian_snapshot.require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    epoch, (index_hash, _), index_bytes = verity.debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, lock["inrelease_sha256"])
    if (epoch != lock["signed_release_date_epoch"]
            or index_hash != lock["packages_index_sha256"]):
        raise ValueError("signed debugfs index differs from reviewed builder candidate")
    entries = [entry for entry in lock["packages"] if entry["name"] == "e2fsprogs"]
    if len(entries) != 1:
        raise ValueError("signed debugfs package identity is absent or ambiguous")
    entry = entries[0]
    records = verity.debian_snapshot.package_records(io.BytesIO(index_bytes))
    record = records.get((entry["name"], entry["version"], entry["architecture"]))
    package = verity.closure.indexed_archive(entry, record, archives, keep_bytes=True)
    program = verity.esp.regular_member_from_deb(package, "usr/sbin/debugfs")
    if not program.startswith(b"\x7fELF"):
        raise ValueError("signed debugfs package member is not ELF")
    return program, entry["sha256"]


def checked_reader(signed_bytes):
    descriptor = os.open(READER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_mode & 0o022 or not before.st_mode & 0o111
                or before.st_size != len(signed_bytes)):
            raise ValueError("installed debugfs executable has unsafe identity")
        installed = stream.read()
        after = os.fstat(stream.fileno())
        if _file_identity(before) != _file_identity(after) or installed != signed_bytes:
            raise ValueError("installed debugfs differs from signed Debian package member")
    return hashlib.sha256(signed_bytes).hexdigest()


def run_stat(reader, image, relative, *, env=ENV, pass_fds=()):
    result = subprocess.run([str(reader), "-R", "stat /" + relative, str(image)],
                            stdin=subprocess.DEVNULL, capture_output=True, env=env,
                            pass_fds=pass_fds, check=False)
    if result.returncode or result.stderr != READER_BANNER:
        raise ValueError("signed debugfs could not read rootfs inode: " + relative)
    try:
        output = result.stdout.decode("ascii")
    except UnicodeError as error:
        raise ValueError("signed debugfs inode report is malformed") from error
    lines = output.splitlines()
    header = STAT_HEADER.fullmatch(lines[0]) if lines else None
    owner_size = STAT_OWNER_SIZE.findall(output)
    if header is None or len(owner_size) != 1:
        raise ValueError("signed debugfs inode report is malformed: " + relative)
    link = FAST_LINK.findall(output)
    if len(link) > 1:
        raise ValueError("signed debugfs symlink report is ambiguous")
    return {"type": header[2], "mode": int(header[3], 8),
            "uid": int(owner_size[0][0]), "gid": int(owner_size[0][1]),
            "size": int(owner_size[0][2]), "link": link[0] if link else None}


def run_cat(reader, image, relative, expected_size, scratch, *, env=ENV, pass_fds=()):
    # One extra byte is enough to detect a changed file while bounding output
    # to the exact staged size. The banner is the only allowed stderr output.
    file_limit = max(expected_size, len(READER_BANNER)) + 1

    def bound_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    with tempfile.TemporaryFile(mode="w+b", dir=scratch) as content, \
            tempfile.TemporaryFile(mode="w+b", dir=scratch) as errors:
        result = subprocess.run([str(reader), "-R", "cat /" + relative, str(image)],
                                stdin=subprocess.DEVNULL, stdout=content, stderr=errors,
                                env=env, preexec_fn=bound_output,
                                pass_fds=pass_fds, check=False)
        errors.seek(0)
        if result.returncode or errors.read() != READER_BANNER:
            raise ValueError("signed debugfs could not read rootfs file: " + relative)
        if os.fstat(content.fileno()).st_size != expected_size:
            raise ValueError("raw rootfs file size differs: " + relative)
        content.seek(0)
        return hashlib.file_digest(content, "sha256").hexdigest()


def inspect_entries(reader, image, selected, scratch, *, env=ENV, pass_fds=()):
    checked = {"file": 0, "directory": 0, "symlink": 0}
    for relative, expected in sorted(selected.items(),
                                     key=lambda item: (item[0].count("/"), item[0])):
        inode = run_stat(reader, image, relative, env=env, pass_fds=pass_fds)
        if inode["type"] != {"file": "regular", "directory": "directory",
                             "symlink": "symlink"}[expected["type"]]:
            raise ValueError("raw rootfs entry type differs: " + relative)
        if expected["type"] == "file":
            final_mode = (ACCOUNT_FILES[relative][3] if relative in ACCOUNT_FILES
                          else expected["mode"])
            if (inode["mode"] != final_mode or inode["size"] != expected["size"]
                    or (relative in ACCOUNT_FILES
                        and (inode["uid"], inode["gid"]) != (0, 0))):
                raise ValueError("raw rootfs file metadata differs: " + relative)
            if run_cat(reader, image, relative, expected["size"], scratch,
                       env=env, pass_fds=pass_fds) != expected["sha256"]:
                raise ValueError("raw rootfs file bytes differ: " + relative)
        elif expected["type"] == "symlink":
            if inode["link"] != expected["target"]:
                raise ValueError("raw rootfs symlink target differs: " + relative)
        checked[expected["type"]] += 1
    return checked


def inspect(raw, expected_sha256, expected_bytes, sector_size, layout,
            verified_verity, inrelease, packages_index, archives,
            stage, manifest, workspace):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native x86_64 Linux rootfs inspection required")
    if (type(layout) is not dict or layout.get("status") != "diagnostic-gpt-only-unapproved"
            or layout.get("raw_disk_sha256") != expected_sha256
            or layout.get("raw_disk_bytes") != expected_bytes
            or type(verified_verity) is not dict
            or verified_verity.get("status") != "diagnostic-raw-root-verity-unapproved"
            or verified_verity.get("raw_disk_sha256") != expected_sha256
            or verified_verity.get("raw_disk_bytes") != expected_bytes
            or verified_verity.get("verity_userspace_verified") is not True
            or verified_verity.get("private_mode_approved") is not False):
        raise ValueError("raw rootfs inspection requires matching verified disk reports")
    workspace = verity.esp.workspace_scratch(workspace)
    selected = checked_overlay(manifest, stage)
    signed_reader, archive_sha256 = signed_reader_bytes(inrelease, packages_index, archives)
    reader_sha256 = checked_reader(signed_reader)
    with tempfile.TemporaryDirectory(prefix="zrpc-raw-rootfs-", dir=workspace) as temporary:
        scratch = Path(temporary)
        images = verity.partition_images(raw, layout, expected_sha256,
                                         expected_bytes, sector_size, scratch)
        root, root_bytes, root_guid = images["root-x86-64"]
        if (root_guid != verified_verity.get("root_partition_guid")
                or root_bytes != verified_verity.get("root_partition_bytes")):
            raise ValueError("raw rootfs partition differs from verified verity report")
        with root.open("rb") as stream:
            root_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        # The installed executable is checked for build consistency, but the
        # inspected bytes are read using this immutable package-member fd.
        with verity.closure.sealed_elf_bytes(signed_reader) as (reader, descriptor):
            checked = inspect_entries(reader, root, selected, scratch,
                                      pass_fds=(descriptor,))
    return {"status": STATUS, "raw_disk_sha256": expected_sha256,
            "raw_disk_bytes": expected_bytes,
            "root_partition_guid": root_guid,
            "root_partition_sha256": root_sha256,
            "overlay_entries_checked": checked,
            "staged_builder_debugfs_sha256": reader_sha256,
            "signed_e2fsprogs_archive_sha256": archive_sha256,
            "reader_executable_matches_signed_package": True,
            "reader_dynamic_runtime_independently_sealed": False,
            "boot_verified": False, "private_mode_approved": False}
