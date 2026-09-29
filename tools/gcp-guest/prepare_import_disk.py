#!/usr/bin/env python3
"""Make a checked mkosi GPT image usable as Google's whole-GB disk.raw input.

This is an offline format conversion, not an image-import, boot, or release
approval. The resulting *new* disk identity must go through all raw-image,
ESP/UKI, rootfs, and verity inspections before operator packaging.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


GIB = 1024 ** 3
MAX_IMPORT_GIB = 2048
SECTOR_SIZE = 512  # Reviewed deploy/gcp/guest/mkosi.conf SectorSize.
WORKSPACE = Path("/workspace")
# Signed Debian snapshot builder-closure.lock.json: fdisk 2.41.5-0+deb13u1,
# archive SHA-256 7f37094ca3f63c3a07b4431532b0bcc4aa64291e75c48cabebf41bf42ad706b1.
# The executable digest was extracted from its exact hash-checked .deb, without
# executing a package hook. Dynamic loader/library trust remains a separate
# builder-host requirement; this diagnostic cannot grant production approval.
SFDISK_PACKAGE_SHA256 = "7f37094ca3f63c3a07b4431532b0bcc4aa64291e75c48cabebf41bf42ad706b1"
SFDISK_SHA256 = "d0cfef56b8bd47f19e2ec6b73836f89b0d3d4956233eeff4f32ae03dfa4e8919"
SFDISK = Path("/usr/sbin/sfdisk")
CHUNK = 1024 * 1024


def _load_gpt():
    path = Path(__file__).with_name("inspect_raw_gpt.py")
    spec = importlib.util.spec_from_file_location("inspect_raw_gpt", path)
    if spec is None or spec.loader is None:
        raise ValueError("reviewed GPT inspector unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _digest(fd, size):
    result = hashlib.sha256()
    for offset in range(0, size, CHUNK):
        block = os.pread(fd, min(CHUNK, size - offset), offset)
        if len(block) != min(CHUNK, size - offset):
            raise ValueError("image changed during hashing")
        result.update(block)
    return result.hexdigest()


def _open_regular(path, *, executable=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (executable and not info.st_mode & 0o111):
        os.close(fd)
        raise ValueError("input must be one regular, nonredirected file")
    return fd, info


def _compare_range(left, right, start, end):
    for offset in range(start, end, CHUNK):
        count = min(CHUNK, end - offset)
        if os.pread(left, count, offset) != os.pread(right, count, offset):
            raise ValueError("reviewed partition bytes changed during import preparation")


def _zero_range(fd, start, end):
    zeros = bytes(CHUNK)
    for offset in range(start, end, CHUNK):
        count = min(CHUNK, end - offset)
        if os.pwrite(fd, zeros[:count], offset) != count:
            raise ValueError("old backup GPT removal was incomplete")


def _require_zero_range(fd, start, end):
    for offset in range(start, end, CHUNK):
        count = min(CHUNK, end - offset)
        if os.pread(fd, count, offset) != bytes(count):
            raise ValueError("obsolete backup GPT remains in unallocated space")


def _remove_old_backup(fd, old_start, old_end, new_start, new_end):
    """Erase obsolete backup metadata, preserving any overlap with new GPT."""
    cleared = []
    if old_start < new_start:
        cleared.append((old_start, min(old_end, new_start)))
    if new_end < old_end:
        cleared.append((max(old_start, new_end), old_end))
    for start, end in cleared:
        _zero_range(fd, start, end)
    return cleared


def _prepare(source, expected_sha256, expected_bytes, destination, sfdisk,
             *, allow_non_workspace_paths=False, sfdisk_env=None, gpt_module=None,
             sfdisk_runner=None):
    source, destination, sfdisk = map(Path, (source, destination, sfdisk))
    if (not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or type(expected_bytes) is not int or expected_bytes <= 0
            or expected_bytes % SECTOR_SIZE or expected_bytes > MAX_IMPORT_GIB * GIB):
        raise ValueError("exact mkosi disk SHA-256 and sector-aligned size required")
    if (not source.is_absolute() or not destination.is_absolute()
            or not sfdisk.is_absolute() or destination.name != "disk.raw"
            or source == destination or destination.exists()
            or destination.is_symlink() or not destination.parent.is_dir()
            or destination.parent.resolve(strict=True) != destination.parent):
        raise ValueError("new absolute disk.raw in a real existing directory required")
    if (not allow_non_workspace_paths
            and (not source.is_relative_to(WORKSPACE)
                 or not destination.is_relative_to(WORKSPACE))):
        raise ValueError("source and output must remain on the workspace volume")
    target_bytes = expected_bytes + (-expected_bytes % GIB)
    # The production outer runner passes its selected-commit GPT module. The
    # standalone diagnostic keeps its adjacent inspector for local use.
    gpt = _load_gpt() if gpt_module is None else gpt_module
    source_fd, source_info = _open_regular(source)
    temp_path = None
    try:
        if source_info.st_size != expected_bytes or _digest(source_fd, expected_bytes) != expected_sha256:
            raise ValueError("mkosi disk differs from exact reviewed input identity")
        original = gpt.inspect(source, expected_sha256, expected_bytes, SECTOR_SIZE)
        if target_bytes == expected_bytes:
            old_backup_start = None
        else:
            old_last_lba = expected_bytes // SECTOR_SIZE - 1
            old_backup_start = gpt.header(source_fd, old_last_lba,
                                          SECTOR_SIZE, old_last_lba)[3] * SECTOR_SIZE
        tool_fd, tool_info = _open_regular(sfdisk, executable=True)
        try:
            if _digest(tool_fd, tool_info.st_size) != SFDISK_SHA256:
                raise ValueError("sfdisk differs from pinned signed fdisk package")
            with tempfile.NamedTemporaryFile(prefix=".disk.raw-", dir=destination.parent,
                                             delete=False) as temporary:
                temp_path = Path(temporary.name)
                temporary_fd = temporary.fileno()
                for offset in range(0, expected_bytes, CHUNK):
                    count = min(CHUNK, expected_bytes - offset)
                    block = os.pread(source_fd, count, offset)
                    if len(block) != count or temporary.write(block) != count:
                        raise ValueError("mkosi disk copy was incomplete")
                temporary.flush()
                os.ftruncate(temporary_fd, target_bytes)
                os.fsync(temporary_fd)
                if target_bytes != expected_bytes:
                    if sfdisk_runner is None:
                        environment = ({"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C",
                                        "HOME": "/nonexistent"} if sfdisk_env is None else sfdisk_env)
                        result = subprocess.run(
                            [str(sfdisk), "--relocate", "gpt-bak-std", str(temp_path)],
                            executable=f"/proc/self/fd/{tool_fd}", pass_fds=(tool_fd,),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=environment, check=False)
                        if result.returncode:
                            raise ValueError("pinned sfdisk could not relocate the backup GPT")
                    else:
                        sfdisk_runner(temp_path)
                    new_last_lba = target_bytes // SECTOR_SIZE - 1
                    new_backup_start = gpt.header(temporary_fd, new_last_lba,
                                                  SECTOR_SIZE, new_last_lba)[3] * SECTOR_SIZE
                    cleared = _remove_old_backup(temporary_fd, old_backup_start,
                                                 expected_bytes, new_backup_start, target_bytes)
                    os.fsync(temporary_fd)
                    for start, end in cleared:
                        _require_zero_range(temporary_fd, start, end)
                final_sha256 = _digest(temporary_fd, target_bytes)
                final = gpt.inspect(temp_path, final_sha256, target_bytes, SECTOR_SIZE)
                if (original["disk_guid"] != final["disk_guid"]
                        or original["partitions"] != final["partitions"]):
                    raise ValueError("GPT disk or partition identities changed")
                for part in original["partitions"]:
                    start = part["first_lba"] * SECTOR_SIZE
                    end = (part["last_lba"] + 1) * SECTOR_SIZE
                    _compare_range(source_fd, temporary_fd, start, end)
                if (_identity(os.fstat(source_fd)) != _identity(source_info)
                        or _digest(source_fd, expected_bytes) != expected_sha256
                        or _digest(tool_fd, tool_info.st_size) != SFDISK_SHA256
                        or os.fstat(temporary_fd).st_size != target_bytes
                        or _digest(temporary_fd, target_bytes) != final_sha256):
                    raise ValueError("input, pinned tool, or final disk changed during preparation")
            os.link(temp_path, destination, follow_symlinks=False)
            os.unlink(temp_path)
            temp_path = None
            directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            output_fd, output_info = _open_regular(destination)
            try:
                if output_info.st_size != target_bytes or _digest(output_fd, target_bytes) != final_sha256:
                    raise ValueError("published import disk differs from inspected bytes")
            finally:
                os.close(output_fd)
            return {"schema_version": 1,
                    "status": "diagnostic-import-sized-gpt-unapproved",
                    "mkosi_disk_sha256": expected_sha256,
                    "mkosi_disk_bytes": expected_bytes,
                    "raw_disk_sha256": final_sha256,
                    "raw_disk_bytes": target_bytes,
                    "sfdisk_sha256": SFDISK_SHA256,
                    "sfdisk_package_archive_sha256": SFDISK_PACKAGE_SHA256,
                    "sfdisk_archive_membership_rechecked": False,
                    "sfdisk_dynamic_runtime_authenticated": False,
                    "gpt_reinspected": True,
                    "partition_bytes_preserved": True,
                    "old_backup_gpt_removed": target_bytes != expected_bytes,
                    "full_image_reinspection_required": ["esp", "uki", "rootfs", "verity"],
                    "import_package_ready": False,
                    "image_built": False,
                    "private_mode_approved": False}
        finally:
            os.close(tool_fd)
    finally:
        os.close(source_fd)
        if temp_path is not None:
            os.unlink(temp_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mkosi_disk", type=Path)
    parser.add_argument("mkosi_disk_sha256")
    parser.add_argument("mkosi_disk_bytes", type=int)
    parser.add_argument("disk_raw", type=Path)
    parser.add_argument("--sfdisk", type=Path, default=SFDISK)
    args = parser.parse_args()
    try:
        report = _prepare(args.mkosi_disk, args.mkosi_disk_sha256,
                          args.mkosi_disk_bytes, args.disk_raw, args.sfdisk)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report = {"status": "blocked", "reason": str(error),
                  "import_package_ready": False, "private_mode_approved": False}
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
