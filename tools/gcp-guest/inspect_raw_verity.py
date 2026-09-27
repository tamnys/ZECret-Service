#!/usr/bin/env python3
"""Verify a raw image's root/verity pair against its exact UKI roothash.

This is an offline diagnostic, not image admission. The signed Debian
veritysetup ELF and its initial loader objects are sealed and checked, but
Python, gpgv, ESP parser runtimes, later library loads, boot behavior, and
hardware measurements do not have a complete release closure here.
"""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile

import debian_snapshot
import inspect_raw_esp as esp
import inspect_raw_gpt as gpt
import verify_builder_closure as closure
import verify_builder_packages as direct


# Exact SONAME providers observed for cryptsetup-bin 2:2.7.5-2 in the
# source-reviewed 20260918 signed Debian snapshot. The signed loader's --list
# must report precisely these sealed objects before veritysetup is run.
ELF_PROVIDERS = (
    ("libcryptsetup.so.12", "libcryptsetup12"),
    ("libpopt.so.0", "libpopt0"),
    ("libblkid.so.1", "libblkid1"),
    ("libc.so.6", "libc6"),
    ("libuuid.so.1", "libuuid1"),
    ("libdevmapper.so.1.02.1", "libdevmapper1.02.1"),
    ("libcrypto.so.3", "libssl3t64"),
    ("libjson-c.so.5", "libjson-c5"),
    ("libselinux.so.1", "libselinux1"),
    ("libudev.so.1", "libudev1"),
    ("libm.so.6", "libc6"),
    ("libz.so.1", "zlib1g"),
    ("libzstd.so.1", "libzstd1"),
    ("libpcre2-8.so.0", "libpcre2-8-0"),
    ("libcap.so.2", "libcap2"),
)


def authenticated_toolchain(inrelease, packages_index, archives):
    """Extract exact executable/ELF bytes from the reviewed signed closure."""
    lock_bytes = debian_snapshot.bounded_regular_bytes(
        esp.LOCK, closure.LOCK_BYTES, "builder closure lock",
    )
    if (len(lock_bytes) != closure.LOCK_BYTES
            or hashlib.sha256(lock_bytes).hexdigest() != closure.LOCK_SHA256):
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=direct.unique_object)
    if (lock.get("schema_version") != 1
            or lock.get("status") != "apt-resolved-candidate-unbuilt-unapproved"):
        raise ValueError("unsupported builder closure lock")
    snapshot_time = datetime.strptime(
        lock["snapshot"].rstrip("/").rsplit("/", 1)[-1], "%Y%m%dT%H%M%SZ",
    ).replace(tzinfo=timezone.utc)
    debian_snapshot.require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    epoch, (index_hash, _), index_bytes = debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, lock["inrelease_sha256"],
    )
    if (epoch != lock["signed_release_date_epoch"]
            or index_hash != lock["packages_index_sha256"]):
        raise ValueError("signed tool index differs from reviewed builder candidate")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("signed tool archive directory missing or redirected")
    entries = {entry["name"]: entry for entry in lock["packages"]}
    needed = {"cryptsetup-bin", "libc6", *(name for _, name in ELF_PROVIDERS)}
    packages = {}
    identities = {}
    for name in sorted(needed):
        entry = entries[name]
        record = records.get((name, entry["version"], entry["architecture"]))
        packages[name] = closure.indexed_archive(
            entry, record, archives, keep_bytes=True,
        )
        identities[name] = entry["sha256"]
    program = esp.regular_member_from_deb(
        packages["cryptsetup-bin"], "usr/sbin/veritysetup",
    )
    if not program.startswith(b"\x7fELF"):
        raise ValueError("signed veritysetup member is not ELF")
    loader = closure.package_elf(packages["libc6"], "ld-linux-x86-64.so.2")
    libraries = tuple(
        (soname, closure.package_elf(packages[name], soname))
        for soname, name in ELF_PROVIDERS
    )
    return program, loader, libraries, identities


def run_verity(toolchain, arguments, scratch):
    """Run one reviewed command with no ambient initial ELF loader objects."""
    program_bytes, loader_bytes, libraries, _ = toolchain
    if scratch.is_symlink() or not scratch.is_dir():
        raise ValueError("verity scratch directory missing or redirected")
    with tempfile.TemporaryDirectory(prefix="zrpc-verity-libs-", dir=scratch) as empty_lib, ExitStack() as stack:
        program, program_fd = stack.enter_context(
            closure.sealed_elf_bytes(program_bytes))
        loader, loader_fd = stack.enter_context(
            closure.sealed_elf_bytes(loader_bytes))
        preloads = []
        descriptors = [program_fd, loader_fd]
        for _, data in libraries:
            path, descriptor = stack.enter_context(closure.sealed_elf_bytes(data))
            preloads.append(path)
            descriptors.append(descriptor)
        prefix = [str(loader), "--inhibit-cache", "--preload",
                  ":".join(map(str, preloads)), "--library-path", empty_lib]
        environment = {"HOME": empty_lib, "LC_ALL": "C", "PATH": empty_lib}
        inspected = subprocess.run(
            [*prefix, "--list", str(program)], pass_fds=descriptors,
            env=environment, capture_output=True, text=True, check=False,
        )
        closure.check_loader_report(inspected, loader, preloads)
        result = subprocess.run(
            [*prefix, str(program), *arguments], pass_fds=descriptors,
            env=environment, capture_output=True, text=True, check=False,
        )
    if result.returncode != 0 or result.stderr.strip():
        raise ValueError("signed veritysetup operation failed")
    return result.stdout


def partition_images(raw_disk, layout, expected_sha256, expected_bytes,
                     sector_size, root):
    """Copy the exact GPT data/hash extents from one hash-pinned raw file."""
    selected = {
        kind: next(entry for entry in layout["partitions"] if entry["type"] == kind)
        for kind in ("root-x86-64", "root-x86-64-verity")
    }
    descriptor = os.open(raw_disk, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != expected_bytes
                or gpt.digest(descriptor, expected_bytes) != expected_sha256):
            raise ValueError("raw disk changed before root/verity copy")
        images = {}
        for kind, partition in selected.items():
            start = partition["first_lba"] * sector_size
            length = (partition["last_lba"] - partition["first_lba"] + 1) * sector_size
            target = root / ("root.img" if kind == "root-x86-64" else "hash.img")
            with target.open("xb") as output:
                offset = 0
                while offset < length:
                    chunk = gpt.read_at(
                        descriptor, start + offset, min(1024 * 1024, length - offset),
                    )
                    output.write(chunk)
                    offset += len(chunk)
            images[kind] = (target, length, partition["partition_guid"])
        if (os.fstat(descriptor).st_size != expected_bytes
                or gpt.digest(descriptor, expected_bytes) != expected_sha256):
            raise ValueError("raw disk changed during root/verity copy")
        return images
    finally:
        os.close(descriptor)


def verity_header(output, root_bytes):
    """Require full data-partition coverage under the signed tool's header."""
    wanted = {"Hash type", "Data blocks", "Data block size",
              "Hash block size", "Hash algorithm"}
    fields = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name, value = name.strip(), value.strip()
        if name in wanted:
            if name in fields or not value:
                raise ValueError("verity superblock report is ambiguous")
            fields[name] = value
    if set(fields) != wanted:
        raise ValueError("verity superblock report lacks required fields")
    if fields["Hash algorithm"] != "sha256" or fields["Hash type"] != "1":
        raise ValueError("verity superblock hash profile differs")
    for name in ("Data blocks", "Data block size", "Hash block size"):
        if not re.fullmatch(r"[1-9][0-9]*", fields[name]):
            raise ValueError("verity superblock block count or size differs")
    blocks = int(fields["Data blocks"])
    data_size = int(fields["Data block size"])
    hash_size = int(fields["Hash block size"])
    if blocks * data_size != root_bytes:
        raise ValueError("verity superblock does not cover the full root partition")
    return {"hash_type": 1, "hash_algorithm": "sha256", "data_blocks": blocks,
            "data_block_size": data_size, "hash_block_size": hash_size}


def inspect(raw_disk, expected_sha256, expected_bytes, sector_size,
            inrelease, packages_index, archives, scratch):
    if platform.machine() != "x86_64":
        raise ValueError("reviewed Debian verity tools require x86_64 Linux")
    scratch = esp.workspace_scratch(scratch)
    # The ESP inspector reads exact PE .cmdline bytes, checks them against the
    # reviewed profile, and rejects replacement sections and ESP companions.
    boot = esp.inspect(raw_disk, expected_sha256, expected_bytes, sector_size,
                       inrelease, packages_index, archives, scratch)
    roothash = boot["uki_cmdline_for_review"].split(" ", 1)[0].removeprefix("roothash=")
    if not re.fullmatch(r"[0-9a-f]{64}", roothash):
        raise ValueError("reviewed UKI roothash absent")
    layout = gpt.inspect(raw_disk, expected_sha256, expected_bytes, sector_size)
    toolchain = authenticated_toolchain(inrelease, packages_index, archives)
    with tempfile.TemporaryDirectory(prefix="zrpc-verity-inspect-", dir=scratch) as temporary:
        root = Path(temporary)
        images = partition_images(raw_disk, layout, expected_sha256,
                                  expected_bytes, sector_size, root)
        data_image, data_bytes, data_guid = images["root-x86-64"]
        hash_image, hash_bytes, hash_guid = images["root-x86-64-verity"]
        header = verity_header(
            run_verity(toolchain, ["dump", str(hash_image)], root), data_bytes,
        )
        run_verity(toolchain, ["verify", str(data_image), str(hash_image), roothash], root)
    return {
        "status": "diagnostic-raw-root-verity-unapproved",
        "raw_disk_sha256": expected_sha256,
        "raw_disk_bytes": expected_bytes,
        "uki_sha256": boot["uki_sha256"],
        "uki_cmdline_for_review": boot["uki_cmdline_for_review"],
        "root_partition_guid": data_guid,
        "root_partition_bytes": data_bytes,
        "verity_partition_guid": hash_guid,
        "verity_partition_bytes": hash_bytes,
        "verity_header": header,
        "verity_userspace_verified": True,
        "signed_tool_archives_sha256": toolchain[3],
        "complete_builder_toolchain": False,
        "signed_uki_checked": False,
        "cmdline_approved": False,
        "dm_verity_boot_checked": False,
        "image_built": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_disk", type=Path)
    parser.add_argument("expected_sha256")
    parser.add_argument("expected_bytes", type=int)
    parser.add_argument("sector_size", type=int)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect(args.raw_disk, args.expected_sha256, args.expected_bytes,
                         args.sector_size, args.inrelease, args.packages_index,
                         args.archives, args.scratch)
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False,
                          "verity_userspace_verified": False,
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
