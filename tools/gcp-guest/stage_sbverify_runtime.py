#!/usr/bin/env python3
"""Stage exact signed-snapshot sbverify ELF objects as data, without installation.

This tool does not perform UKI verification or approve the signer or release.
It rechecks the source-reviewed builder-closure lock and the selected package
archives. It relies on the separate prior signed-index authentication receipt;
it does not revalidate InRelease or Packages.xz on this invocation.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

import debian_snapshot
import verify_builder_closure as closure


OBJECTS = (
    ("sbverify", "sbsigntool", "usr/bin/sbverify", 64872,
     "e4cfb5bf60a8dd2034d728af0f7bf3dd1398f6420473c7bc19a0623fcd003881"),
    ("ld-linux-x86-64.so.2", "libc6", None, 225672,
     "c8438e4fde1934e61c88311633f00949ff645d5c04cdb8671fa3d78164d2f307"),
    ("libc.so.6", "libc6", None, 1995216,
     "9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92"),
    ("libz.so.1", "zlib1g", None, 125376,
     "85590dd58edf5445e18bc7193e5ebc01ac5841f1ae187e97705a662e90c6421e"),
    ("libzstd.so.1", "libzstd1", None, 825336,
     "27f07c9a49c2c956bcfb64cd4712976586a66facbf15fc7f09bc37413b5f2b21"),
    ("libcrypto.so.3", "libssl3t64", None, 6517312,
     "8bb5f3fdffe280d4453eb79a4663c2c47af70b7c247fe2e94e2da703cee1fd3d"),
)


def _program_from_package(data):
    found = None
    with tarfile.open(fileobj=io.BytesIO(closure.deb_data_tar(data)), mode="r:xz") as archive:
        for member in archive:
            if member.name in {"./usr/bin/sbverify", "usr/bin/sbverify"}:
                if found is not None or not member.isfile():
                    raise ValueError("signed sbsigntool archive has no unique regular sbverify")
                found = archive.extractfile(member).read()
    if found is None:
        raise ValueError("signed sbsigntool archive has no unique regular sbverify")
    return found


def _archive(entry, directory):
    path = directory / (entry["sha256"] + ".deb")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != entry["size"]:
            raise ValueError("signed sbverify provider archive size differs from lock")
        data = stream.read(entry["size"] + 1)
    if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("signed sbverify provider archive hash differs from lock")
    return data


def stage(archives, output):
    lock_bytes = debian_snapshot.bounded_regular_bytes(
        closure.LOCK, closure.LOCK_BYTES, "builder closure lock",
    )
    if (len(lock_bytes) != closure.LOCK_BYTES
            or hashlib.sha256(lock_bytes).hexdigest() != closure.LOCK_SHA256):
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes)
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("signed provider archive directory missing or redirected")
    packages = {entry["name"]: entry for entry in lock["packages"]}
    staged = {}
    archive_cache = {}
    for name, package, program, size, digest in OBJECTS:
        entry = packages[package]
        if package not in archive_cache:
            archive_cache[package] = _archive(entry, archives)
        data = (_program_from_package(archive_cache[package]) if program is not None
                else closure.package_elf(archive_cache[package], name))
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("signed sbverify runtime member differs from source review")
        staged[name] = data
    # Do not overwrite an existing directory or any operator-owned artifacts.
    output.mkdir(mode=0o700)
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for name, data in staged.items():
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=directory_fd,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
    finally:
        os.close(directory_fd)
    return {
        "status": "diagnostic-sbverify-objects-staged-unapproved",
        "builder_closure_lock_sha256": closure.LOCK_SHA256,
        "objects": {name: hashlib.sha256(data).hexdigest()
                    for name, data in staged.items()},
        "release_approved": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(stage(args.archives, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "release_approved": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
