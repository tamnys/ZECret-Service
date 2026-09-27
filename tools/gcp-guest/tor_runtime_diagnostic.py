#!/usr/bin/env python3
"""Stage one authenticated Tor executable for a networkless native CI diagnostic.

The reviewed builder lock bootstraps the exact gpgv binary. Debian's signed
snapshot then authenticates Tor and libevent archives. No package is installed,
no maintainer script runs, and this does not approve Tor or private mode.
"""

import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import sys
import tarfile
import urllib.error

import debian_snapshot
import fetch_builder_closure
import fetch_guest_closure
import verify_builder_closure
import verify_builder_packages


GPGV = {
    "name": "gpgv", "version": "2.4.7-21+deb13u1+b5", "architecture": "amd64",
    "filename": "pool/main/g/gnupg2/gpgv_2.4.7-21+deb13u1+b5_amd64.deb",
    "size": 241100,
    "sha256": "104e4c57b98f0b883aa94c68fbe7ec7b48bcdec7c0f9dedf2a51a5054aaeb5ae",
}
TOR = {
    "name": "tor", "version": "0.4.9.11-0+deb13u1", "architecture": "amd64",
    "filename": "pool/main/t/tor/tor_0.4.9.11-0+deb13u1_amd64.deb",
    "size": 2087008,
    "sha256": "2381888dc083316fa59a675434decdf94e3869c34eb1e17a6b54fc9d5a041b98",
}
LIBEVENT = {
    "name": "libevent-2.1-7t64", "version": "2.1.12-stable-10+b1",
    "architecture": "amd64",
    "filename": "pool/main/libe/libevent/libevent-2.1-7t64_2.1.12-stable-10+b1_amd64.deb",
    "size": 181612,
    "sha256": "5b2201fe46d8710bc4b2566abe0a3e29c63dd94779644f6d32c777a5281c86a3",
}
TOR_ELF_SHA256 = "2e0a57ea04c80865fd38e9bbde7219ed19d1b5c34cc5ed5b3f98cc3a6adf19ef"
TOR_ELF_BYTES = 3647448
LIBEVENT_ELF_SHA256 = "0ddb193589335d52561359545965db42885e9f4ea1f681ec012863f2c6498b10"
LIBEVENT_ELF_BYTES = 350608


def require_pin(data, expected_size, expected_hash, label):
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError(f"{label} differs from reviewed bytes")
    return data


def builder_gpgv_entry(lock_path=verify_builder_closure.LOCK):
    data = debian_snapshot.bounded_regular_bytes(
        lock_path, verify_builder_closure.LOCK_BYTES, "builder closure lock"
    )
    require_pin(data, verify_builder_closure.LOCK_BYTES,
                verify_builder_closure.LOCK_SHA256, "builder closure lock")
    lock = json.loads(data, object_pairs_hook=verify_builder_packages.unique_object)
    if (lock.get("snapshot") != fetch_guest_closure.SNAPSHOT
            or not isinstance(lock.get("packages"), list)
            or [entry for entry in lock["packages"] if entry.get("name") == "gpgv"] != [GPGV]):
        raise ValueError("reviewed builder closure lacks exact gpgv archive")
    return GPGV


def signed_record(records, entry):
    record = records.get((entry["name"], entry["version"], entry["architecture"]))
    if record is None or any(str(entry[field]) != record.get(index_field)
                             for field, index_field in (("filename", "Filename"),
                                                        ("size", "Size"),
                                                        ("sha256", "SHA256"))):
        raise ValueError(f'{entry["name"]} differs from signed snapshot')
    return record


def fetch_archive(archives, entry, record):
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("archive cache missing or redirected")
    directory = os.open(archives, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not fetch_builder_closure.verify_cached(directory, entry):
            fetch_builder_closure.download_one(directory, entry, fetch_guest_closure.SNAPSHOT)
        if not fetch_builder_closure.verify_cached(directory, entry):
            raise ValueError("reviewed archive missing after download")
    finally:
        os.close(directory)
    return verify_builder_closure.indexed_archive(entry, record, archives, keep_bytes=True)


def regular_member(data, member_name, expected_size, expected_hash):
    found = None
    try:
        with tarfile.open(fileobj=io.BytesIO(verify_builder_closure.deb_data_tar(data)),
                          mode="r:xz") as archive:
            for member in archive:
                if member.name in {member_name, "./" + member_name}:
                    if found is not None or not member.isfile() or member.size != expected_size:
                        raise ValueError("reviewed executable is not one regular archive member")
                    with archive.extractfile(member) as stream:
                        found = stream.read(expected_size + 1)
    except (lzma.LZMAError, tarfile.TarError) as error:
        raise ValueError("invalid reviewed executable archive") from error
    if found is None or not found.startswith(b"\x7fELF"):
        raise ValueError("reviewed executable ELF missing")
    return require_pin(found, expected_size, expected_hash, "reviewed executable ELF")


def write_executable(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o500)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), 0o500)
        os.fsync(stream.fileno())


def stage_gpgv(archives, output):
    entry = builder_gpgv_entry()
    record = {"Filename": entry["filename"], "Size": str(entry["size"]),
              "SHA256": entry["sha256"]}
    data = fetch_archive(archives, entry, record)
    elf = regular_member(data, "usr/bin/gpgv", debian_snapshot.GPGV_SIZE,
                         debian_snapshot.GPGV_SHA256)
    output.mkdir(mode=0o700)
    write_executable(output / "gpgv", elf)
    return {"status": "reviewed-gpgv-bootstrapped-for-diagnostic",
            "gpgv_sha256": debian_snapshot.GPGV_SHA256}


def signed_records(metadata):
    fetch_guest_closure.reviewed_snapshot_time()
    if metadata.is_symlink() or not metadata.is_dir():
        raise ValueError("snapshot metadata missing or redirected")
    descriptor = os.open(metadata, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held = Path(f"/proc/self/fd/{descriptor}")
        epoch, (index_hash, index_size), data = debian_snapshot.authenticated_index_bytes(
            held / "InRelease", held / "Packages.xz", fetch_guest_closure.INRELEASE_SHA256
        )
    finally:
        os.close(descriptor)
    if (epoch != fetch_guest_closure.SIGNED_RELEASE_EPOCH
            or index_hash != fetch_guest_closure.PACKAGES_SHA256
            or index_size != fetch_guest_closure.PACKAGES_SIZE):
        raise ValueError("signed snapshot differs from reviewed candidate")
    return debian_snapshot.package_records(io.BytesIO(data))


def stage_tor(metadata, archives, output):
    records = signed_records(metadata)
    tor_data = fetch_archive(archives, TOR, signed_record(records, TOR))
    event_data = fetch_archive(archives, LIBEVENT, signed_record(records, LIBEVENT))
    tor = regular_member(tor_data, "usr/bin/tor", TOR_ELF_BYTES, TOR_ELF_SHA256)
    event = verify_builder_closure.package_elf(event_data, "libevent-2.1.so.7")
    require_pin(event, LIBEVENT_ELF_BYTES, LIBEVENT_ELF_SHA256, "libevent ELF")
    output.mkdir(mode=0o700)
    (output / "lib").mkdir(mode=0o700)
    write_executable(output / "tor", tor)
    write_executable(output / "lib/libevent-2.1.so.7", event)
    return {"status": "signed-tor-runtime-staged-for-diagnostic",
            "tor_sha256": TOR_ELF_SHA256, "libevent_sha256": LIBEVENT_ELF_SHA256,
            "signed_snapshot_rechecked": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    gpgv = subcommands.add_parser("stage-gpgv")
    gpgv.add_argument("--archives", type=Path, required=True)
    gpgv.add_argument("--output", type=Path, required=True)
    tor = subcommands.add_parser("stage-tor")
    tor.add_argument("--metadata", type=Path, required=True)
    tor.add_argument("--archives", type=Path, required=True)
    tor.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "stage-gpgv":
            result = stage_gpgv(args.archives, args.output)
        else:
            result = stage_tor(args.metadata, args.archives, args.output)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, urllib.error.URLError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "tor_executed": False, "private_mode_approved": False}))
        return 1
    result.update({"tor_executed": False, "private_mode_approved": False})
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
