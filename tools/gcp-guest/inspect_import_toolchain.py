#!/usr/bin/env python3
"""Compare import receipt claims with the reviewed signed Debian snapshot.

This offline diagnostic compares a self-reported producer receipt with three
authenticated package executables and checks one operator Python binary. A
matching receipt does not prove which code produced an archive. Python modules,
ELF libraries, the running host, and producer execution remain unverified. This
cannot authorize image import, deployment, or private mode.
"""

import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import sys
import tarfile

import debian_snapshot
import verify_builder_closure as closure
import verify_builder_packages as direct


TOOLS = {
    "tar": ("usr/bin/tar", "gnu_tar_sha256"),
    "gzip": ("usr/bin/gzip", "gnu_gzip_sha256"),
    "python3.13-minimal": ("usr/bin/python3.13", "python_executable_sha256"),
}
OPERATOR_PYTHON = Path("/usr/bin/python3")
EXPECTED_PYTHON_TARGET = Path("/usr/bin/python3.13")
HEX = debian_snapshot.HEX_SHA256


def executable_from_package(archive, relative_path):
    """Read one regular executable from an already signed-index-matched deb."""
    path = "./" + relative_path
    found = None
    with tarfile.open(fileobj=io.BytesIO(closure.deb_data_tar(archive)), mode="r:xz") as members:
        for member in members:
            if member.name not in {path, relative_path}:
                continue
            if found is not None or not member.isfile() or not member.mode & 0o111:
                raise ValueError("import executable is duplicate, non-regular, or not executable")
            stream = members.extractfile(member)
            if stream is None:
                raise ValueError("signed import executable cannot be read")
            found = stream.read()
            if len(found) != member.size or stream.read(1):
                raise ValueError("signed import executable has a wrong size")
    if found is None or not found.startswith(b"\x7fELF"):
        raise ValueError("signed import executable is absent or not ELF")
    return found


def regular_sha256(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise ValueError("operator Python must resolve to a regular executable")
        result = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError("operator Python changed during diagnostic")
        return result


def read_receipt(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("import receipt must be a regular file")
        data = stream.read()
        after = os.fstat(stream.fileno())
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError("import receipt changed during diagnostic")
    return json.loads(data, object_pairs_hook=direct.unique_object), hashlib.sha256(data).hexdigest()


def verify(inrelease, packages_index, archives, receipt_path, *,
           operator_python=OPERATOR_PYTHON):
    identities = direct.read_json(closure.IDENTITIES)
    snapshot = identities["downloaded_metadata"]["trixie_snapshot_candidate"]
    lock_bytes = debian_snapshot.bounded_regular_bytes(
        closure.LOCK, closure.LOCK_BYTES, "builder closure lock",
    )
    if (len(lock_bytes) != closure.LOCK_BYTES
            or hashlib.sha256(lock_bytes).hexdigest() != closure.LOCK_SHA256):
        raise ValueError("builder closure lock differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=direct.unique_object)
    if (lock["snapshot"] != snapshot["url"]
            or lock["status"] != "apt-resolved-candidate-unbuilt-unapproved"):
        raise ValueError("import packages do not use the reviewed snapshot")
    epoch, (index_hash, index_size), index_bytes = debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, snapshot["inrelease_sha256"],
    )
    if (epoch != snapshot["signed_release_date_epoch"]
            or index_hash != snapshot["main_binary_amd64_packages_xz_sha256"]
            or index_size != snapshot["main_binary_amd64_packages_xz_size"]):
        raise ValueError("import package index differs from reviewed signed snapshot")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("signed package archive directory missing or redirected")

    receipt, receipt_sha256 = read_receipt(receipt_path)
    if (not isinstance(receipt, dict) or receipt.get("toolchain_reviewed") is not False
            or receipt.get("private_mode_approved") is not False
            or receipt.get("oldgnu_single_member_checked") is not True
            or any(not isinstance(receipt.get(field), str)
                   or not HEX.fullmatch(receipt[field])
                   for _, field in TOOLS.values())):
        raise ValueError("candidate import receipt has invalid executable identities or status")

    selected = {}
    for entry in lock["packages"]:
        if entry["name"] in TOOLS:
            if entry["name"] in selected:
                raise ValueError("duplicate signed import package")
            selected[entry["name"]] = entry
    if set(selected) != set(TOOLS):
        raise ValueError("signed import package set incomplete")

    expected = {}
    for package, (relative_path, receipt_field) in TOOLS.items():
        entry = selected[package]
        record = records.get((package, entry["version"], entry["architecture"]))
        payload = closure.indexed_archive(entry, record, archives, keep_bytes=True)
        executable = executable_from_package(payload, relative_path)
        expected[package] = hashlib.sha256(executable).hexdigest()
        if receipt[receipt_field] != expected[package]:
            raise ValueError("producer import executable differs from signed package")

    # The operator verifier is separate from the archive producer. Accept only
    # the canonical Debian interpreter path used by the Rust package preparer.
    if operator_python.resolve(strict=True) != EXPECTED_PYTHON_TARGET:
        raise ValueError("operator Python does not resolve to reviewed Debian interpreter")
    if regular_sha256(EXPECTED_PYTHON_TARGET) != expected["python3.13-minimal"]:
        raise ValueError("operator Python differs from signed Debian package")
    return {
        "schema_version": 1,
        "status": "diagnostic-import-receipt-claims-match-signed-debian-unapproved",
        "signed_packages_index_sha256": index_hash,
        "builder_closure_lock_sha256": closure.LOCK_SHA256,
        "import_receipt_sha256": receipt_sha256,
        "receipt_claimed_tar_sha256": expected["tar"],
        "receipt_claimed_gzip_sha256": expected["gzip"],
        "receipt_claimed_python_sha256": expected["python3.13-minimal"],
        "operator_python_sha256": expected["python3.13-minimal"],
        "producer_execution_authenticated": False,
        "python_modules_verified": False,
        "elf_runtime_verified": False,
        "complete_import_toolchain": False,
        "deployment_approved": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.inrelease, args.packages_index, args.archives, args.receipt)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError,
            lzma.LZMAError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_import_toolchain": False,
                          "deployment_approved": False,
                          "private_mode_approved": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
