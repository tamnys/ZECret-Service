#!/usr/bin/env python3
"""Inspect a hash-pinned raw disk's ESP with signed, unpacked Debian tools.

This is a local diagnostic, not an image admission check. In particular, the
Python interpreter, libc, and the tools' other runtime inputs are not yet
bound to a complete installed builder. A signed UKI and its boot policy are
separate release gates.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile

import debian_snapshot
import inspect_raw_gpt as gpt
import prepare
import verify_builder_closure as closure
import verify_builder_packages as direct


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deploy/gcp/builder-closure.lock.json"
TOOL_MEMBERS = {
    "mtools": ("mtools", "usr/bin/mtools"),
    "systemd-ukify": ("systemd-ukify", "usr/bin/ukify"),
    "python3-pefile": ("python3-pefile", "usr/lib/python3/dist-packages/pefile.py"),
    "ordlookup-init": ("python3-pefile", "usr/lib/python3/dist-packages/ordlookup/__init__.py"),
    "ordlookup-oleaut32": ("python3-pefile", "usr/lib/python3/dist-packages/ordlookup/oleaut32.py"),
    "ordlookup-ws2_32": ("python3-pefile", "usr/lib/python3/dist-packages/ordlookup/ws2_32.py"),
    "ordlookup-wsock32": ("python3-pefile", "usr/lib/python3/dist-packages/ordlookup/wsock32.py"),
}
# The reviewed direct-UKI repart profile copies /efi to the ESP. A changed
# source profile or legitimate additional entry requires a new review.
EXPECTED_ESP_ENTRIES = (
    "::/EFI/",
    "::/EFI/BOOT/",
    "::/EFI/BOOT/BOOTX64.EFI",
)
# mdir -/ -a -b recursively lists hidden entries one path per line, while
# mcopy reads a named file without mounting the filesystem:
# https://www.gnu.org/software/mtools/manual/mtools.html
# ukify inspect --all --json reports each PE section's size and SHA-256:
# https://manpages.debian.org/trixie/systemd-ukify/ukify.1.en.html
REQUIRED_SECTIONS = frozenset({".cmdline", ".linux", ".initrd"})
# Pinned systemd-stub 257.13 interprets these optional UKI sections as boot
# inputs. The direct-UKI image profile has not reviewed any of them. In
# particular, .profile can select replacement .cmdline/.initrd sections by an
# EFI invocation argument, even when ukify's JSON map shows a safe base entry.
# https://manpages.debian.org/trixie/systemd-boot/sd-stub.7.en.html
UNREVIEWED_STUB_SECTIONS = frozenset({
    ".profile", ".ucode", ".dtb", ".dtbauto", ".hwids",
    ".splash", ".pcrsig", ".pcrpkey",
})


def regular_member_from_deb(data, member_path):
    """Extract one exact regular member; never execute package install scripts."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("signed tool archive is not a deb")
    offset = 8
    payload = None
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("malformed signed tool archive")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size_text = header[48:58].decode("ascii").strip()
        if not size_text.isdecimal():
            raise ValueError("malformed signed tool archive size")
        size = int(size_text)
        start = offset + 60
        end = start + size
        if end > len(data):
            raise ValueError("truncated signed tool archive")
        if name == "data.tar.xz":
            if payload is not None:
                raise ValueError("duplicate signed tool data member")
            payload = data[start:end]
        offset = end + size % 2
    if offset != len(data) or payload is None:
        raise ValueError("signed tool archive lacks unique data member")
    found = None
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as archive:
        for member in archive:
            if member.name in {member_path, "./" + member_path}:
                if found is not None or not member.isfile() or member.size <= 0:
                    raise ValueError("signed tool member is not unique and regular")
                found = archive.extractfile(member).read()
    if found is None:
        raise ValueError("signed tool member absent")
    return found


def authenticated_tools(inrelease, packages_index, archives):
    """Bind parser bytes to the reviewed lock and the signed Debian index."""
    lock_bytes = debian_snapshot.bounded_regular_bytes(
        LOCK, closure.LOCK_BYTES, "builder closure lock",
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
    tools = {}
    identities = {}
    for name, (package, member_path) in TOOL_MEMBERS.items():
        entry = entries[package]
        record = records.get((package, entry["version"], entry["architecture"]))
        archive = closure.indexed_archive(entry, record, archives, keep_bytes=True)
        tools[name] = regular_member_from_deb(archive, member_path)
        identities[package] = entry["sha256"]
    return tools, identities


def workspace_scratch(path):
    if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to("/workspace"):
        raise ValueError("scratch must be an existing workspace directory, not a symlink")
    return path


def copy_esp(raw_disk, partition, sector_size, expected_sha256, expected_bytes, target):
    start = partition["first_lba"] * sector_size
    length = (partition["last_lba"] - partition["first_lba"] + 1) * sector_size
    descriptor = os.open(raw_disk, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != expected_bytes
                or gpt.digest(descriptor, expected_bytes) != expected_sha256):
            raise ValueError("raw disk changed before ESP copy")
        with target.open("xb") as output:
            offset = 0
            while offset < length:
                chunk = gpt.read_at(descriptor, start + offset, min(1024 * 1024, length - offset))
                output.write(chunk)
                offset += len(chunk)
        if (os.fstat(descriptor).st_size != expected_bytes
                or gpt.digest(descriptor, expected_bytes) != expected_sha256):
            raise ValueError("raw disk changed during ESP copy")
    finally:
        os.close(descriptor)
    return length


def run_mtools(binary, command, image, root, *, destination=None):
    program_file = root / "mtools"
    if not program_file.exists():
        program_file.write_bytes(binary)
    with debian_snapshot.sealed_reviewed_file(
            program_file, hashlib.sha256(binary).hexdigest(), len(binary),
            "signed mtools executable", executable=True) as (program, fd):
        argv = [command, "-i", str(image)]
        if command == "mdir":
            argv += ["-/", "-a", "-b", "::"]
        elif command == "mcopy" and destination is not None:
            argv += ["::/EFI/BOOT/BOOTX64.EFI", str(destination)]
        else:
            raise ValueError("unsupported mtools operation")
        result = subprocess.run(
            argv, executable=str(program), pass_fds=(fd,), check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"HOME": str(root), "MTOOLSRC": "/dev/null", "LC_ALL": "C"},
        )
    if result.returncode != 0:
        raise ValueError(f"signed mtools {command} failed")
    return result.stdout


def pe_section_table(image):
    """Read the PE table and exact command-line bytes before consulting ukify."""
    descriptor = os.open(image, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("UKI is not a regular PE file")

        def read(offset, count):
            if offset < 0 or count < 0 or offset + count > info.st_size:
                raise ValueError("UKI PE section table is truncated")
            data = os.pread(descriptor, count, offset)
            if len(data) != count:
                raise ValueError("UKI PE section table changed during inspection")
            return data

        dos = read(0, 64)
        if dos[:2] != b"MZ":
            raise ValueError("UKI lacks DOS PE header")
        pe_offset = struct.unpack_from("<I", dos, 0x3c)[0]
        coff = read(pe_offset, 24)
        if coff[:4] != b"PE\0\0":
            raise ValueError("UKI lacks PE signature")
        machine, count = struct.unpack_from("<HH", coff, 4)
        optional_size = struct.unpack_from("<H", coff, 20)[0]
        if machine != 0x8664 or count == 0 or optional_size < 2:
            raise ValueError("UKI is not an x86_64 PE32+ image")
        optional_start = pe_offset + len(coff)
        if struct.unpack("<H", read(optional_start, 2))[0] != 0x20b:
            raise ValueError("UKI is not an x86_64 PE32+ image")
        section_start = optional_start + optional_size
        if section_start + count * 40 > info.st_size:
            raise ValueError("UKI PE section table is truncated")
        names = []
        cmdline = None
        seen = set()
        for index in range(count):
            section = read(section_start + index * 40, 40)
            raw_name = section[:8]
            name_bytes = raw_name.partition(b"\0")[0]
            if (not name_bytes or any(raw_name[len(name_bytes):])
                    or not name_bytes.startswith(b".")):
                raise ValueError("UKI PE section has an invalid name")
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError as error:
                raise ValueError("UKI PE section has an invalid name") from error
            if name in seen:
                raise ValueError(f"duplicate UKI PE section: {name}")
            if name in UNREVIEWED_STUB_SECTIONS:
                raise ValueError(f"unreviewed UKI boot section: {name}")
            virtual_size = struct.unpack_from("<I", section, 8)[0]
            raw_size, raw_offset = struct.unpack_from("<II", section, 16)
            if raw_size and (raw_offset == 0 or raw_offset + raw_size > info.st_size):
                raise ValueError("UKI PE section data is outside the image")
            if name == ".cmdline":
                # Pinned ukify and systemd-stub use the PE virtual size for
                # section content. Never accept a display string that omits
                # bytes the stub may read, or a virtual size beyond disk data.
                expected = len(b"roothash=") + 64 + 1 + len(
                    prepare.FIXED_KERNEL_CMDLINE.encode("ascii"))
                if virtual_size not in (expected, expected + 1) or virtual_size > raw_size:
                    raise ValueError("UKI command-line section size differs")
                cmdline = read(raw_offset, virtual_size)
            seen.add(name)
            names.append(name)
        return names, cmdline
    finally:
        os.close(descriptor)


def pe_section_names(image):
    """Read the actual PE section names; a JSON object hides duplicates."""
    return pe_section_table(image)[0]


def reviewed_cmdline(raw, details):
    """Match the extracted boot bytes, then cross-check ukify's digest/text."""
    if raw is None:
        raise ValueError("UKI required command-line section absent")
    fixed = prepare.FIXED_KERNEL_CMDLINE.encode("ascii")
    suffix = b" " + fixed
    prefix = b"roothash="
    # ukify may emit a single terminal NUL; embedded or multiple NUL bytes,
    # newlines, duplicate hashes and additional kernel options are rejected.
    logical = raw[:-1] if raw.endswith(b"\0") else raw
    if (len(raw) not in (len(prefix) + 64 + len(suffix),
                         len(prefix) + 64 + len(suffix) + 1)
            or not logical.startswith(prefix)
            or not logical.endswith(suffix)
            or not re.fullmatch(rb"[0-9a-f]{64}", logical[len(prefix):len(prefix) + 64])):
        raise ValueError("UKI command line differs from reviewed boot profile")
    text = logical.decode("ascii")
    if (details["size"] != len(raw)
            or details["sha256"] != hashlib.sha256(raw).hexdigest()
            or details.get("text") != text):
        raise ValueError("ukify command-line report differs from PE bytes")
    return text


def section_report(ukify, pefile, ordlookup, image, root):
    section_names, raw_cmdline = pe_section_table(image)
    script = root / "ukify"
    module = root / "pefile.py"
    script.write_bytes(ukify)
    module.write_bytes(pefile)
    lookup = root / "ordlookup"
    lookup.mkdir()
    for filename, data in ordlookup.items():
        (lookup / filename).write_bytes(data)
    with debian_snapshot.sealed_reviewed_file(
            script, hashlib.sha256(ukify).hexdigest(), len(ukify),
            "signed ukify script") as (program, fd):
        result = subprocess.run(
            [sys.executable, "-S", str(program), "inspect", str(image),
             "--json=short", "--all", "--config=/dev/null"],
            pass_fds=(fd,), check=False, capture_output=True,
            env={"HOME": str(root), "PYTHONPATH": str(root),
                 "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                 "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    if result.returncode != 0:
        raise ValueError("signed ukify inspect failed")
    sections = json.loads(result.stdout, object_pairs_hook=direct.unique_object)
    if not isinstance(sections, dict) or set(sections) != set(section_names):
        raise ValueError("ukify section map differs from PE section table")
    if not REQUIRED_SECTIONS <= sections.keys():
        raise ValueError("UKI required sections absent")
    for name, details in sections.items():
        if (not isinstance(name, str) or not name.startswith(".")
                or not isinstance(details, dict)
                or type(details.get("size")) is not int or details["size"] < 0
                or not isinstance(details.get("sha256"), str)
                or not debian_snapshot.HEX_SHA256.fullmatch(details["sha256"])):
            raise ValueError("invalid UKI section report")
    if any(sections[name]["size"] == 0 for name in REQUIRED_SECTIONS):
        raise ValueError("UKI required section empty")
    cmdline = reviewed_cmdline(raw_cmdline, sections[".cmdline"])
    return {name: {"size": details["size"], "sha256": details["sha256"]}
            for name, details in sections.items()}, cmdline


def inspect(raw_disk, expected_sha256, expected_bytes, sector_size,
            inrelease, packages_index, archives, scratch):
    if platform.machine() != "x86_64":
        raise ValueError("reviewed Debian parser tools require x86_64 Linux")
    prepare.validate_boot_profile()
    scratch = workspace_scratch(scratch)
    tools, identities = authenticated_tools(inrelease, packages_index, archives)
    layout = gpt.inspect(raw_disk, expected_sha256, expected_bytes, sector_size)
    esp = next(entry for entry in layout["partitions"] if entry["type"] == "esp")
    with tempfile.TemporaryDirectory(prefix="zrpc-esp-inspect-", dir=scratch) as temporary:
        root = Path(temporary)
        esp_image = root / "esp.img"
        esp_bytes = copy_esp(raw_disk, esp, sector_size, expected_sha256,
                             expected_bytes, esp_image)
        listing = run_mtools(tools["mtools"], "mdir", esp_image, root)
        entries = tuple(listing.decode("utf-8").splitlines())
        if entries != EXPECTED_ESP_ENTRIES:
            raise ValueError("ESP inventory differs from direct-UKI profile")
        uki = root / "BOOTX64.EFI"
        run_mtools(tools["mtools"], "mcopy", esp_image, root, destination=uki)
        uki_info = uki.lstat()
        if not stat.S_ISREG(uki_info.st_mode) or not 0 < uki_info.st_size <= esp_bytes:
            raise ValueError("extracted UKI has invalid type or size")
        sections, cmdline = section_report(
            tools["systemd-ukify"], tools["python3-pefile"],
            {"__init__.py": tools["ordlookup-init"],
             "oleaut32.py": tools["ordlookup-oleaut32"],
             "ws2_32.py": tools["ordlookup-ws2_32"],
             "wsock32.py": tools["ordlookup-wsock32"]},
            uki, root,
        )
        with uki.open("rb") as stream:
            uki_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "status": "diagnostic-esp-uki-sections-unapproved",
        "raw_disk_sha256": expected_sha256,
        "raw_disk_bytes": expected_bytes,
        "esp_partition_guid": esp["partition_guid"],
        "esp_bytes": esp_bytes,
        "esp_inventory": list(entries),
        "uki_sha256": uki_hash,
        "uki_bytes": uki_info.st_size,
        "uki_sections": sections,
        "uki_cmdline_for_review": cmdline,
        "signed_tool_archives_sha256": identities,
        "complete_builder_toolchain": False,
        "signed_uki_checked": False,
        "cmdline_approved": False,
        "dm_verity_checked": False,
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
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError,
            tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False,
                          "signed_uki_checked": False,
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
