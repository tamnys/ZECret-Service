#!/usr/bin/env python3
"""Inventory inert control files in the authenticated guest Debian closure.

No maintainer script, trigger, package installer, image builder, or signing
operation is executed. This is review input, never release approval.
"""

import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import tarfile

import fetch_guest_closure as guest
import stage_builder_toolchain as builder


STATUS = "diagnostic-authenticated-guest-control-inventory-unreviewed"
SCRIPT_NAMES = {"config", "preinst", "postinst", "prerm", "postrm"}
# These are the only control member names observed in the exact reviewed
# 104-package closure. A changed closure must undergo a new member review.
CONTROL_NAMES = SCRIPT_NAMES | {
    "control", "conffiles", "md5sums", "shlibs", "symbols", "templates", "triggers",
}
# Measured maximum decoded control.tar size among the signed 104 archives:
# libstdc++6 has 440,320 bytes. A new package set requires a new bound review.
MAX_CONTROL_TAR_BYTES = 440_320
AR_MAGIC = b"!<arch>\n"
AR_MEMBERS = ("debian-binary", "control.tar.xz", "data.tar.xz")


def control_tar(archive):
    """Return the unique xz control member from one exact-shape Debian ar."""
    if not archive.startswith(AR_MAGIC):
        raise ValueError("guest archive is not a Debian ar")
    offset = len(AR_MAGIC)
    members = []
    while offset < len(archive):
        header = archive[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("malformed guest ar header")
        try:
            name = header[:16].decode("ascii").strip().removesuffix("/")
            size_text = header[48:58].decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise ValueError("non-ASCII guest ar header") from error
        if not size_text.isdecimal():
            raise ValueError("malformed guest ar member size")
        size = int(size_text)
        start = offset + 60
        end = start + size
        if end > len(archive) or (size % 2 and (end >= len(archive) or archive[end:end + 1] != b"\n")):
            raise ValueError("truncated guest ar member")
        members.append((name, archive[start:end]))
        offset = end + size % 2
    if offset != len(archive) or tuple(name for name, _ in members) != AR_MEMBERS:
        raise ValueError("guest Debian ar member set differs from reviewed closure")
    if members[0][1] != b"2.0\n":
        raise ValueError("unsupported guest Debian archive version")
    return members[1][1]


def control_entries(archive):
    """Hash all regular control files, including every executable hook."""
    compressed = control_tar(archive)
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        decoded = decoder.decompress(compressed, max_length=MAX_CONTROL_TAR_BYTES + 1)
    except lzma.LZMAError as error:
        raise ValueError("invalid guest control xz member") from error
    if (len(decoded) > MAX_CONTROL_TAR_BYTES or not decoder.eof
            or decoder.unused_data):
        raise ValueError("guest control tar exceeds reviewed shape or has trailing data")

    rows = []
    seen = set()
    root_seen = False
    try:
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as contents:
            for member in contents:
                if member.name in {".", "./"}:
                    if root_seen or not member.isdir():
                        raise ValueError("guest control tar has invalid root entry")
                    root_seen = True
                    continue
                if (not member.name.startswith("./")
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", member.name[2:])):
                    raise ValueError("unsafe guest control member path")
                name = member.name[2:]
                if name not in CONTROL_NAMES or name in seen or not member.isfile():
                    raise ValueError("unreviewed, repeated, or non-regular guest control member")
                stream = contents.extractfile(member)
                if stream is None:
                    raise ValueError("unreadable guest control member")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError("truncated guest control member")
                seen.add(name)
                kind = ("maintainer_script" if name in SCRIPT_NAMES else
                        "trigger_declarations" if name == "triggers" else "metadata")
                rows.append({"name": name, "kind": kind, "mode": member.mode,
                             "bytes": len(data),
                             "sha256": hashlib.sha256(data).hexdigest()})
    except tarfile.TarError as error:
        raise ValueError("invalid guest control tar") from error
    if not root_seen or "control" not in seen:
        raise ValueError("guest control tar lacks required entries")
    return hashlib.sha256(compressed).hexdigest(), sorted(rows, key=lambda row: row["name"])


def inventory(metadata, archives):
    # Authenticates the source-reviewed manifest through Debian's signed
    # snapshot and checks every archived byte before control parsing.
    identities = guest.authenticated_packages(Path(metadata))
    directory = guest.open_directory(Path(archives), "guest archive")
    packages = []
    try:
        for identity in identities:
            archive = builder.locked_archive(
                {key: identity[key] for key in builder.closure.PACKAGE_FIELDS},
                directory,
            )
            control_sha256, members = control_entries(archive)
            packages.append({
                "name": identity["name"], "version": identity["version"],
                "architecture": identity["architecture"],
                "archive_sha256": identity["sha256"],
                "control_tar_xz_sha256": control_sha256,
                "members": members,
            })
    finally:
        os.close(directory)
    encoded = json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
    all_members = [member for package in packages for member in package["members"]]
    return {
        "schema_version": 1, "status": STATUS,
        "guest_package_closure_sha256": guest.prepare.PACKAGE_CLOSURE_SHA256,
        "package_count": len(packages), "control_file_count": len(all_members),
        "maintainer_script_count": sum(member["kind"] == "maintainer_script"
                                       for member in all_members),
        "trigger_file_count": sum(member["kind"] == "trigger_declarations"
                                  for member in all_members),
        "package_inventory_sha256": hashlib.sha256(encoded).hexdigest(),
        "packages": packages,
        "signed_snapshot_rechecked": True, "archive_bytes_checked": True,
        "package_scripts_executed": False, "image_built": False,
        "private_mode_approved": False,
    }
