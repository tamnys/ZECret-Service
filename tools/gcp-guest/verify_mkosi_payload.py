#!/usr/bin/env python3
"""Compare the signed Debian mkosi binary payload with its signed source.

This is a source-to-package diagnostic. It does not install or run mkosi,
authenticate the complete builder runtime, build an image, or approve a guest.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import sys
import tarfile

import debian_snapshot
import verify_builder_closure as closure
import verify_builder_packages as direct
import verify_mkosi_source as source
import verify_mkosi_tree as tree


# These generated console scripts and entry-point metadata were reviewed from
# mkosi_25.3-7_all.deb in the signed 20260918 Debian snapshot. The project
# never executes the package's maintainer scripts in this diagnostic.
CONSOLE_SCRIPTS = {
    "usr/bin/mkosi": "8a671b36fef6b71ece78c54288b0d97b449b854c71b598b16340a125bf5e9a03",
    "usr/bin/mkosi-addon": "326ba6733f02dcd7442cbe3f0f4198e7b0be1a9b9f377a5576f9be4f9a7c541e",
    "usr/bin/mkosi-initrd": "7f157ef4c522308a851cbc38325f7ae1af39c29c52b71e3d0cddf0632a66ff2a",
    "usr/bin/mkosi-sandbox": "58693f43ddc0a18d386757cd2bf5882be5fe7a3c424e3cf53fe8d8cff2ff0cca",
}
KERNEL_INSTALL = {
    "usr/lib/kernel/install.d/50-mkosi.install": "kernel-install/50-mkosi.install",
    "usr/lib/kernel/install.d/51-mkosi-addon.install": "kernel-install/51-mkosi-addon.install",
}
DIST_INFO = "usr/lib/python3/dist-packages/mkosi-25.3.dist-info/"
DIST_INFO_FILES = {"INSTALLER", "METADATA", "WHEEL", "entry_points.txt", "top_level.txt"}
ENTRY_POINTS_SHA256 = "811504855dddf499c8854a5d41152401eb5ec2de5dc4dde0e004b03914d6afc5"
PACKAGE_MODULES = "usr/lib/python3/dist-packages/mkosi/"
GENERATED_MAN_PAGES = {
    "mkosi-addon.1", "mkosi-initrd.1", "mkosi-sandbox.1", "mkosi.1", "mkosi.news.7",
}
MAN_PREFIX = "mkosi/resources/man/"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compare_payload(source_entries, binary_bytes, *, console_scripts=CONSOLE_SCRIPTS,
                    entry_points_sha256=ENTRY_POINTS_SHA256):
    """Check every packaged mkosi resource and every executable payload file."""
    expected = {name: entry[2] for name, entry in source_entries.items()
                if name.startswith("mkosi/") and entry[0] == "file"}
    if not expected or not any(name.endswith(".py") for name in expected):
        raise ValueError("mkosi source package has no Python implementation")
    kernel_expected = {package_path: source_entries[source_path][2]
                       for package_path, source_path in KERNEL_INSTALL.items()
                       if source_path in source_entries and source_entries[source_path][0] == "file"}
    if set(kernel_expected) != set(KERNEL_INSTALL):
        raise ValueError("mkosi source lacks reviewed kernel-install scripts")
    matched = set()
    executable = set()
    generated_man = set()
    seen = set()
    entry_points = False
    try:
        with tarfile.open(fileobj=io.BytesIO(closure.deb_data_tar(binary_bytes)), mode="r:xz") as archive:
            for member in archive:
                if member.name in {".", "./"} and member.isdir():
                    continue
                if not member.name.startswith("./"):
                    raise ValueError("non-canonical mkosi package path")
                name = member.name[2:].rstrip("/")
                if (not name or any(part in {"", ".", ".."} for part in name.split("/"))
                        or name in seen):
                    raise ValueError("duplicate or traversing mkosi package path")
                seen.add(name)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError("unexpected mkosi package link or special file")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("unreadable mkosi package file")
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if member.mode & 0o111:
                    executable.add(name)
                if name.startswith(PACKAGE_MODULES):
                    relative = "mkosi/" + name[len(PACKAGE_MODULES):]
                    if relative in expected:
                        if digest != expected[relative]:
                            raise ValueError("packaged mkosi implementation differs from signed source: " + relative)
                        matched.add(relative)
                    elif relative.startswith(MAN_PREFIX) and relative[len(MAN_PREFIX):] in GENERATED_MAN_PAGES:
                        if member.mode & 0o111:
                            raise ValueError("generated mkosi man page is executable")
                        generated_man.add(relative[len(MAN_PREFIX):])
                    else:
                        raise ValueError("unexpected packaged mkosi implementation: " + relative)
                elif name in kernel_expected:
                    if digest != kernel_expected[name]:
                        raise ValueError("packaged mkosi kernel-install script differs from signed source")
                elif name in console_scripts:
                    if digest != console_scripts[name] or not member.mode & 0o111:
                        raise ValueError("mkosi console script differs from reviewed Debian package")
                elif name.startswith(DIST_INFO):
                    suffix = name[len(DIST_INFO):]
                    if suffix not in DIST_INFO_FILES or member.mode & 0o111:
                        raise ValueError("unexpected executable or metadata in mkosi dist-info")
                    if suffix == "entry_points.txt":
                        if digest != entry_points_sha256:
                            raise ValueError("mkosi entry points differ from reviewed Debian package")
                        entry_points = True
                elif name.startswith("usr/lib/python3/dist-packages/"):
                    raise ValueError("unexpected Python path in mkosi package")
    except (tarfile.TarError, lzma.LZMAError, EOFError) as error:
        raise ValueError("invalid mkosi package data archive") from error
    if matched != set(expected) or generated_man != GENERATED_MAN_PAGES:
        raise ValueError("packaged mkosi source or generated man pages missing")
    if not set(KERNEL_INSTALL) <= seen or executable != set(console_scripts) | set(KERNEL_INSTALL):
        raise ValueError("mkosi package executable set differs from review")
    if not entry_points or not set(console_scripts) <= seen:
        raise ValueError("mkosi console entry points missing")
    return {"source_files_matched": len(matched),
            "python_modules_matched": sum(name.endswith(".py") for name in matched),
            "generated_man_pages": sorted(generated_man),
            "reviewed_console_scripts": sorted(console_scripts)}


def verify(inrelease, sources_index, packages_index, source_dir, binary_package,
           *, lock_path=closure.LOCK, identities_path=source.IDENTITIES):
    source_files = {name: source_dir / name for name in source.SOURCE_FILES}
    membership = source.verify(inrelease, sources_index, source_files, identities_path)
    if (membership["status"] != "source-membership-verified-toolchain-unreviewed"
            or membership["image_built"] is not False
            or membership["private_mode_approved"] is not False):
        raise ValueError("signed mkosi source membership was not established")
    identities = direct.read_json(identities_path)
    snapshot = identities["downloaded_metadata"]["trixie_snapshot_candidate"]
    epoch, (index_hash, index_size), index_bytes = debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, snapshot["inrelease_sha256"])
    if (epoch != snapshot["signed_release_date_epoch"]
            or index_hash != snapshot["main_binary_amd64_packages_xz_sha256"]
            or index_size != snapshot["main_binary_amd64_packages_xz_size"]):
        raise ValueError("mkosi binary index differs from reviewed signed snapshot")
    snapshot_time = datetime.strptime(snapshot["url"].rstrip("/").rsplit("/", 1)[-1],
                                      "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    debian_snapshot.require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    lock_bytes = debian_snapshot.bounded_regular_bytes(lock_path, closure.LOCK_BYTES,
                                                       "builder closure lock")
    if len(lock_bytes) != closure.LOCK_BYTES or sha256(lock_bytes) != closure.LOCK_SHA256:
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=direct.unique_object)
    entries = [entry for entry in lock["packages"] if entry["name"] == "mkosi"]
    if len(entries) != 1:
        raise ValueError("builder closure lacks unique mkosi package")
    entry = entries[0]
    if entry["version"] != source.SOURCE_VERSION or entry["architecture"] != "all":
        raise ValueError("mkosi binary and source versions differ")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    record = records.get((entry["name"], entry["version"], entry["architecture"]))
    if record is None or any(str(entry[field]) != record.get(index_field) for field, index_field in (
            ("filename", "Filename"), ("size", "Size"), ("sha256", "SHA256"))):
        raise ValueError("mkosi binary package differs from signed index")
    if (not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or type(entry["size"]) is not int or entry["size"] <= 0):
        raise ValueError("invalid mkosi binary package identity")
    binary_bytes = debian_snapshot.bounded_regular_bytes(binary_package, entry["size"],
                                                        "mkosi binary package")
    if len(binary_bytes) != entry["size"] or sha256(binary_bytes) != entry["sha256"]:
        raise ValueError("mkosi binary package differs from signed index")
    source_archive = source_files["mkosi_25.3.orig.tar.gz"]
    source_entries = tree.archive_entries(source_archive, root=tree.DEBIAN_ROOT)
    if source.digest(source_archive) != membership["source_file_sha256"][source_archive.name]:
        raise ValueError("mkosi source changed during package comparison")
    payload = compare_payload(source_entries, binary_bytes)
    return {"status": "diagnostic-signed-mkosi-binary-matches-debian-source-unbuilt",
            "mkosi_package_sha256": entry["sha256"],
            "debian_source_sha256": membership["source_file_sha256"][source_archive.name],
            **payload, "installer_hooks_executed": False,
            "complete_builder_toolchain": False, "image_built": False,
            "private_mode_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--sources-index", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--binary-package", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.inrelease, args.sources_index, args.packages_index,
                                args.source_dir, args.binary_package), indent=2))
        return 0
    except (OSError, ValueError, KeyError, IndexError, TypeError, UnicodeError,
            tarfile.TarError, lzma.LZMAError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False, "image_built": False,
                          "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
