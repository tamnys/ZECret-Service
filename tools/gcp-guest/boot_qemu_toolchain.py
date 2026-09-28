#!/usr/bin/env python3
"""Fetch and stage a signed Debian QEMU/OVMF diagnostic toolchain.

This is a boot-test tool, not a guest input or a release-approval path. It
never invokes package scripts, QEMU, a cloud API, or an image signer. The
caller must run the staged executable in a separate no-route chroot and treat
the boot as synthetic evidence only.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

# The native workflow invokes this exact-commit script with Python -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import debian_snapshot
import fetch_builder_closure as fetcher
import stage_builder_toolchain as stager
import verify_builder_closure as builder
import verify_builder_packages as direct


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deploy/gcp/boot-toolchain.lock.json"
# Review this digest and size when the signed package selection changes.
LOCK_BYTES = 26983
LOCK_SHA256 = "6ef3021c4392c3bcbdf62d08e9c1121c42922befd680d761ec397ee8376e3028"
ANCHORS = ("ovmf", "qemu-system-x86")
QEMU = "usr/bin/qemu-system-x86_64"
OVMF_CODE = "usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS = "usr/share/OVMF/OVMF_VARS_4M.fd"
LOADER = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
LIBRARY = "usr/lib/x86_64-linux-gnu"
LOADER_LINE = re.compile(r"\s*(\S+) \(0x[0-9a-f]+\)\Z")
LOADER_MAP = re.compile(r"\s*\S+ => (\S+) \(0x[0-9a-f]+\)\Z")
VDSO_LINE = re.compile(r"\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)\Z")


def real_directory(path, label):
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} must be a real directory")
    return path


def reviewed_lock(lock_path=LOCK):
    data = debian_snapshot.bounded_regular_bytes(lock_path, LOCK_BYTES,
                                                  "boot toolchain lock")
    if len(data) != LOCK_BYTES or hashlib.sha256(data).hexdigest() != LOCK_SHA256:
        raise ValueError("boot toolchain lock differs from source-reviewed bytes")
    lock = json.loads(data, object_pairs_hook=direct.unique_object)
    base, base_sha256, _ = fetcher.reviewed_lock(builder.LOCK)
    if (type(lock) is not dict or set(lock) != {
            "schema_version", "status", "snapshot", "inrelease_sha256",
            "packages_index_sha256", "signed_release_date_epoch",
            "builder_closure_sha256", "anchors", "resolver", "packages"}
            or type(lock["schema_version"]) is not int or lock["schema_version"] != 1
            or lock["status"] != "apt-resolved-candidate-unbuilt-unapproved"
            or lock["builder_closure_sha256"] != base_sha256
            or any(lock[field] != base[field] for field in (
                "snapshot", "inrelease_sha256", "packages_index_sha256",
                "signed_release_date_epoch", "resolver"))
            or type(lock["anchors"]) is not list
            or [entry.get("name") for entry in lock["anchors"]] != list(ANCHORS)):
        raise ValueError("boot toolchain lock differs from reviewed snapshot and resolver")
    return lock


def authenticated_selection(metadata, lock_path=LOCK):
    real_directory(metadata, "snapshot metadata")
    lock = reviewed_lock(lock_path)
    epoch, (index_sha256, _), index = debian_snapshot.authenticated_index_bytes(
        metadata / "InRelease", metadata / "Packages.xz",
        lock["inrelease_sha256"])
    if (epoch != lock["signed_release_date_epoch"]
            or index_sha256 != lock["packages_index_sha256"]):
        raise ValueError("boot toolchain index differs from reviewed signed snapshot")
    records = debian_snapshot.package_records(io.BytesIO(index))
    entries = lock["packages"]
    if type(entries) is not list or not entries:
        raise ValueError("boot toolchain package list missing")
    names = []
    selected = {}
    for entry in entries:
        if (type(entry) is not dict or set(entry) != builder.PACKAGE_FIELDS
                or not isinstance(entry["name"], str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", entry["name"])
                or not isinstance(entry["version"], str)
                or entry["architecture"] not in {"amd64", "all"}
                or type(entry["size"]) is not int or entry["size"] <= 0
                or not isinstance(entry["sha256"], str)
                or not debian_snapshot.HEX_SHA256.fullmatch(entry["sha256"])):
            raise ValueError("invalid boot toolchain package identity")
        filename = PurePosixPath(entry["filename"])
        if (filename.is_absolute() or filename.as_posix() != entry["filename"]
                or not filename.parts or filename.parts[0] != "pool"
                or ".." in filename.parts or filename.suffix != ".deb"):
            raise ValueError("unsafe boot toolchain package filename")
        record = records.get((entry["name"], entry["version"],
                              entry["architecture"]))
        if record is None or any(str(entry[field]) != record.get(index_field)
                                 for field, index_field in (("filename", "Filename"),
                                                            ("size", "Size"),
                                                            ("sha256", "SHA256"))):
            raise ValueError("boot toolchain package differs from signed index")
        names.append(entry["name"])
        selected[entry["name"]] = (entry["version"], entry["architecture"])
    if names != sorted(set(names)):
        raise ValueError("boot toolchain package order or identity differs")
    for anchor in lock["anchors"]:
        if (type(anchor) is not dict or set(anchor) !=
                {"name", "version", "architecture"}
                or selected.get(anchor["name"]) !=
                (anchor["version"], anchor["architecture"])):
            raise ValueError("boot toolchain anchor differs from package selection")
    return lock, index, records, selected


def cached_archives(archives, entries):
    real_directory(archives, "boot archive cache")
    directory = os.open(archives, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for entry in entries:
            if not fetcher.verify_cached(directory, entry):
                raise ValueError("signed boot archive missing: " + entry["name"])
    finally:
        os.close(directory)


def fetch(metadata, archives, *, lock_path=LOCK):
    # This networked runner phase only fetches immutable reviewed bytes.
    # The runner's ambient gpgv is not the signed Debian one. The offline
    # stage below authenticates InRelease, signed package membership, and APT.
    lock = reviewed_lock(lock_path)
    real_directory(metadata, "snapshot metadata")
    metadata_fd = os.open(metadata, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for name, digest, maximum in (
                ("InRelease", lock["inrelease_sha256"],
                 debian_snapshot.MAX_INRELEASE_BYTES),
                ("Packages.xz", lock["packages_index_sha256"],
                 debian_snapshot.MAX_SIGNED_INDEX_BYTES)):
            if not fetcher.verified_metadata(metadata_fd, name, digest, maximum):
                raise ValueError("hash-pinned Debian snapshot metadata missing: " + name)
    finally:
        os.close(metadata_fd)
    real_directory(archives, "boot archive cache")
    directory = os.open(archives, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for entry in lock["packages"]:
            if not fetcher.verify_cached(directory, entry):
                fetcher.download_one(directory, entry, lock["snapshot"])
            if not fetcher.verify_cached(directory, entry):
                raise ValueError("signed boot archive missing after fetch")
    finally:
        os.close(directory)
    return {"status": "diagnostic-boot-archives-hash-matched-signature-unchecked",
            "lock_sha256": LOCK_SHA256, "package_count": len(lock["packages"]),
            "signed_snapshot_rechecked": False,
            "boot_verified": False, "private_mode_approved": False}


def apt_plan(lock, index, records, archives, scratch):
    """Recompute the reviewed selection using the sealed signed APT resolver."""
    base, _, _ = fetcher.reviewed_lock(builder.LOCK)
    provider_entries = {entry["name"]: entry for entry in base["packages"]
                        if entry["name"] in builder.APT_ELF_PACKAGES}
    if set(provider_entries) != builder.APT_ELF_PACKAGES:
        raise ValueError("base builder excludes a signed APT runtime provider")
    cached_archives(archives, provider_entries.values())
    runtime = {}
    for name, entry in provider_entries.items():
        record = records.get((name, entry["version"], entry["architecture"]))
        runtime[name] = builder.indexed_archive(
            entry, record, archives, keep_bytes=True)
    apt = builder.apt_get_from_deb(runtime["apt"])
    if (len(apt) != base["resolver"]["executable_size"]
            or hashlib.sha256(apt).hexdigest() !=
            base["resolver"]["executable_sha256"]):
        raise ValueError("signed APT executable differs from reviewed builder")
    real_directory(scratch, "APT scratch")
    with tempfile.TemporaryDirectory(prefix="zrpc-boot-apt-", dir=scratch) as temporary:
        program = Path(temporary) / "apt-get"
        program.write_bytes(apt)
        resolved, _ = builder.apt_plan(index, scratch, program,
                                       lock["resolver"], lock["anchors"],
                                       lock["snapshot"], runtime)
    return resolved


def elf_x86_64(path):
    with path.open("rb") as stream:
        head = stream.read(20)
    if (len(head) != 20 or head[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(head[18:20], "little") != 62):
        raise ValueError("boot toolchain executable or library is not x86_64 ELF")


def checked_file(output, inventory, name, package=None):
    entry = inventory.get(name)
    if (entry is None or entry.get("kind") != "file"
            or not isinstance(entry.get("packages"), list)
            or len(entry["packages"]) != 1
            or (package is not None and entry["packages"] != [package])):
        raise ValueError("boot toolchain required file lacks signed package provenance: " + name)
    path = output / name
    if path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(output):
        raise ValueError("boot toolchain required file redirected: " + name)
    with path.open("rb") as stream:
        data_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if path.stat().st_size != entry["size"] or data_hash != entry["sha256"]:
        raise ValueError("boot toolchain required file differs from signed archive: " + name)
    return path


def dynamic_closure(output, inventory):
    qemu = checked_file(output, inventory, QEMU, "qemu-system-x86")
    code = checked_file(output, inventory, OVMF_CODE, "ovmf")
    variables = checked_file(output, inventory, OVMF_VARS, "ovmf")
    loader = checked_file(output, inventory, LOADER, "libc6")
    for path in (qemu, loader):
        elf_x86_64(path)
    result = subprocess.run(
        [str(loader), "--inhibit-cache", "--library-path", str(output / LIBRARY),
         "--list", str(qemu)], capture_output=True, text=True, check=False,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if result.returncode != 0 or result.stderr.strip():
        raise ValueError("signed QEMU dynamic loader inspection failed")
    libraries = []
    for line in result.stdout.splitlines():
        if VDSO_LINE.fullmatch(line):
            continue
        match = LOADER_MAP.fullmatch(line) or LOADER_LINE.fullmatch(line)
        if match is None:
            raise ValueError("unrecognized QEMU dynamic loader dependency")
        path = Path(match.group(1))
        if not path.is_absolute() or not path.resolve(strict=True).is_relative_to(output):
            raise ValueError("QEMU dynamic dependency escaped signed toolchain")
        resolved = path.resolve(strict=True)
        checked_file(output, inventory, str(resolved.relative_to(output)))
        elf_x86_64(resolved)
        libraries.append(str(resolved))
    if not libraries:
        raise ValueError("QEMU dynamic loader reported no libraries")
    # The staged chroot and explicit -L are still necessary: --list does not
    # reveal later dlopen calls or prove which firmware/data QEMU will open.
    return {"qemu_host_path": str(qemu), "ovmf_code_host_path": str(code),
            "ovmf_vars_template_host_path": str(variables),
            "qemu_chroot_path": "/" + QEMU,
            "ovmf_code_chroot_path": "/" + OVMF_CODE,
            "ovmf_vars_template_chroot_path": "/" + OVMF_VARS,
            "dynamic_library_count": len(libraries),
            "dynamic_loader_dependencies_within_signed_stage": True,
            "post_start_plugin_loads_verified": False}


def stage(metadata, archives, output, scratch, workspace, *, lock_path=LOCK):
    lock, index, records, selected = authenticated_selection(metadata, lock_path)
    cached_archives(archives, lock["packages"])
    real_directory(workspace, "managed workspace")
    real_directory(scratch, "APT scratch")
    if not scratch.is_relative_to(workspace) or not output.is_relative_to(workspace):
        raise ValueError("boot toolchain output and scratch must stay on workspace volume")
    resolved = apt_plan(lock, index, records, archives, scratch)
    if selected != resolved:
        raise ValueError("boot toolchain differs from signed offline APT plan")
    staged = stager.stage(archives, output, workspace=workspace, lock_path=lock_path,
                          lock_size=LOCK_BYTES, lock_sha256=LOCK_SHA256)
    if staged["package_count"] != len(lock["packages"]):
        raise ValueError("boot toolchain staging package count differs")
    manifest = json.loads(debian_snapshot.bounded_regular_bytes(
        output / stager.MANIFEST, 16 * 1024 * 1024, "boot toolchain inventory"),
        object_pairs_hook=direct.unique_object)
    if (manifest.get("builder_closure_lock_sha256") != LOCK_SHA256
            or manifest.get("package_scripts_executed") is not False):
        raise ValueError("boot toolchain staged inventory differs")
    inventory = {entry["path"]: entry for entry in manifest["entries"]}
    if len(inventory) != len(manifest["entries"]):
        raise ValueError("duplicate boot toolchain staged path")
    paths = dynamic_closure(output, inventory)
    return {"status": "diagnostic-pinned-qemu-ovmf-staged-unapproved",
            "lock_sha256": LOCK_SHA256, "package_count": len(lock["packages"]),
            "stage_inventory_sha256": staged["manifest_sha256"],
            "stage_host_path": str(output), **paths,
            "package_scripts_executed": False, "boot_verified": False,
            "hardware_verified": False, "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fetching = sub.add_parser("fetch")
    fetching.add_argument("--metadata", type=Path, required=True)
    fetching.add_argument("--archives", type=Path, required=True)
    staging = sub.add_parser("stage")
    staging.add_argument("--metadata", type=Path, required=True)
    staging.add_argument("--archives", type=Path, required=True)
    staging.add_argument("--output", type=Path, required=True)
    staging.add_argument("--scratch", type=Path, required=True)
    staging.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            report = fetch(args.metadata, args.archives)
        else:
            report = stage(args.metadata, args.archives, args.output,
                           args.scratch, args.workspace)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "boot_verified": False, "private_mode_approved": False},
                         sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
