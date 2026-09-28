#!/usr/bin/env python3
"""Build only the production Debian initrd subimage as an unsigned diagnostic.

The selected HEAD, signed Debian guest closure, and double-built x86_64 /init
receipt are inputs. The build needs an independently
reviewed mkosi 25.3 builder and externally enforced isolation. This runner
observes loopback-only IP state but cannot prove outer namespace creation,
mount isolation, or the absence of UNIX-socket egress. It does not build a
disk, append kernel modules, sign a UKI, or prove a boot.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tarfile
import types


ROOT = Path(__file__).resolve(strict=True).parents[2]
MODULE_DIR = Path(__file__).resolve(strict=True).parent
SCRIPT = "tools/gcp-guest/package_initrd_runner.py"
SUBIMAGE = "deploy/gcp/guest/mkosi.images/initrd/mkosi.conf"
STATUS = "diagnostic-package-installed-initrd-cpio-unapproved"
PROFILE_STATUS = "diagnostic-production-initrd-subimage-profile-unbuilt"
FULL_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
PROFILE_FILES = {"mkosi.conf", "audit-initrd.py", "profile-manifest.json", "rootfs", "packages"}
ARCHIVE_PATH = re.compile(r"[A-Za-z0-9_./-]+\Z")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Rust receipt field")
        result[key] = value
    return result


class ReceiptSourceArchive:
    """Read selected Git bytes from the exact-HEAD Rust receipt, without Git.

    The outer workflow checks the selected Git commit and verifies this receipt
    before mounting it read-only in the no-route builder. This inner check
    retains the archive and receipt digests and permits only source reads used
    by the existing verifier. Neither receipt nor archive approves private mode.
    """

    def __init__(self, rust_bundle, revision):
        if not FULL_COMMIT.fullmatch(revision):
            raise ValueError("exact full selected source commit required")
        bundle = Path(rust_bundle)
        report = json.loads(regular(bundle / "guest-inputs/diagnostic-rust-inputs.json"),
                            object_pairs_hook=unique_object)
        manifest_bytes = regular(bundle / "manifest.json")
        manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
        if (not isinstance(report, dict) or not isinstance(manifest, dict)
                or report.get("status") != "diagnostic-unsigned-x86_64-rust-inputs-unapproved"
                or report.get("source_commit") != revision
                or report.get("image_built") is not False
                or report.get("private_mode_approved") is not False
                or manifest.get("source_commit") != revision
                or report.get("source_tree") != manifest.get("source_tree")
                or not isinstance(report.get("source_tree"), str)
                or not FULL_COMMIT.fullmatch(report["source_tree"])
                or report.get("reproduction_manifest_sha256") != sha256(manifest_bytes)
                or not isinstance(manifest.get("source_archive_sha256"), str)
                or not HEX.fullmatch(manifest["source_archive_sha256"])):
            raise ValueError("selected source archive lacks the matching Rust receipt")
        raw = regular(bundle / "source.tar")
        if sha256(raw) != manifest["source_archive_sha256"]:
            raise ValueError("selected Git archive differs from Rust receipt")
        self.revision = revision
        self.tree = report["source_tree"]
        self.archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        self.members = {}
        for member in self.archive:
            path = member.name.rstrip("/") if member.isdir() else member.name
            if (not ARCHIVE_PATH.fullmatch(path)
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                    or (member.name != path and not member.isdir())):
                raise ValueError("selected Git archive has an unsafe member")
            if path in self.members:
                raise ValueError("selected Git archive has a duplicate member")
            self.members[path] = member
        self.report = report

    def output(self, arguments):
        if arguments == ["rev-parse", "HEAD"]:
            return (self.revision + "\n").encode()
        if arguments == ["show", "-s", "--format=%T", self.revision]:
            return (self.tree + "\n").encode()
        if (len(arguments) != 2 or arguments[0] != "show"
                or not arguments[1].startswith(self.revision + ":")):
            raise ValueError("unsupported selected source archive read")
        path = arguments[1][len(self.revision) + 1:]
        if (not ARCHIVE_PATH.fullmatch(path)
                or any(part in {"", ".", ".."} for part in path.split("/"))):
            raise ValueError("selected source archive path is unsafe")
        member = self.members.get(path)
        if member is None or not member.isfile():
            raise ValueError("selected Git archive lacks a regular verifier input")
        return self.archive.extractfile(member).read()


def source_module(revision, selected):
    """Load the existing source-bound preflight from checked archive bytes."""
    if not FULL_COMMIT.fullmatch(revision):
        raise ValueError("exact full selected source commit required")
    source = MODULE_DIR / "prepare_initrd_basetree_profile.py"
    selected_bytes = selected.output(
        ["show", f"{revision}:tools/gcp-guest/prepare_initrd_basetree_profile.py"])
    if regular(source) != selected_bytes:
        raise ValueError("initrd source binder differs from selected HEAD")
    module = types.ModuleType("initrd_source_profile")
    module.__file__ = str(source)
    exec(compile(selected_bytes, str(source), "exec"), module.__dict__)
    if selected.output(["rev-parse", "HEAD"]).decode().strip() != revision:
        raise ValueError("selected HEAD differs from requested source")
    if module.source_file(MODULE_DIR / Path(SCRIPT).name) != selected.output(
        ["show", f"{revision}:{SCRIPT}"]
    ):
        raise ValueError("package initrd runner differs from selected HEAD")
    module.bind_selected_modules(revision, selected_output=selected.output)
    return module


def preflight_rust_receipt(revision, selected, rust_bundle):
    """Check the complete receipt before importing the remaining verifier."""
    source = MODULE_DIR / "export_rust_inputs.py"
    selected_bytes = selected.output(
        ["show", f"{revision}:tools/gcp-guest/export_rust_inputs.py"])
    if regular(source) != selected_bytes:
        raise ValueError("Rust receipt verifier differs from selected HEAD")
    module = types.ModuleType("initrd_rust_receipt")
    module.__file__ = str(source)
    exec(compile(selected_bytes, str(source), "exec"), module.__dict__)
    report = module.inspect(Path(rust_bundle), revision,
                            selected_output=selected.output)
    if report != selected.report:
        raise ValueError("Rust receipt differs from selected source archive")
    return report


def config_bytes(source, selected, profile, packages):
    """Materialize the production subimage and its universal parent settings."""
    prepare = source.guest.prepare
    prepare.validate_boot_profile()
    subimage_path = prepare.PROFILE / "mkosi.images/initrd/mkosi.conf"
    static = source.rust_inputs.regular_bytes(subimage_path)
    if static != selected.output(["show", f"{source._BOUND_REVISION}:{SUBIMAGE}"]):
        raise ValueError("production initrd source differs from selected HEAD")
    versions = {entry["name"]: entry["version"] for entry in packages}
    if not prepare.INITRD_PACKAGES <= set(versions):
        raise ValueError("signed guest closure misses production initrd package seeds")
    epoch = source.guest.SIGNED_RELEASE_EPOCH
    if type(epoch) is not int or epoch <= 0:
        raise ValueError("signed Debian release epoch differs")
    selected = ",".join(f"{name}={versions[name]}" for name in sorted(prepare.INITRD_PACKAGES))
    # Pinned mkosi 25.3 marks these parent settings universal for subimages.
    # Local paths are absolute so direct --directory=profile has the same inputs.
    extension = (
        f"\n[Distribution]\nDistribution=debian\nRelease=trixie\n"
        f"Architecture=x86-64\nMirror={source.guest.SNAPSHOT}\n"
        f"RepositoryKeyCheck=yes\nRepositoryKeyFetch=no\n"
        f"\n[Output]\nOutputDirectory={profile.parent / (profile.name + '-output')}\n"
        f"\n[Content]\nPackages={selected}\nPackageDirectories={profile / 'packages'}\n"
        f"ExtraTrees={profile / 'rootfs'}\nFinalizeScripts={profile / 'audit-initrd.py'}\n"
        f"SourceDateEpoch={epoch}\n"
        f"\n[Build]\nWithNetwork=no\nCacheOnly=always\nIncremental=no\n"
        f"WorkspaceDirectory={profile.parent / (profile.name + '-work')}\n"
        f"PackageCacheDirectory={profile.parent / (profile.name + '-package-cache')}\n"
    ).encode()
    return static + extension, sha256(static)


def inputs(source, selected, metadata, archives, rust_bundle, revision, workspace):
    workspace = Path(workspace).resolve(strict=True)
    rust_bundle = Path(rust_bundle).resolve(strict=True)
    if not rust_bundle.is_relative_to(workspace):
        raise ValueError("Rust receipt must be on the selected workspace volume")
    receipt = source.rust_inputs.inspect(
        rust_bundle, revision, selected_output=selected.output)
    if receipt != selected.report:
        raise ValueError("Rust receipt differs after no-route verification")
    if (receipt.get("status") != "diagnostic-unsigned-x86_64-rust-inputs-unapproved"
            or receipt.get("image_built") is not False
            or receipt.get("private_mode_approved") is not False):
        raise ValueError("Rust receipt changed diagnostic state")
    early = receipt["artifacts"]["early_init"]
    if early["path"] != "early_init" or not HEX.fullmatch(early["sha256"]):
        raise ValueError("Rust receipt early-init role differs")
    binary = source.rust_inputs.regular_bytes(rust_bundle / "artifacts/zrpc-gcp-early-init")
    if sha256(binary) != early["sha256"] or not source.rust_inputs.x86_64_elf(binary):
        raise ValueError("/init differs from double-built x86_64 Rust receipt")
    audit_template = source.rust_inputs.regular_bytes(MODULE_DIR / "audit-initrd.py")
    if (audit_template != selected.output(
            ["show", f"{revision}:tools/gcp-guest/audit-initrd.py"])
            or audit_template.count(b"__STAGED_INIT_SHA256__") != 1
            or not audit_template.startswith(b"#!/usr/bin/env python3\n")):
        raise ValueError("initrd audit differs from selected HEAD")
    audit = audit_template.replace(b"#!/usr/bin/env python3\n", b"#!/usr/bin/python3 -I\n", 1)
    audit = audit.replace(b"__STAGED_INIT_SHA256__", early["sha256"].encode())
    preflight = {"rust_source_commit": revision,
                 "mkosi_source_commit": source.guest.prepare.SOURCE_COMMIT,
                 "rust_receipt_sha256": receipt["reproduction_manifest_sha256"],
                 "early_init_sha256": early["sha256"]}
    signed = source.guest.verify_cached_archives(metadata, archives)
    if (signed["signed_snapshot_rechecked"] is not True
            or signed["archive_bytes_checked"] is not True):
        raise ValueError("signed Debian guest archive verification incomplete")
    packages = source.guest.authenticated_packages(metadata)
    return preflight, binary, audit, packages


def checked_profile(profile, workspace, source):
    return source.checked_profile_path(Path(profile), Path(workspace))


def manifest_for(source, preflight, packages, config, static_sha256, audit):
    return {
        "schema_version": 1, "status": PROFILE_STATUS,
        "source_commit": preflight["rust_source_commit"],
        "mkosi_source_commit": preflight["mkosi_source_commit"],
        "signed_release_epoch": source.guest.SIGNED_RELEASE_EPOCH,
        "signed_guest_closure_sha256": source.guest.prepare.PACKAGE_CLOSURE_SHA256,
        "signed_inrelease_sha256": source.guest.INRELEASE_SHA256,
        "signed_packages_index_sha256": source.guest.PACKAGES_SHA256,
        "rust_receipt_sha256": preflight["rust_receipt_sha256"],
        "early_init_sha256": preflight["early_init_sha256"],
        "production_subimage_source_sha256": static_sha256,
        "effective_config_sha256": sha256(config),
        "initrd_audit_sha256": sha256(audit),
        "packages": [{key: row[key] for key in ("name", "version", "architecture", "size", "sha256")}
                     for row in packages],
        "signed_snapshot_rechecked": True,
        "package_install_configured": True,
        "mkosi_executed": False,
        "initrd_built": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }


def regular(path, *, mode=None):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required regular file missing or redirected: {path.name}")
    info = path.stat()
    if info.st_nlink != 1 or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise ValueError(f"required file metadata differs: {path.name}")
    return path.read_bytes()


def prepare_profile(source, selected, metadata, archives, rust_bundle, revision,
                    profile, workspace):
    preflight, binary, audit, packages = inputs(
        source, selected, metadata, archives, rust_bundle, revision, workspace)
    profile = checked_profile(profile, workspace, source)
    config, static_sha256 = config_bytes(source, selected, profile, packages)
    expected = manifest_for(source, preflight, packages, config, static_sha256, audit)
    parent_fd = source.builder.output_parent(Path(workspace), profile)
    try:
        os.mkdir(profile.name, mode=0o700, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    (profile / "rootfs").mkdir(mode=0o700)
    (profile / "packages").mkdir(mode=0o700)
    root = source.guest.open_directory(profile, "package initrd profile")
    try:
        source.write_file(root, "mkosi.conf", config)
        source.write_file(root, "audit-initrd.py", audit, mode=0o500)
        source.write_file(root, "profile-manifest.json", canonical(expected))
    finally:
        os.close(root)
    rootfs = source.guest.open_directory(profile / "rootfs", "initrd extra tree")
    try:
        source.write_file(rootfs, "init", binary, mode=0o500)
    finally:
        os.close(rootfs)
    for entry in packages:
        name = entry["sha256"] + ".deb"
        original = Path(archives) / name
        raw = regular(original)
        if len(raw) != entry["size"] or sha256(raw) != entry["sha256"]:
            raise ValueError("signed Debian archive changed while staging")
        target = profile / "packages" / name
        target.write_bytes(raw)
        target.chmod(0o400)
    return {"status": PROFILE_STATUS, "profile_manifest_sha256": sha256(canonical(expected)),
            "package_count": len(packages), "initrd_built": False,
            "boot_verified": False, "private_mode_approved": False}


def verify_profile(source, selected, metadata, archives, rust_bundle, revision,
                   profile, workspace):
    preflight, binary, audit, packages = inputs(
        source, selected, metadata, archives, rust_bundle, revision, workspace)
    profile = checked_profile(profile, workspace, source)
    config, static_sha256 = config_bytes(source, selected, profile, packages)
    expected = manifest_for(source, preflight, packages, config, static_sha256, audit)
    if profile.is_symlink() or stat.S_IMODE(profile.stat().st_mode) != 0o700 or set(os.listdir(profile)) != PROFILE_FILES:
        raise ValueError("package initrd profile contains unreviewed inputs")
    if regular(profile / "mkosi.conf", mode=0o400) != config:
        raise ValueError("package initrd config differs from selected source")
    if regular(profile / "audit-initrd.py", mode=0o500) != audit:
        raise ValueError("package initrd audit differs from selected source")
    if regular(profile / "profile-manifest.json", mode=0o400) != canonical(expected):
        raise ValueError("package initrd profile receipt differs")
    if (profile.joinpath("rootfs").is_symlink()
            or stat.S_IMODE((profile / "rootfs").stat().st_mode) != 0o700
            or set(os.listdir(profile / "rootfs")) != {"init"}):
        raise ValueError("package initrd extra tree differs")
    if regular(profile / "rootfs/init", mode=0o500) != binary:
        raise ValueError("package initrd /init differs from Rust receipt")
    if (profile.joinpath("packages").is_symlink()
            or stat.S_IMODE((profile / "packages").stat().st_mode) != 0o700
            or set(os.listdir(profile / "packages")) != {
        entry["sha256"] + ".deb" for entry in packages
    }):
        raise ValueError("package initrd archive set differs from signed closure")
    for entry in packages:
        raw = regular(profile / "packages" / (entry["sha256"] + ".deb"), mode=0o400)
        if len(raw) != entry["size"] or sha256(raw) != entry["sha256"]:
            raise ValueError("package initrd archive differs from signed closure")
    return {"status": PROFILE_STATUS, "profile_manifest_sha256": sha256(canonical(expected)),
            "package_count": len(packages), "initrd_built": False,
            "boot_verified": False, "private_mode_approved": False}


def check_loopback_only_ip_state(parent_network_namespace, parent_mount_namespace):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("native x86_64 Linux builder required")
    current_net = os.readlink("/proc/self/ns/net")
    current_mount = os.readlink("/proc/self/ns/mnt")
    if (not re.fullmatch(r"net:\[[0-9]+\]", parent_network_namespace)
            or current_net == parent_network_namespace
            or not re.fullmatch(r"mnt:\[[0-9]+\]", parent_mount_namespace)
            or current_mount == parent_mount_namespace):
        raise ValueError("caller-reported parent namespace IDs do not differ")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("outer network namespace has a non-loopback interface")
    for path, fields in (("/proc/net/route", 11), ("/proc/net/ipv6_route", 10)):
        lines = Path(path).read_text().splitlines()
        if path.endswith("/route"):
            if not lines or not lines[0].startswith("Iface"):
                raise ValueError("IPv4 route table malformed")
            lines = lines[1:]
        for line in lines:
            parts = line.split()
            if len(parts) != fields or (parts[0] if fields == 11 else parts[-1]) != "lo":
                raise ValueError("outer network namespace has a non-loopback route")
    # These parent IDs are supplied by the caller, not independently
    # authenticated evidence of namespace creation. Loopback-only IP state
    # cannot exclude inherited UNIX sockets or other mounted network access.
    return {"network_namespace": current_net, "mount_namespace": current_mount,
            "caller_reported_parent_namespace_differs": True,
            "loopback_only_ip_state_observed": True,
            "outer_namespace_separation_verified": False,
            "builder_mounts_verified": False,
            "network_egress_excluded": False}


def fresh_sibling(profile, suffix):
    """Create a new empty mkosi work/cache directory; reject reused state."""
    parent = profile.parent
    name = profile.name + suffix
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.mkdir(name, mode=0o700, dir_fd=directory)
        created = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            if stat.S_IMODE(os.fstat(created).st_mode) != 0o700 or os.listdir(created):
                raise ValueError("fresh mkosi state directory differs")
        finally:
            os.close(created)
    finally:
        os.close(directory)


def installed_manifest(path, packages, source):
    raw = regular(path)
    data = json.loads(raw, object_pairs_hook=source.guest.prepare.unique_object)
    if (not isinstance(data, dict) or set(data) != {"manifest_version", "config", "packages"}
            or data["manifest_version"] != 1
            or not isinstance(data["config"], dict)
            or set(data["config"]) - {"name", "distribution", "release", "architecture", "version"}
            # Pinned mkosi 25.3 uses ImageId or "image" here. The production
            # subimage has no ImageId; adding one would also alter os-release.
            or data["config"].get("name") != "image"
            or data["config"].get("distribution") != "debian"
            or data["config"].get("release") != "trixie"
            or data["config"].get("architecture") != "x86-64"
            or not isinstance(data["packages"], list)
            or not data["packages"]):
        raise ValueError("mkosi initrd package manifest is unsupported")
    expected = {row["name"]: (row["version"], row["architecture"]) for row in packages}
    observed = {}
    for row in data["packages"]:
        if (not isinstance(row, dict)
                or set(row) != {"type", "name", "version", "architecture"}
                or row["type"] != "deb" or row["name"] in observed
                or expected.get(row["name"]) != (row["version"], row["architecture"])):
            raise ValueError("mkosi initrd installed an unlocked package")
        observed[row["name"]] = (row["version"], row["architecture"])
    if not source.guest.prepare.INITRD_PACKAGES <= set(observed):
        raise ValueError("mkosi initrd omitted a required package seed")
    return sha256(raw), len(observed)


def verified_mkosi(source, metadata, builder_archives):
    """Match installed mkosi code to a package in the signed Debian snapshot."""
    direct = source.builder.closure.direct
    report = direct.verify(Path(metadata) / "InRelease",
                           Path(metadata) / "Packages.xz", builder_archives)
    if report["status"] != "direct-builder-archives-matched-signed-snapshot":
        raise ValueError("mkosi builder package authentication incomplete")
    lock = direct.read_json(direct.LOCK)
    selected = [row for row in lock["packages"] if row["name"] == "mkosi"]
    if len(selected) != 1 or selected[0]["version"] != "25.3-7":
        raise ValueError("signed mkosi package version differs")
    entry = selected[0]
    raw = regular(Path(builder_archives) / (entry["sha256"] + ".deb"))
    if len(raw) != entry["size"] or sha256(raw) != entry["sha256"]:
        raise ValueError("signed mkosi archive changed before execution")
    seen = set()
    module_files = 0
    with tarfile.open(fileobj=io.BytesIO(source.builder.closure.deb_data_tar(raw)),
                      mode="r:xz") as contents:
        for member in contents:
            if not member.isfile() or not member.name.startswith("./"):
                continue
            name = member.name[2:]
            if name not in {"usr/bin/mkosi", "usr/bin/mkosi-sandbox",
                            "usr/lib/python3/dist-packages/mkosi-25.3.dist-info/entry_points.txt"} and not name.startswith(
                                "usr/lib/python3/dist-packages/mkosi/"):
                continue
            if name in seen or any(part in {"", ".", ".."} for part in name.split("/")):
                raise ValueError("signed mkosi payload has an unsafe code path")
            seen.add(name)
            payload = contents.extractfile(member).read()
            installed = regular(Path("/") / name)
            if installed != payload:
                raise ValueError("installed mkosi code differs from signed Debian package")
            if name.startswith("usr/lib/python3/dist-packages/mkosi/"):
                module_files += 1
    if not {"usr/bin/mkosi", "usr/bin/mkosi-sandbox",
            "usr/lib/python3/dist-packages/mkosi-25.3.dist-info/entry_points.txt"} <= seen or not module_files:
        raise ValueError("signed mkosi package code is incomplete")
    module_root = Path("/usr/lib/python3/dist-packages/mkosi")
    installed_paths = set()
    for directory, children, files in os.walk(module_root, followlinks=False):
        for name in children:
            child = Path(directory) / name
            if child.is_symlink():
                raise ValueError("installed mkosi module redirects")
        for name in files:
            installed_paths.add((Path(directory) / name).relative_to("/").as_posix())
    if installed_paths != {name for name in seen if name.startswith(
            "usr/lib/python3/dist-packages/mkosi/")}:
        raise ValueError("installed mkosi module has unreviewed files")
    return {"mkosi_package_sha256": entry["sha256"],
            "mkosi_code_files_checked": len(seen)}


def checked_mkosi_tmpdir(path=Path("/zrpc-apt-scratch/tmp"), *, expected_uid=0):
    """Use only the outer builder's verified, writable scratch directory."""
    if not path.is_absolute() or path.name != "tmp":
        raise ValueError("mkosi scratch path differs from prepared layout")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.fstatvfs(descriptor).f_flag & os.ST_RDONLY):
            raise ValueError("mkosi scratch is not root-owned writable private storage")
        marker = ".zrpc-mkosi-write-probe-" + secrets.token_hex(16)
        file_descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT |
                                  os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=descriptor)
        try:
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
            os.unlink(marker, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    return str(path)


def build_profile(source, selected, metadata, archives, rust_bundle, revision,
                  profile, workspace, parent_network_namespace,
                  parent_mount_namespace, mkosi, builder_archives):
    before = verify_profile(source, selected, metadata, archives, rust_bundle,
                            revision, profile, workspace)
    namespace = check_loopback_only_ip_state(parent_network_namespace,
                                              parent_mount_namespace)
    if Path(mkosi) != Path("/usr/bin/mkosi") or Path(mkosi).is_symlink():
        raise ValueError("reviewed Debian mkosi executable required")
    builder_identity = verified_mkosi(source, metadata, builder_archives)
    temporary_directory = checked_mkosi_tmpdir()
    profile = Path(profile)
    output = profile.parent / (profile.name + "-output")
    if output.exists() or output.is_symlink():
        raise ValueError("fresh mkosi output directory required")
    fresh_sibling(profile, "-work")
    fresh_sibling(profile, "-package-cache")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
                   "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "TMPDIR": temporary_directory}
    result = subprocess.run([mkosi, f"--directory={profile}", "build"],
                            env=environment, check=False)
    if result.returncode:
        raise ValueError("pinned mkosi initrd build failed")
    after = verify_profile(source, selected, metadata, archives, rust_bundle,
                           revision, profile, workspace)
    if after != before:
        raise ValueError("source-bound initrd inputs changed during mkosi build")
    if output.is_symlink() or set(os.listdir(output)) != {"initrd.cpio.zst", "initrd.manifest"}:
        raise ValueError("mkosi initrd output set differs")
    packages = source.guest.authenticated_packages(metadata)
    manifest_hash, package_count = installed_manifest(output / "initrd.manifest", packages, source)
    audit_hash = json.loads((profile / "profile-manifest.json").read_bytes())["initrd_audit_sha256"]
    cpio = source.audit_cpio(output / "initrd.cpio.zst", profile / "audit-initrd.py",
                             workspace, audit_hash)
    if check_loopback_only_ip_state(parent_network_namespace,
                                    parent_mount_namespace) != namespace:
        raise ValueError("outer build namespace changed during mkosi execution")
    return {"status": STATUS, "source_commit": revision,
            "profile_manifest_sha256": before["profile_manifest_sha256"],
            **builder_identity,
            "mkosi_manifest_sha256": manifest_hash,
            "installed_package_count": package_count,
            **cpio, **namespace,
            "source_commit_tree_proof": "outer-exact-head-git-and-verified-rust-receipt",
            "source_commit_tree_independently_rechecked_in_no_route_builder": False,
            "loopback_only_ip_state_observed_before_mkosi": True,
            "mkosi_executed": True, "initrd_built": True,
            "post_build_cpio_audited": True,
            "complete_package_script_trigger_helper_closure_verified": False,
            "generated_effects_fully_audited": False,
            "runtime_closure_verified": False,
            "disk_image_built": False,
            "boot_verified": False, "private_mode_approved": False}


def main(argv=None):
    if not sys.flags.isolated:
        print(json.dumps({"status": "blocked", "reason": "run with Python -I",
                          "initrd_built": False, "private_mode_approved": False}))
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "build"))
    for name in ("metadata", "archives", "rust-bundle",
                 "profile", "workspace"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--parent-network-namespace")
    parser.add_argument("--parent-mount-namespace")
    parser.add_argument("--mkosi", default="/usr/bin/mkosi")
    parser.add_argument("--builder-archives", type=Path)
    args = parser.parse_args(argv)
    try:
        selected = ReceiptSourceArchive(args.rust_bundle, args.revision)
        preflight_rust_receipt(args.revision, selected, args.rust_bundle)
        source = source_module(args.revision, selected)
        common = (source, selected, args.metadata, args.archives, args.rust_bundle,
                  args.revision, args.profile, args.workspace)
        if args.command == "prepare":
            report = prepare_profile(*common)
        elif args.command == "verify":
            report = verify_profile(*common)
        else:
            if (not args.parent_network_namespace or not args.parent_mount_namespace
                    or args.builder_archives is None):
                raise ValueError("outer namespace identities and signed builder archives required")
            report = build_profile(*common, args.parent_network_namespace,
                                   args.parent_mount_namespace, args.mkosi,
                                   args.builder_archives)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError,
            tarfile.TarError) as error:
        report = {"status": "blocked", "reason": str(error),
                  "initrd_built": False, "boot_verified": False,
                  "private_mode_approved": False}
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
