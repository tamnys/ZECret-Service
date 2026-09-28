#!/usr/bin/env python3
"""Build only the production Debian initrd subimage as an unsigned diagnostic.

The selected HEAD, signed Debian guest closure, production input lock, and
double-built x86_64 /init receipt are inputs. The build needs an independently
reviewed mkosi 25.3 builder and externally enforced isolation. This runner
observes loopback-only IP state but cannot prove outer namespace creation,
mount isolation, or the absence of UNIX-socket egress. It does not build a
disk, append kernel modules, sign a UKI, or prove a boot.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve(strict=True).parents[2]
MODULE_DIR = Path(__file__).resolve(strict=True).parent
SCRIPT = "tools/gcp-guest/package_initrd_runner.py"
SUBIMAGE = "deploy/gcp/guest/mkosi.images/initrd/mkosi.conf"
STATUS = "diagnostic-package-installed-initrd-cpio-unapproved"
PROFILE_STATUS = "diagnostic-production-initrd-subimage-profile-unbuilt"
FULL_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
PROFILE_FILES = {"mkosi.conf", "audit-initrd.py", "profile-manifest.json", "rootfs", "packages"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def source_module(revision):
    """Load the existing source-bound preflight after binding this new runner."""
    if not FULL_COMMIT.fullmatch(revision):
        raise ValueError("exact full selected source commit required")
    source = MODULE_DIR / "prepare_initrd_basetree_profile.py"
    spec = importlib.util.spec_from_file_location("initrd_source_profile", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.source_git_output(["rev-parse", "HEAD"]).decode().strip() != revision:
        raise ValueError("selected HEAD differs from requested source")
    if module.source_file(MODULE_DIR / Path(SCRIPT).name) != module.source_git_output(
        ["show", f"{revision}:{SCRIPT}"]
    ):
        raise ValueError("package initrd runner differs from selected HEAD")
    module.bind_selected_modules(revision)
    return module


def production_lock(path, source, revision):
    """Use only initrd-relevant fields; absent signing/Zebra files are allowed."""
    raw = source.rust_inputs.regular_bytes(path)
    lock = json.loads(raw, object_pairs_hook=source.guest.prepare.unique_object)
    prepare = source.guest.prepare
    if (not isinstance(lock, dict)
            or set(lock) != {"schema_version", "mkosi_source_commit", "source_date_epoch",
                                "kernel_version", "snapshot", "artifacts", "runtime"}
            or lock["schema_version"] != 6
            or lock["mkosi_source_commit"] != prepare.SOURCE_COMMIT
            or lock["kernel_version"] != prepare.KERNEL_VERSION
            or lock["snapshot"] != source.guest.SNAPSHOT
            or type(lock["source_date_epoch"]) is not int
            or lock["source_date_epoch"] <= 0):
        raise ValueError("production input lock differs from reviewed initrd policy")
    artifacts = lock["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != prepare.ROLES:
        raise ValueError("production input lock role set differs")
    early = artifacts[prepare.EARLY_INIT_ROLE]
    package = artifacts["package_manifest"]
    if (not isinstance(early, dict) or not isinstance(package, dict)
            or not HEX.fullmatch(early.get("sha256", ""))
            or package.get("sha256") != prepare.PACKAGE_CLOSURE_SHA256):
        raise ValueError("production lock initrd artifact identities differ")
    return lock, sha256(raw)


def config_bytes(source, profile, epoch, packages):
    """Materialize the production subimage and its universal parent settings."""
    prepare = source.guest.prepare
    prepare.validate_boot_profile()
    subimage_path = prepare.PROFILE / "mkosi.images/initrd/mkosi.conf"
    static = source.rust_inputs.regular_bytes(subimage_path)
    if static != source.source_git_output(["show", f"{source._BOUND_REVISION}:{SUBIMAGE}"]):
        raise ValueError("production initrd source differs from selected HEAD")
    versions = {entry["name"]: entry["version"] for entry in packages}
    if not prepare.INITRD_PACKAGES <= set(versions):
        raise ValueError("signed guest closure misses production initrd package seeds")
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


def inputs(source, metadata, archives, rust_bundle, revision, lock_path, workspace):
    workspace = Path(workspace).resolve(strict=True)
    rust_bundle = Path(rust_bundle).resolve(strict=True)
    if not rust_bundle.is_relative_to(workspace):
        raise ValueError("Rust receipt must be on the selected workspace volume")
    receipt = source.rust_inputs.inspect(rust_bundle, revision)
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
    if (audit_template != source.source_git_output(
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
    lock, lock_sha256 = production_lock(lock_path, source, revision)
    if lock["artifacts"][source.guest.prepare.EARLY_INIT_ROLE]["sha256"] != sha256(binary):
        raise ValueError("production lock /init differs from reproducible Rust receipt")
    signed = source.guest.verify_cached_archives(metadata, archives)
    if (signed["signed_snapshot_rechecked"] is not True
            or signed["archive_bytes_checked"] is not True):
        raise ValueError("signed Debian guest archive verification incomplete")
    packages = source.guest.authenticated_packages(metadata)
    return preflight, binary, audit, packages, lock, lock_sha256


def checked_profile(profile, workspace, source):
    return source.checked_profile_path(Path(profile), Path(workspace))


def manifest_for(source, preflight, packages, lock_sha256, config, static_sha256, audit):
    return {
        "schema_version": 1, "status": PROFILE_STATUS,
        "source_commit": preflight["rust_source_commit"],
        "mkosi_source_commit": preflight["mkosi_source_commit"],
        "production_lock_sha256": lock_sha256,
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


def prepare_profile(source, metadata, archives, rust_bundle, revision,
                    lock_path, profile, workspace):
    preflight, binary, audit, packages, lock, lock_sha256 = inputs(
        source, metadata, archives, rust_bundle, revision, lock_path, workspace)
    profile = checked_profile(profile, workspace, source)
    config, static_sha256 = config_bytes(source, profile, lock["source_date_epoch"], packages)
    expected = manifest_for(source, preflight, packages, lock_sha256, config, static_sha256, audit)
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


def verify_profile(source, metadata, archives, rust_bundle, revision,
                   lock_path, profile, workspace):
    preflight, binary, audit, packages, lock, lock_sha256 = inputs(
        source, metadata, archives, rust_bundle, revision, lock_path, workspace)
    profile = checked_profile(profile, workspace, source)
    config, static_sha256 = config_bytes(source, profile, lock["source_date_epoch"], packages)
    expected = manifest_for(source, preflight, packages, lock_sha256, config, static_sha256, audit)
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


def build_profile(source, metadata, archives, rust_bundle, revision,
                  lock_path, profile, workspace, parent_network_namespace,
                  parent_mount_namespace, mkosi, builder_archives):
    before = verify_profile(source, metadata, archives, rust_bundle,
                            revision, lock_path, profile, workspace)
    namespace = check_loopback_only_ip_state(parent_network_namespace,
                                              parent_mount_namespace)
    if Path(mkosi) != Path("/usr/bin/mkosi") or Path(mkosi).is_symlink():
        raise ValueError("reviewed Debian mkosi executable required")
    builder_identity = verified_mkosi(source, metadata, builder_archives)
    profile = Path(profile)
    output = profile.parent / (profile.name + "-output")
    if output.exists() or output.is_symlink():
        raise ValueError("fresh mkosi output directory required")
    fresh_sibling(profile, "-work")
    fresh_sibling(profile, "-package-cache")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
                   "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run([mkosi, f"--directory={profile}", "build"],
                            env=environment, check=False)
    if result.returncode:
        raise ValueError("pinned mkosi initrd build failed")
    after = verify_profile(source, metadata, archives, rust_bundle,
                           revision, lock_path, profile, workspace)
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
    for name in ("metadata", "archives", "rust-bundle", "input-lock",
                 "profile", "workspace"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--parent-network-namespace")
    parser.add_argument("--parent-mount-namespace")
    parser.add_argument("--mkosi", default="/usr/bin/mkosi")
    parser.add_argument("--builder-archives", type=Path)
    args = parser.parse_args(argv)
    try:
        source = source_module(args.revision)
        common = (source, args.metadata, args.archives, args.rust_bundle,
                  args.revision, args.input_lock,
                  args.profile, args.workspace)
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
