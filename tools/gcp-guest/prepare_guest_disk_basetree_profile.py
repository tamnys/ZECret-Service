#!/usr/bin/env python3
"""Build a non-bootable root/verity disk from the authenticated BaseTrees.

This profile exercises pinned mkosi 25.3 and the production root/verity
partition definitions without package installation or release approval. Its
root input still lacks the reviewed runtime binaries and its output has no
ESP, initrd, UKI, or Secure Boot signature.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import uuid

import assemble_guest_base_tree as base_tree
import fetch_guest_closure as guest
import fetch_builder_closure as builder_fetch
import prepare
import prepare_guest_basetree_profile as root_profile
import stage_builder_toolchain as builder
import verify_builder_closure as builder_closure


STATUS = "diagnostic-no-package-root-verity-disk-profile-unbuilt"
BUILT_STATUS = "diagnostic-no-boot-root-verity-disk-built-unapproved"
MANIFEST = "profile-manifest.json"
CONFIG = "mkosi.conf"
INPUT = "input"
REPART = "repart"
OUTPUT = "zrpc-root-verity.raw"
REPART_NAMES = ("10-root.conf", "20-root-verity.conf")
INPUT_NAMES = (base_tree.ARCHIVE, root_profile.ACCOUNT_TREE,
               root_profile.SOURCE_OVERLAY)
SEED_PREFIX = "https://github.com/tamnys/ZECret-Service/gcp-basetree-disk-diagnostic/v1/"
# The runner mounts these after staging. None is an executable search path.
MOUNTED_SCRATCH = frozenset({"proc", "dev", "zrpc-source", "zrpc-archives",
                             "zrpc-metadata", "zrpc-guest-archives",
                             "zrpc-apt-scratch", "zrpc-guest-payload-parent"})


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def seed_for(source_manifest_sha256):
    return uuid.uuid5(uuid.NAMESPACE_URL, SEED_PREFIX + source_manifest_sha256)


def config_bytes(profile, source_manifest_sha256):
    """Pinned mkosi 25.3 syntax: custom, no packages, offline repart."""
    extra = ",".join(str(profile / INPUT / name) for name in INPUT_NAMES[1:])
    return (f"[Distribution]\nDistribution=custom\nArchitecture=x86-64\n"
            f"\n[Output]\nFormat=disk\nOutput=zrpc-root-verity\n"
            f"OutputDirectory={profile.parent / (profile.name + '-output')}\n"
            f"RepartDirectories={profile / REPART}\nSectorSize=512\n"
            f"Seed={seed_for(source_manifest_sha256)}\n"
            f"\n[Content]\nBootable=no\nSsh=no\nAutologin=no\n"
            f"BaseTrees={profile / INPUT / INPUT_NAMES[0]}\n"
            f"ExtraTrees={extra}\nPackages=\n"
            f"CleanPackageMetadata=no\nSourceDateEpoch=0\n"
            f"\n[Build]\nWithNetwork=no\nCacheOnly=always\n"
            f"Incremental=no\nRepartOffline=yes\n"
            f"WorkspaceDirectory={profile.parent / (profile.name + '-work')}\n").encode()


def source_identity(metadata, archives, artifact, account_artifact, source, workspace):
    verified = root_profile.verify_profile(
        metadata, archives, artifact, account_artifact, source, workspace,
        include_overlay=True,
    )
    if (verified["status"] != root_profile.OVERLAY_STATUS
            or verified["committed_rootfs_overlay_included"] is not True
            or verified["runtime_binaries_included"] is not False
            or verified["package_install_configured"] is not False
            or verified["package_scripts_executed"] is not False
            or verified["disk_image_built"] is not False
            or verified["private_mode_approved"] is not False):
        raise ValueError("source profile changed diagnostic acceptance status")
    return verified


def checked_file_identity(parent, name, expected):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o400
                or before.st_size != expected["bytes"]):
            raise ValueError("disk diagnostic input size or mode differs")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after) or digest.hexdigest() != expected["sha256"]:
            raise ValueError("disk diagnostic input changed or differs from signed source")
    finally:
        os.close(descriptor)


def copy_input(source_parent, destination_parent, name, expected):
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=source_parent)
    try:
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o400
                or before.st_size != expected["bytes"]):
            raise ValueError("source input changed before disk profile copy")
        target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o400,
                         dir_fd=destination_parent)
        try:
            digest = hashlib.sha256()
            total = 0
            while chunk := os.read(source, 1024 * 1024):
                digest.update(chunk)
                total += len(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(target, view):]
            after = os.fstat(source)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                     item.st_mtime_ns, item.st_ctime_ns)
            if (identity(before) != identity(after)
                    or total != expected["bytes"]
                    or digest.hexdigest() != expected["sha256"]):
                raise ValueError("source input changed during disk profile copy")
            os.fchmod(target, 0o400)
            os.fsync(target)
        finally:
            os.close(target)
        checked_file_identity(destination_parent, name, expected)
    finally:
        os.close(source)


def source_inputs(source, source_report):
    """Use the previously verified source manifest without loading its tar."""
    descriptor = guest.open_directory(source, "authenticated root profile")
    try:
        size = os.stat(root_profile.MANIFEST, dir_fd=descriptor,
                       follow_symlinks=False).st_size
        encoded = root_profile.verified_file(descriptor, root_profile.MANIFEST, size)
        if sha256(encoded) != source_report["profile_manifest_sha256"]:
            raise ValueError("root profile manifest changed after verification")
        manifest = json.loads(encoded, object_pairs_hook=prepare.unique_object,
                              parse_constant=prepare.reject_nonfinite_constant)
        identities = {
            INPUT_NAMES[0]: {"sha256": manifest["base_tree_sha256"],
                             "bytes": manifest["base_tree_size"]},
            INPUT_NAMES[1]: {"sha256": manifest["account_tree_sha256"],
                             "bytes": manifest["account_tree_size"]},
            INPUT_NAMES[2]: {"sha256": manifest["source_overlay_sha256"],
                             "bytes": manifest["source_overlay_size"]},
        }
        for identity in identities.values():
            if (not isinstance(identity["sha256"], str)
                    or len(identity["sha256"]) != 64
                    or type(identity["bytes"]) is not int
                    or identity["bytes"] <= 0):
                raise ValueError("root profile input identity malformed")
        input_fd = os.open(INPUT, builder.DIRECTORY_FLAGS, dir_fd=descriptor)
        try:
            checked_file_identity(input_fd, INPUT_NAMES[0], identities[INPUT_NAMES[0]])
        finally:
            os.close(input_fd)
        for name in INPUT_NAMES[1:]:
            checked_file_identity(descriptor, name, identities[name])
        return identities
    finally:
        os.close(descriptor)


def repart_bytes():
    prepare.validate_boot_profile()
    return {name: (prepare.PROFILE / REPART / name).read_bytes()
            for name in REPART_NAMES}


def expected_manifest(source_report, inputs, repart, config):
    return {
        "schema_version": 1,
        "status": STATUS,
        "mkosi_source_commit": prepare.SOURCE_COMMIT,
        "guest_package_closure_sha256": prepare.PACKAGE_CLOSURE_SHA256,
        "source_profile_manifest_sha256": source_report["profile_manifest_sha256"],
        "base_tree_sha256": source_report["base_tree_sha256"],
        "inputs": {name: identity for name, identity in sorted(inputs.items())},
        "repart": {name: sha256(data) for name, data in sorted(repart.items())},
        "mkosi_config_sha256": sha256(config),
        "repart_seed": str(seed_for(source_report["profile_manifest_sha256"])),
        "sector_size": 512,
        "signed_snapshot_rechecked": True,
        "package_install_configured": False,
        "package_scripts_executed": False,
        "runtime_binaries_included": False,
        "esp_included": False,
        "uki_included": False,
        "boot_verified": False,
        "disk_image_built": False,
        "disk_root_contents_audited": False,
        "private_mode_approved": False,
    }


def expected(metadata, archives, artifact, account_artifact, source,
             profile, workspace):
    source = root_profile.checked_profile_path(source, workspace)
    profile = root_profile.checked_profile_path(profile, workspace)
    if source == profile:
        raise ValueError("source and disk profile paths must differ")
    source_report = source_identity(metadata, archives, artifact,
                                    account_artifact, source, workspace)
    inputs = source_inputs(source, source_report)
    if inputs[INPUT_NAMES[0]]["sha256"] != source_report["base_tree_sha256"]:
        raise ValueError("source BaseTrees identity changed")
    repart = repart_bytes()
    config = config_bytes(profile, source_report["profile_manifest_sha256"])
    manifest = expected_manifest(source_report, inputs, repart, config)
    return profile, inputs, repart, config, manifest


def receipt(manifest):
    return {"status": manifest["status"],
            "profile_manifest_sha256": sha256(root_profile.canonical_bytes(manifest)),
            "base_tree_sha256": manifest["base_tree_sha256"],
            "repart_sha256": manifest["repart"],
            "package_install_configured": False,
            "package_scripts_executed": False,
            "runtime_binaries_included": False,
            "esp_included": False,
            "uki_included": False,
            "boot_verified": False,
            "disk_image_built": False,
            "disk_root_contents_audited": False,
            "private_mode_approved": False}


def inspect_staged_builder(root, expected):
    """Compare every non-mounted staged object to signed package payloads."""
    actual = set()
    root_fd = os.open(root, builder.DIRECTORY_FLAGS)
    try:
        def walk(directory, prefix=""):
            with os.scandir(directory) as entries:
              for entry in entries:
                name = entry.name
                relative = f"{prefix}/{name}" if prefix else name
                if not prefix and (name in MOUNTED_SCRATCH or
                                   name == builder.MANIFEST):
                    continue
                record = expected.get(relative)
                if record is None:
                    raise ValueError("staged builder contains unreviewed file: " + relative)
                observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (record["kind"] != "symlink"
                        and stat.S_IMODE(observed.st_mode) != record["staged_mode"]):
                    raise ValueError("staged builder mode differs: " + relative)
                if record["kind"] == "directory":
                    if not stat.S_ISDIR(observed.st_mode):
                        raise ValueError("staged builder directory differs: " + relative)
                    child = os.open(name, builder.DIRECTORY_FLAGS, dir_fd=directory)
                    try:
                        walk(child, relative)
                    finally:
                        os.close(child)
                elif record["kind"] == "symlink":
                    if (not stat.S_ISLNK(observed.st_mode)
                            or os.readlink(name, dir_fd=directory) != record["target"]):
                        raise ValueError("staged builder symlink differs: " + relative)
                elif record["kind"] == "file":
                    if not stat.S_ISREG(observed.st_mode) or observed.st_size != record["size"]:
                        raise ValueError("staged builder file size differs: " + relative)
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                         os.O_CLOEXEC, dir_fd=directory)
                    try:
                        before = os.fstat(descriptor)
                        digest = hashlib.sha256()
                        while chunk := os.read(descriptor, 1024 * 1024):
                            digest.update(chunk)
                        after = os.fstat(descriptor)
                        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                                 item.st_mtime_ns, item.st_ctime_ns)
                        if (identity(before) != identity(after)
                                or digest.hexdigest() != record["sha256"]):
                            raise ValueError("staged builder file differs: " + relative)
                    finally:
                        os.close(descriptor)
                else:
                    raise ValueError("staged builder has unsupported entry kind")
                actual.add(relative)

        walk(root_fd)
    finally:
        os.close(root_fd)
    wanted = {path for path in expected
              if path.split("/", 1)[0] not in MOUNTED_SCRATCH}
    if actual != wanted:
        raise ValueError("staged builder package file missing")
    return len(actual)


def verify_execution_context(metadata, builder_archives, parent_net_ns,
                             apt_scratch):
    """Fail before mkosi unless signed tools and no-route isolation are live."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native x86_64 Linux builder required")
    current = os.readlink("/proc/self/ns/net")
    if (not isinstance(parent_net_ns, str)
            or not re.fullmatch(r"net:\[[0-9]+\]", parent_net_ns)
            or not re.fullmatch(r"net:\[[0-9]+\]", current)
            or current == parent_net_ns
            or {name for _, name in socket.if_nameindex()} != {"lo"}):
        raise ValueError("outer no-route network namespace not established")
    ipv4 = Path("/proc/net/route").read_text().splitlines()
    ipv6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if (not ipv4
            or any(not line.split() or line.split()[0] != "lo" for line in ipv4[1:])
            or any(not line.split() or line.split()[-1] != "lo" for line in ipv6)):
        raise ValueError("outer namespace has a non-loopback route")
    signed = builder_closure.verify(
        metadata / "InRelease", metadata / "Packages.xz",
        builder_archives, Path("/usr/bin/apt-get"), apt_scratch)
    if (signed["status"] != "diagnostic-signed-builder-apt-plan-matched-unbuilt"
            or signed["private_mode_approved"] is not False):
        raise ValueError("signed builder closure not established")
    lock, _, lock_sha256, _ = builder_fetch.authenticated_packages(
        metadata / "InRelease", metadata / "Packages.xz")
    archives_fd = guest.open_directory(builder_archives, "builder archives")
    try:
        packages = [(entry["name"], builder.locked_archive(entry, archives_fd))
                    for entry in lock["packages"]]
    finally:
        os.close(archives_fd)
    payloads, expected = builder.payload_entries(packages)
    del payloads, packages
    manifest = {"schema_version": 1, "status": builder.STATUS,
                "builder_closure_lock_sha256": lock_sha256,
                "snapshot": lock["snapshot"],
                "package_count": len(lock["packages"]),
                "entries": [expected[path] for path in sorted(expected)],
                "signed_snapshot_rechecked": False,
                "package_scripts_executed": False,
                "runtime_execution_verified": False,
                "complete_builder_toolchain": False,
                "image_built": False, "private_mode_approved": False}
    encoded = root_profile.canonical_bytes(manifest)
    root_fd = os.open("/", builder.DIRECTORY_FLAGS)
    try:
        stored = root_profile.verified_file(root_fd, builder.MANIFEST,
                                            len(encoded), mode=0o600)
    finally:
        os.close(root_fd)
    if stored != encoded:
        raise ValueError("staged builder manifest differs from signed payloads")
    count = inspect_staged_builder(Path("/"), expected)
    return {"status": "diagnostic-signed-staged-builder-no-route",
            "signed_builder_package_count": len(lock["packages"]),
            "staged_entries_checked": count,
            "network_namespace": current,
            "complete_builder_toolchain": False,
            "private_mode_approved": False}


def prepare_profile(metadata, archives, artifact, account_artifact, source,
                    profile, workspace):
    profile, inputs, repart, config, manifest = expected(
        metadata, archives, artifact, account_artifact, source, profile, workspace)
    parent = builder.output_parent(Path(workspace), profile)
    try:
        os.mkdir(profile.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)
    descriptor = guest.open_directory(profile, "disk diagnostic profile")
    try:
        source_fd = guest.open_directory(source, "authenticated root profile")
        try:
            for directory, entries in ((INPUT, inputs), (REPART, repart)):
                os.mkdir(directory, mode=0o700, dir_fd=descriptor)
                child = os.open(directory, builder.DIRECTORY_FLAGS, dir_fd=descriptor)
                try:
                    if directory == INPUT:
                        source_input = os.open(INPUT, builder.DIRECTORY_FLAGS,
                                               dir_fd=source_fd)
                        try:
                            for name, identity in entries.items():
                                parent_fd = source_input if name == INPUT_NAMES[0] else source_fd
                                copy_input(parent_fd, child, name, identity)
                        finally:
                            os.close(source_input)
                    else:
                        for name, data in entries.items():
                            root_profile.write_file(child, name, data)
                    os.fchmod(child, 0o500)
                    os.fsync(child)
                finally:
                    os.close(child)
        finally:
            os.close(source_fd)
        root_profile.write_file(descriptor, CONFIG, config)
        root_profile.write_file(descriptor, MANIFEST,
                                root_profile.canonical_bytes(manifest))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return receipt(manifest)


def verify_profile(metadata, archives, artifact, account_artifact, source,
                   profile, workspace):
    profile, inputs, repart, config, manifest = expected(
        metadata, archives, artifact, account_artifact, source, profile, workspace)
    descriptor = guest.open_directory(profile, "disk diagnostic profile")
    try:
        if (stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700
                or {entry.name for entry in os.scandir(descriptor)} !=
                {INPUT, REPART, CONFIG, MANIFEST}):
            raise ValueError("disk profile has unreviewed inputs")
        for directory, entries in ((INPUT, inputs), (REPART, repart)):
            child = os.open(directory, builder.DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                if (stat.S_IMODE(os.fstat(child).st_mode) != 0o500
                        or {entry.name for entry in os.scandir(child)} != set(entries)):
                    raise ValueError("disk profile input set differs")
                for name, data in entries.items():
                    if directory == INPUT:
                        checked_file_identity(child, name, data)
                    elif root_profile.verified_file(child, name, len(data)) != data:
                        raise ValueError("disk profile repart differs from committed source")
            finally:
                os.close(child)
        if root_profile.verified_file(descriptor, CONFIG, len(config)) != config:
            raise ValueError("disk profile config differs")
        encoded = root_profile.canonical_bytes(manifest)
        if root_profile.verified_file(descriptor, MANIFEST, len(encoded)) != encoded:
            raise ValueError("disk profile manifest differs")
    finally:
        os.close(descriptor)
    return receipt(manifest)


def build_disk(metadata, archives, artifact, account_artifact, source,
               profile, workspace, builder_archives, parent_net_ns,
               apt_scratch):
    before = verify_profile(metadata, archives, artifact, account_artifact,
                            source, profile, workspace)
    output = Path(profile).parent / (Path(profile).name + "-output") / OUTPUT
    if output.exists() or output.is_symlink():
        raise ValueError("disk diagnostic output already exists")
    if not isinstance(builder_archives, Path) or not isinstance(apt_scratch, Path):
        raise ValueError("signed builder archive and scratch paths required")
    execution = verify_execution_context(metadata, builder_archives,
                                         parent_net_ns, apt_scratch)
    subprocess.run(["/usr/bin/mkosi", f"--directory={profile}", "build"], check=True)
    after = verify_profile(metadata, archives, artifact, account_artifact,
                           source, profile, workspace)
    if after != before or output.is_symlink():
        raise ValueError("mkosi changed verified disk profile inputs")
    descriptor = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size == 0:
            raise ValueError("mkosi did not emit a regular raw disk")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256")
        raw_after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(raw_after):
            raise ValueError("mkosi raw disk changed during hashing")
    finally:
        os.close(descriptor)
    return {**after, "status": BUILT_STATUS, "disk_image_built": True,
            "raw_disk_sha256": digest.hexdigest(), "raw_disk_bytes": before.st_size,
            "builder_execution": execution,
            "gpt_checked": False, "verity_userspace_verified": False,
            "production_image_built": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "build"))
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--account-artifact", type=Path, required=True)
    parser.add_argument("--source-profile", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--builder-archives", type=Path)
    parser.add_argument("--parent-network-namespace")
    parser.add_argument("--apt-scratch", type=Path)
    args = parser.parse_args(argv)
    try:
        workspace = args.workspace or Path(os.environ["CODEX_WORKSPACE_DIR"])
        parameters = (args.metadata, args.archives, args.artifact,
                      args.account_artifact, args.source_profile,
                      args.profile, workspace)
        if args.command == "build":
            report = build_disk(*parameters, args.builder_archives,
                                args.parent_network_namespace, args.apt_scratch)
        else:
            report = {"prepare": prepare_profile,
                      "verify": verify_profile}[args.command](*parameters)
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "disk_image_built": False,
                          "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
