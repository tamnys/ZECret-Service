#!/usr/bin/env python3
"""Prepare and exercise a non-bootable mkosi BaseTrees root diagnostic.

The input tar is reconstructed from the signed Debian guest closure. The only
additional tree input is the source-bound project sysusers file. This profile
never configures a package manager or a guest disk/UKI build. Pinned
mkosi 25.3 still runs its own sysusers, tmpfiles, preset, depmod, firstboot,
hwdb, and output steps; those effects require a separate final-tree audit.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import assemble_guest_base_tree as base_tree
import build_guest_accounts as accounts
import fetch_guest_closure as guest
import prepare
import stage_builder_toolchain as builder


STATUS = "diagnostic-no-package-install-root-basetree-profile-unbuilt"
MANIFEST = "profile-manifest.json"
CONFIG = "mkosi.conf"
INPUT = "input/guest-root.tar"
ACCOUNT_TREE = "account-tree"
ACCOUNT_TREE_DIRS = (ACCOUNT_TREE, "usr", "lib", "sysusers.d")
ACCOUNT_FILE = "zrpc.conf"
PROJECT_SYSUSERS = accounts.PROJECT_SYSUSERS
OUTPUT_NAME = "zrpc-guest-root"
ALLOWED_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def checked_profile_path(profile, workspace):
    profile = Path(profile)
    workspace = Path(workspace)
    if (not profile.is_absolute() or ".." in profile.parts
            or not ALLOWED_PATH.fullmatch(str(profile))):
        raise ValueError("mkosi diagnostic profile path is not canonical")
    parent = builder.output_parent(workspace, profile)
    os.close(parent)
    return profile


def config_bytes(profile):
    """Only the authenticated archive and one project sysusers file enter."""
    return (f"[Distribution]\nDistribution=custom\nArchitecture=x86-64\n"
            f"\n[Output]\nFormat=directory\nOutput={OUTPUT_NAME}\n"
            f"OutputDirectory={profile.parent / (profile.name + '-output')}\n"
            f"\n[Content]\nBootable=no\nSsh=no\nAutologin=no\n"
            f"BaseTrees={profile / INPUT}\n"
            f"ExtraTrees={profile / ACCOUNT_TREE}\nPackages=\n"
            f"CleanPackageMetadata=no\nSourceDateEpoch={guest.SIGNED_RELEASE_EPOCH}\n"
            f"\n[Build]\nWithNetwork=no\nCacheOnly=always\n"
            f"Incremental=no\n"
            f"WorkspaceDirectory={profile.parent / (profile.name + '-work')}\n").encode()


def expected_manifest(source, archive_size, config, project):
    return {
        "schema_version": 2,
        "status": STATUS,
        "guest_package_closure_sha256": prepare.PACKAGE_CLOSURE_SHA256,
        "mkosi_source_commit": prepare.SOURCE_COMMIT,
        "source_manifest_sha256": source["manifest_sha256"],
        "base_tree_sha256": source["archive_sha256"],
        "base_tree_size": archive_size,
        "project_sysusers_sha256": hashlib.sha256(project).hexdigest(),
        "project_sysusers_size": len(project),
        "source_date_epoch": guest.SIGNED_RELEASE_EPOCH,
        "mkosi_config_sha256": hashlib.sha256(config).hexdigest(),
        "signed_snapshot_rechecked": True,
        "archive_bytes_checked": True,
        "package_install_configured": False,
        "package_scripts_executed": False,
        "root_directory_built": False,
        "disk_image_built": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }


def write_file(parent, name, data, mode=0o400):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def project_sysusers_bytes():
    descriptor = os.open(PROJECT_SYSUSERS, os.O_RDONLY | os.O_NONBLOCK |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) & 0o022):
            raise ValueError("project sysusers source missing, redirected, or mutable")
        data = bytearray()
        while len(data) <= before.st_size:
            chunk = os.read(descriptor, min(65536, before.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError("project sysusers source changed during inspection")
        return bytes(data)
    finally:
        os.close(descriptor)


def stage_account_tree(root, project):
    opened = []
    parent = root
    try:
        for part in ACCOUNT_TREE_DIRS:
            os.mkdir(part, mode=0o700, dir_fd=parent)
            child = os.open(part, builder.DIRECTORY_FLAGS, dir_fd=parent)
            opened.append(child)
            parent = child
        write_file(parent, ACCOUNT_FILE, project, mode=0o444)
        for child in reversed(opened):
            os.fchmod(child, 0o555)
            os.fsync(child)
    finally:
        for child in reversed(opened):
            os.close(child)


def prepare_profile(metadata, archives, artifact, profile, workspace):
    profile = checked_profile_path(profile, workspace)
    artifact = Path(artifact)
    if (not artifact.is_absolute() or artifact.resolve(strict=True) != artifact
            or not artifact.is_relative_to(Path(workspace).resolve(strict=True))):
        raise ValueError("guest BaseTrees artifact path is not workspace-owned")
    source = base_tree.verify(metadata, archives, artifact)
    project = project_sysusers_bytes()
    config = config_bytes(profile)
    parent = builder.output_parent(Path(workspace), profile)
    try:
        os.mkdir(profile.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)
    root = guest.open_directory(profile, "mkosi diagnostic profile")
    try:
        os.mkdir("input", mode=0o700, dir_fd=root)
        input_fd = os.open("input", builder.DIRECTORY_FLAGS, dir_fd=root)
        artifact_fd = guest.open_directory(artifact, "guest BaseTrees candidate")
        try:
            src = os.open(base_tree.ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW |
                          os.O_CLOEXEC, dir_fd=artifact_fd)
            dst = os.open(base_tree.ARCHIVE, os.O_WRONLY | os.O_CREAT |
                          os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400,
                          dir_fd=input_fd)
            try:
                before = os.fstat(src)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("guest BaseTrees archive is not a regular file")
                digest = hashlib.sha256()
                copied = 0
                while chunk := os.read(src, 1024 * 1024):
                    digest.update(chunk)
                    copied += len(chunk)
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(dst, view):]
                after = os.fstat(src)
                if ((before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns)
                    or copied != before.st_size
                    or digest.hexdigest() != source["archive_sha256"]):
                    raise ValueError("guest BaseTrees archive changed during profile staging")
                os.fchmod(dst, 0o400)
                os.fsync(dst)
            finally:
                os.close(src)
                os.close(dst)
            os.fchmod(input_fd, 0o500)
            os.fsync(input_fd)
        finally:
            os.close(artifact_fd)
            os.close(input_fd)
        stage_account_tree(root, project)
        manifest = expected_manifest(source, copied, config, project)
        write_file(root, CONFIG, config)
        encoded = canonical_bytes(manifest)
        write_file(root, MANIFEST, encoded)
        os.fsync(root)
    finally:
        os.close(root)
    return {"status": STATUS, "profile_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "base_tree_sha256": source["archive_sha256"],
            "package_install_configured": False, "package_scripts_executed": False,
            "root_directory_built": False, "disk_image_built": False,
            "boot_verified": False, "private_mode_approved": False}


def verified_file(parent, name, maximum, mode=0o400):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or stat.S_IMODE(observed.st_mode) != mode:
            raise ValueError("mkosi diagnostic profile file metadata differs")
        if observed.st_size > maximum:
            raise ValueError("mkosi diagnostic profile file exceeds bound")
        data = bytearray()
        while chunk := os.read(fd, 1024 * 1024):
            data.extend(chunk)
            if len(data) > maximum:
                raise ValueError("mkosi diagnostic profile file exceeds bound")
        after = os.fstat(fd)
        if ((observed.st_dev, observed.st_ino, observed.st_size,
             observed.st_mtime_ns, observed.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size,
             after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("mkosi diagnostic profile file changed during inspection")
        return bytes(data)
    finally:
        os.close(fd)


def verified_archive(parent):
    fd = os.open(base_tree.ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o400):
            raise ValueError("mkosi diagnostic BaseTrees archive metadata differs")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(fd)
        if (size != before.st_size or
            (before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size,
             after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("mkosi diagnostic BaseTrees archive changed during inspection")
        return digest.hexdigest(), size
    finally:
        os.close(fd)


def verified_account_tree(root, project):
    opened = []
    parent = root
    try:
        for index, part in enumerate(ACCOUNT_TREE_DIRS):
            child = os.open(part, builder.DIRECTORY_FLAGS, dir_fd=parent)
            opened.append(child)
            parent = child
            expected = (ACCOUNT_TREE_DIRS[index + 1]
                        if index + 1 < len(ACCOUNT_TREE_DIRS) else ACCOUNT_FILE)
            if (stat.S_IMODE(os.fstat(child).st_mode) != 0o555
                    or set(os.listdir(child)) != {expected}):
                raise ValueError("mkosi diagnostic project sysusers tree differs")
        if verified_file(parent, ACCOUNT_FILE, len(project), mode=0o444) != project:
            raise ValueError("mkosi diagnostic project sysusers bytes differ from source")
    finally:
        for child in reversed(opened):
            os.close(child)


def verify_profile(metadata, archives, artifact, profile, workspace):
    profile = checked_profile_path(profile, workspace)
    source = base_tree.verify(metadata, archives, artifact)
    project = project_sysusers_bytes()
    root = guest.open_directory(profile, "mkosi diagnostic profile")
    try:
        if stat.S_IMODE(os.fstat(root).st_mode) != 0o700:
            raise ValueError("mkosi diagnostic profile directory mode differs")
        if {entry.name for entry in os.scandir(root)} != {"input", ACCOUNT_TREE,
                                                         CONFIG, MANIFEST}:
            raise ValueError("mkosi diagnostic profile has unreviewed inputs")
        config = verified_file(root, CONFIG, len(config_bytes(profile)))
        if config != config_bytes(profile):
            raise ValueError("mkosi diagnostic config differs from script-free profile")
        input_fd = os.open("input", builder.DIRECTORY_FLAGS, dir_fd=root)
        try:
            if (stat.S_IMODE(os.fstat(input_fd).st_mode) != 0o500
                    or {entry.name for entry in os.scandir(input_fd)} != {base_tree.ARCHIVE}):
                raise ValueError("mkosi diagnostic BaseTrees input differs")
            archive_sha256, archive_size = verified_archive(input_fd)
        finally:
            os.close(input_fd)
        if archive_sha256 != source["archive_sha256"]:
            raise ValueError("mkosi diagnostic BaseTrees archive differs from signed source")
        verified_account_tree(root, project)
        manifest = expected_manifest(source, archive_size, config, project)
        encoded = canonical_bytes(manifest)
        if verified_file(root, MANIFEST, len(encoded)) != encoded:
            raise ValueError("mkosi diagnostic profile manifest differs from signed source")
    finally:
        os.close(root)
    return {"status": STATUS, "profile_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "base_tree_sha256": archive_sha256,
            "package_install_configured": False, "package_scripts_executed": False,
            "root_directory_built": False, "disk_image_built": False,
            "boot_verified": False, "private_mode_approved": False}


def build_root_directory(metadata, archives, artifact, profile, workspace):
    """Run the pinned CI tool after source checks; never create a boot image."""
    profile = checked_profile_path(profile, workspace)
    before = verify_profile(metadata, archives, artifact, profile, workspace)
    output = profile.parent / (profile.name + "-output") / OUTPUT_NAME
    if output.exists() or output.is_symlink():
        raise ValueError("mkosi diagnostic output already exists")
    subprocess.run(["/usr/bin/mkosi", f"--directory={profile}", "build"], check=True)
    after = verify_profile(metadata, archives, artifact, profile, workspace)
    if after != before or output.is_symlink() or not output.is_dir():
        raise ValueError("mkosi diagnostic build did not preserve verified inputs or output a directory")
    return {**before, "status": "diagnostic-root-directory-built-unapproved",
            "root_directory_built": True, "post_mkosi_tree_audited": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "build"))
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args(argv)
    try:
        workspace = args.workspace or Path(os.environ["CODEX_WORKSPACE_DIR"])
        action = {"prepare": prepare_profile, "verify": verify_profile,
                  "build": build_root_directory}[args.command]
        report = action(args.metadata, args.archives, args.artifact,
                        args.profile, workspace)
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "disk_image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
