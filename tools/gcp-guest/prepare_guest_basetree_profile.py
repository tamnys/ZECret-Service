#!/usr/bin/env python3
"""Prepare and exercise a non-bootable mkosi BaseTrees root diagnostic.

The input tar is reconstructed from the signed Debian guest closure. The only
additional tree input is a deterministic tar of signed-source account files
and the source-bound project sysusers file. This profile never configures a
package manager or a guest disk/UKI build. Pinned mkosi 25.3 still runs its
own sysusers, tmpfiles, preset, depmod, firstboot, hwdb, and output steps;
those effects require a separate final-tree audit.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

import assemble_guest_base_tree as base_tree
import build_guest_accounts as accounts
import fetch_guest_closure as guest
import prepare
import stage_builder_toolchain as builder


STATUS = "diagnostic-no-package-install-root-basetree-profile-unbuilt"
MANIFEST = "profile-manifest.json"
CONFIG = "mkosi.conf"
INPUT = "input/guest-root.tar"
ACCOUNT_TREE = "account-tree.tar"
SOURCE_OVERLAY = "source-overlay.tar"
OVERLAY_STATUS = "diagnostic-no-package-source-overlay-profile-unbuilt"
ACCOUNT_FILE = "zrpc.conf"
INSTALLED_ACCOUNT_MODES = {"passwd": 0o644, "group": 0o644, "shadow": 0o000}
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


def config_bytes(profile, include_overlay=False):
    """Use signed Debian payloads and, optionally, the reviewed source overlay."""
    extra = f"{profile / ACCOUNT_TREE}"
    if include_overlay:
        extra += f",{profile / SOURCE_OVERLAY}"
    return (f"[Distribution]\nDistribution=custom\nArchitecture=x86-64\n"
            f"\n[Output]\nFormat=directory\nOutput={OUTPUT_NAME}\n"
            f"OutputDirectory={profile.parent / (profile.name + '-output')}\n"
            f"\n[Content]\nBootable=no\nSsh=no\nAutologin=no\n"
            f"BaseTrees={profile / INPUT}\n"
            f"ExtraTrees={extra}\nPackages=\n"
            f"CleanPackageMetadata=no\nSourceDateEpoch=0\n"
            f"\n[Build]\nWithNetwork=no\nCacheOnly=always\n"
            f"Incremental=no\n"
            f"PackageCacheDirectory={profile.parent / (profile.name + '-package-cache')}\n"
            f"WorkspaceDirectory={profile.parent / (profile.name + '-work')}\n").encode()


def source_overlay_bytes(workspace):
    """Archive all committed rootfs files plus production's boot overrides."""
    prepare.validate_boot_profile()
    source = prepare.PROFILE / "rootfs"
    source_fd = prepare.open_stage_directory(source)
    try:
        source_entries = prepare.staged_inventory(source_fd)
    finally:
        os.close(source_fd)
    with tempfile.TemporaryDirectory(prefix="zrpc-source-overlay-", dir=workspace) as scratch:
        tree = Path(scratch) / "rootfs"
        shutil.copytree(source, tree, symlinks=True)
        copied_fd = guest.open_directory(tree, "copied source overlay")
        try:
            prepare.staged_inventory(copied_fd, source_entries)
        finally:
            os.close(copied_fd)
        prepare.install_boot_overrides(tree)
        root = guest.open_directory(tree, "source overlay with boot overrides")
        try:
            entries = prepare.staged_inventory(root)
        finally:
            os.close(root)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
            for relative in sorted(entries, key=lambda item: (item.count("/"), item)):
                entry = entries[relative]
                path = tree / relative
                observed = path.lstat()
                header = tarfile.TarInfo(relative + ("/" if entry["type"] == "directory" else ""))
                header.uid = header.gid = 0
                header.mtime = 0
                header.mode = entry.get("mode", 0o777)
                if entry["type"] == "directory":
                    if not stat.S_ISDIR(observed.st_mode):
                        raise ValueError("source overlay directory changed")
                    header.type = tarfile.DIRTYPE
                    archive.addfile(header)
                elif entry["type"] == "symlink":
                    if not stat.S_ISLNK(observed.st_mode) or path.readlink().as_posix() != entry["target"]:
                        raise ValueError("source overlay link changed")
                    header.type = tarfile.SYMTYPE
                    header.linkname = entry["target"]
                    archive.addfile(header)
                elif entry["type"] == "file":
                    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
                        raise ValueError("source overlay regular file changed or hardlinked")
                    data = path.read_bytes()
                    if len(data) != observed.st_size or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                        raise ValueError("source overlay file changed")
                    header.type = tarfile.REGTYPE
                    header.size = len(data)
                    archive.addfile(header, io.BytesIO(data))
                else:
                    raise ValueError("source overlay contains unsupported entry")
        return output.getvalue()


def expected_manifest(source, archive_size, config, project, account_tree, overlay=None):
    manifest = {
        "schema_version": 2,
        "status": OVERLAY_STATUS if overlay is not None else STATUS,
        "guest_package_closure_sha256": prepare.PACKAGE_CLOSURE_SHA256,
        "mkosi_source_commit": prepare.SOURCE_COMMIT,
        "source_manifest_sha256": source["manifest_sha256"],
        "base_tree_sha256": source["archive_sha256"],
        "base_tree_size": archive_size,
        "project_sysusers_sha256": hashlib.sha256(project).hexdigest(),
        "project_sysusers_size": len(project),
        "account_tree_sha256": hashlib.sha256(account_tree).hexdigest(),
        "account_tree_size": len(account_tree),
        "account_artifact_regenerated_and_verified": True,
        "account_files_preseeded_from_signed_source": True,
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
    if overlay is not None:
        manifest.update(source_overlay_sha256=hashlib.sha256(overlay).hexdigest(),
                        source_overlay_size=len(overlay),
                        committed_rootfs_overlay_included=True,
                        runtime_binaries_included=False,
                        production_package_install_exercised=False)
    return manifest


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


def verified_account_files(metadata, archives, account_artifact, workspace):
    """Regenerate signed expectations before reading the stored artifact."""
    receipt = accounts.verify(metadata, archives, workspace, account_artifact)
    if (receipt["status"] != "diagnostic-verified-guest-account-artifact-unbuilt"
            or receipt["independent_generation_runs_matched"] is not True
            or receipt["package_scripts_executed"] is not False
            or receipt["installed_rootfs_accounts_compared"] is not False
            or receipt["image_built"] is not False
            or receipt["private_mode_approved"] is not False):
        raise ValueError("signed-source account artifact changed acceptance status")
    rows = receipt["outputs"]
    if (len(rows) != len(accounts.OUTPUT_FILES)
            or {row["path"] for row in rows} !=
            {"etc/" + name for name in accounts.OUTPUT_FILES}):
        raise ValueError("signed-source account output inventory differs")
    root = guest.open_directory(account_artifact, "signed-source account artifact")
    try:
        etc = os.open("etc", builder.DIRECTORY_FLAGS, dir_fd=root)
        try:
            files = {}
            for row in rows:
                name = row["path"].removeprefix("etc/")
                mode = row["sysusers_generated_mode"]
                if (mode != INSTALLED_ACCOUNT_MODES[name]
                        or row["expected_root_uid"] != 0
                        or row["expected_root_gid"] != 0):
                    raise ValueError("signed-source account install metadata differs")
                data = verified_file(etc, name, row["size"], mode=row["mode"])
                if (len(data) != row["size"]
                        or hashlib.sha256(data).hexdigest() != row["sha256"]):
                    raise ValueError("signed-source account artifact bytes differ: " + name)
                files[name] = (data, mode)
        finally:
            os.close(etc)
    finally:
        os.close(root)
    return files


def account_tree_bytes(project, files):
    """Create one exact root-owned ExtraTrees tar without executable hooks."""
    stream = io.BytesIO()
    entries = [("etc/" + name, *files[name]) for name in accounts.OUTPUT_FILES]
    entries.append(("usr/lib/sysusers.d/" + ACCOUNT_FILE, project, 0o644))
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("etc/", "usr/", "usr/lib/", "usr/lib/sysusers.d/"):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            member.uid = member.gid = 0
            member.mtime = 0
            archive.addfile(member)
        for name, data, mode in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = mode
            member.uid = member.gid = 0
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


def prepare_profile(metadata, archives, artifact, account_artifact, profile, workspace,
                    include_overlay=False):
    profile = checked_profile_path(profile, workspace)
    artifact = Path(artifact)
    if (not artifact.is_absolute() or artifact.resolve(strict=True) != artifact
            or not artifact.is_relative_to(Path(workspace).resolve(strict=True))):
        raise ValueError("guest BaseTrees artifact path is not workspace-owned")
    source = base_tree.verify(metadata, archives, artifact)
    project = project_sysusers_bytes()
    account_tree = account_tree_bytes(
        project, verified_account_files(metadata, archives, account_artifact, workspace))
    overlay = source_overlay_bytes(workspace) if include_overlay else None
    config = config_bytes(profile, include_overlay)
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
        write_file(root, ACCOUNT_TREE, account_tree)
        if overlay is not None:
            write_file(root, SOURCE_OVERLAY, overlay)
        manifest = expected_manifest(source, copied, config, project, account_tree, overlay)
        write_file(root, CONFIG, config)
        encoded = canonical_bytes(manifest)
        write_file(root, MANIFEST, encoded)
        os.fsync(root)
    finally:
        os.close(root)
    return {"status": manifest["status"], "profile_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "base_tree_sha256": source["archive_sha256"],
            "account_files_preseeded_from_signed_source": True,
            "committed_rootfs_overlay_included": include_overlay,
            "runtime_binaries_included": False,
            "production_package_install_exercised": False,
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


def verify_profile(metadata, archives, artifact, account_artifact, profile, workspace,
                   include_overlay=False):
    profile = checked_profile_path(profile, workspace)
    source = base_tree.verify(metadata, archives, artifact)
    project = project_sysusers_bytes()
    account_tree = account_tree_bytes(
        project, verified_account_files(metadata, archives, account_artifact, workspace))
    overlay = source_overlay_bytes(workspace) if include_overlay else None
    root = guest.open_directory(profile, "mkosi diagnostic profile")
    try:
        if stat.S_IMODE(os.fstat(root).st_mode) != 0o700:
            raise ValueError("mkosi diagnostic profile directory mode differs")
        expected_names = {"input", ACCOUNT_TREE, CONFIG, MANIFEST}
        if include_overlay:
            expected_names.add(SOURCE_OVERLAY)
        if {entry.name for entry in os.scandir(root)} != expected_names:
            raise ValueError("mkosi diagnostic profile has unreviewed inputs")
        config = verified_file(root, CONFIG, len(config_bytes(profile, include_overlay)))
        if config != config_bytes(profile, include_overlay):
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
        if verified_file(root, ACCOUNT_TREE, len(account_tree)) != account_tree:
            raise ValueError("mkosi diagnostic account tree differs from signed source")
        if overlay is not None and verified_file(root, SOURCE_OVERLAY, len(overlay)) != overlay:
            raise ValueError("mkosi diagnostic source overlay differs from committed source")
        manifest = expected_manifest(source, archive_size, config, project, account_tree, overlay)
        encoded = canonical_bytes(manifest)
        if verified_file(root, MANIFEST, len(encoded)) != encoded:
            raise ValueError("mkosi diagnostic profile manifest differs from signed source")
    finally:
        os.close(root)
    return {"status": manifest["status"], "profile_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "base_tree_sha256": archive_sha256,
            "account_files_preseeded_from_signed_source": True,
            "committed_rootfs_overlay_included": include_overlay,
            "runtime_binaries_included": False,
            "production_package_install_exercised": False,
            "package_install_configured": False, "package_scripts_executed": False,
            "root_directory_built": False, "disk_image_built": False,
            "boot_verified": False, "private_mode_approved": False}


def build_root_directory(metadata, archives, artifact, account_artifact,
                         profile, workspace, include_overlay=False):
    """Run the pinned CI tool after source checks; never create a boot image."""
    profile = checked_profile_path(profile, workspace)
    before = verify_profile(metadata, archives, artifact, account_artifact,
                            profile, workspace, include_overlay)
    output = profile.parent / (profile.name + "-output") / OUTPUT_NAME
    if output.exists() or output.is_symlink():
        raise ValueError("mkosi diagnostic output already exists")
    package_cache = profile.parent / (profile.name + "-package-cache")
    if package_cache.exists() or package_cache.is_symlink():
        raise ValueError("mkosi diagnostic package cache already exists")
    subprocess.run(["/usr/bin/mkosi", f"--directory={profile}", "build"], check=True)
    after = verify_profile(metadata, archives, artifact, account_artifact,
                           profile, workspace, include_overlay)
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
    parser.add_argument("--account-artifact", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--source-overlay", action="store_true")
    args = parser.parse_args(argv)
    try:
        workspace = args.workspace or Path(os.environ["CODEX_WORKSPACE_DIR"])
        action = {"prepare": prepare_profile, "verify": verify_profile,
                  "build": build_root_directory}[args.command]
        report = action(args.metadata, args.archives, args.artifact,
                        args.account_artifact, args.profile, workspace,
                        args.source_overlay)
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "disk_image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
