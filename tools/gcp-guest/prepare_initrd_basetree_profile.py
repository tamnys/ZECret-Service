#!/usr/bin/env python3
"""Stage a no-package mkosi CPIO diagnostic from source-bound inputs.

The Debian tree is regenerated from signed package data, while /init comes
only from the matching, double-built x86_64 Rust receipt. The staged audit is
the selected source's initrd audit with that /init digest fixed into it.
Preparation does not build, sign, boot, or approve anything.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile

import assemble_initrd_base_tree as initrd_input
import export_rust_inputs as rust_inputs
import fetch_guest_closure as guest
import preflight_initrd_build as preflight
import prepare_guest_basetree_profile as root_profile
import stage_builder_toolchain as builder


STATUS = "diagnostic-no-package-initrd-cpio-profile-unbuilt"
ARCHIVE = initrd_input.ARCHIVE
INPUT = "input/" + ARCHIVE
INIT_TREE = "init-tree.tar"
AUDIT = "audit-initrd.py"
CONFIG = "mkosi.conf"
MANIFEST = "profile-manifest.json"
OUTPUT_NAME = "initrd.cpio.zst"


def config_bytes(profile):
    return (f"[Distribution]\nDistribution=custom\nArchitecture=x86-64\n"
            f"\n[Output]\nFormat=cpio\nOutput=initrd\n"
            f"CompressOutput=zstd\n"
            f"OutputDirectory={profile.parent / (profile.name + '-output')}\n"
            f"\n[Content]\nBootable=no\nMakeInitrd=yes\nSsh=no\n"
            f"Autologin=no\nBaseTrees={profile / INPUT}\n"
            f"ExtraTrees={profile / INIT_TREE}\nPackages=\n"
            f"CleanPackageMetadata=no\nSourceDateEpoch=0\n"
            f"FinalizeScripts={profile / AUDIT}\n"
            f"\n[Build]\nWithNetwork=no\nCacheOnly=always\n"
            f"Incremental=no\n"
            f"WorkspaceDirectory={profile.parent / (profile.name + '-work')}\n").encode()


def init_tree_bytes(binary):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("init")
        entry.type = tarfile.REGTYPE
        entry.uid = entry.gid = 0
        entry.mode = 0o555
        entry.mtime = 0
        entry.size = len(binary)
        archive.addfile(entry, io.BytesIO(binary))
    return stream.getvalue()


def checked_inputs(metadata, archives, artifact, rust_bundle, revision, workspace):
    workspace = Path(workspace).resolve(strict=True)
    artifact = Path(artifact)
    rust_bundle = Path(rust_bundle)
    if (not artifact.is_absolute() or artifact.resolve(strict=True) != artifact
            or not artifact.is_relative_to(workspace)
            or not rust_bundle.is_absolute()
            or rust_bundle.resolve(strict=True) != rust_bundle
            or not rust_bundle.is_relative_to(workspace)):
        raise ValueError("initrd and Rust inputs must be real workspace paths")
    # The preflight reauthenticates the Debian snapshot, reconstructs the
    # selected tar, checks the exact Rust source commit and both binary builds.
    source = preflight.preflight(metadata, archives, artifact, rust_bundle, revision)
    if (source.get("status") != "blocked"
            or source.get("reason") !=
            "pinned mkosi CPIO build and post-build audit have not been executed"
            or not isinstance(source.get("early_init_sha256"), str)
            or source.get("rust_source_commit") != revision
            or any(source.get(field) is not False for field in (
                "package_control_scripts_executed", "network_used_for_build",
                "mkosi_executed", "initrd_built", "boot_verified",
                "private_mode_approved"))):
        raise ValueError("initrd preflight changed non-accepting state")
    artifact_fd = guest.open_directory(artifact, "signed initrd input")
    try:
        archive_info = os.stat(ARCHIVE, dir_fd=artifact_fd, follow_symlinks=False)
        initrd_input.check_artifact_metadata(
            archive_info, directory=False, label="signed initrd archive")
        source["source_bound_archive_size"] = archive_info.st_size
    finally:
        os.close(artifact_fd)
    # This profile's own staging rules must be the selected source commit.
    script = rust_inputs.regular_bytes(Path(__file__).resolve(strict=True))
    if rust_inputs.git_bytes(revision, "tools/gcp-guest/prepare_initrd_basetree_profile.py") != script:
        raise ValueError("initrd profile script differs from selected source commit")
    binary = rust_inputs.regular_bytes(rust_bundle / "artifacts/zrpc-gcp-early-init")
    if (hashlib.sha256(binary).hexdigest() != source["early_init_sha256"]
            or not rust_inputs.x86_64_elf(binary)):
        raise ValueError("Rust /init changed after reproducible receipt inspection")
    audit_template = rust_inputs.regular_bytes(Path(__file__).with_name("audit-initrd.py"))
    if (rust_inputs.git_bytes(revision, "tools/gcp-guest/audit-initrd.py") != audit_template
            or not audit_template.startswith(b"#!/usr/bin/env python3\n")
            or audit_template.count(b"__STAGED_INIT_SHA256__") != 1):
        raise ValueError("initrd audit differs from selected source commit")
    audit = audit_template.replace(b"#!/usr/bin/env python3\n",
                                   b"#!/usr/bin/python3 -I\n", 1).replace(
                                       b"__STAGED_INIT_SHA256__",
                                       source["early_init_sha256"].encode())
    return source, binary, hashlib.sha256(script).hexdigest(), audit


def expected_manifest(source, archive_size, init_tree, config, script_sha256, audit):
    return {
        "schema_version": 1,
        "status": STATUS,
        "source_bound_archive_sha256": source["source_bound_archive_sha256"],
        "source_bound_manifest_sha256": source["source_bound_manifest_sha256"],
        "source_bound_archive_size": archive_size,
        "signed_snapshot_rechecked": True,
        "mkosi_source_commit": source["mkosi_source_commit"],
        "rust_source_commit": source["rust_source_commit"],
        "rust_receipt_sha256": source["rust_receipt_sha256"],
        "early_init_sha256": source["early_init_sha256"],
        "init_tree_sha256": hashlib.sha256(init_tree).hexdigest(),
        "initrd_audit_sha256": hashlib.sha256(audit).hexdigest(),
        "mkosi_config_sha256": hashlib.sha256(config).hexdigest(),
        "profile_script_sha256": script_sha256,
        "package_install_configured": False,
        "package_control_scripts_executed": False,
        "mkosi_executed": False,
        "initrd_built": False,
        "selective_cpio_audit_passed": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }


def result(manifest, encoded):
    return {
        "status": STATUS,
        "profile_manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        "source_bound_archive_sha256": manifest["source_bound_archive_sha256"],
        "early_init_sha256": manifest["early_init_sha256"],
        "initrd_audit_sha256": manifest["initrd_audit_sha256"],
        "package_install_configured": False,
        "package_control_scripts_executed": False,
        "mkosi_executed": False,
        "initrd_built": False,
        "selective_cpio_audit_passed": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }


def copy_archive(artifact, input_fd, expected_sha256, expected_size):
    src_parent = guest.open_directory(artifact, "signed initrd input")
    try:
        src = os.open(ARCHIVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=src_parent)
        dst = os.open(ARCHIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=input_fd)
        try:
            before = os.fstat(src)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError("signed initrd archive is not a single regular file")
            digest = hashlib.sha256()
            copied = 0
            while chunk := os.read(src, 1024 * 1024):
                digest.update(chunk)
                copied += len(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(dst, view):]
            after = os.fstat(src)
            if (initrd_input.artifact_identity(before) != initrd_input.artifact_identity(after)
                    or copied != before.st_size or copied != expected_size
                    or digest.hexdigest() != expected_sha256):
                raise ValueError("signed initrd archive changed during profile staging")
            os.fchmod(dst, 0o400)
            os.fsync(dst)
            return copied
        finally:
            os.close(src)
            os.close(dst)
    finally:
        os.close(src_parent)


def prepare_profile(metadata, archives, artifact, rust_bundle, revision, profile, workspace):
    profile = root_profile.checked_profile_path(profile, workspace)
    source, binary, script_sha256, audit = checked_inputs(
        metadata, archives, artifact, rust_bundle, revision, workspace)
    init_tree = init_tree_bytes(binary)
    config = config_bytes(profile)
    parent = builder.output_parent(Path(workspace), profile)
    try:
        os.mkdir(profile.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)
    root = guest.open_directory(profile, "mkosi initrd directory profile")
    try:
        os.mkdir("input", mode=0o700, dir_fd=root)
        input_fd = os.open("input", builder.DIRECTORY_FLAGS, dir_fd=root)
        try:
            archive_size = copy_archive(Path(artifact), input_fd,
                                        source["source_bound_archive_sha256"],
                                        source["source_bound_archive_size"])
            os.fchmod(input_fd, 0o500)
            os.fsync(input_fd)
        finally:
            os.close(input_fd)
        manifest = expected_manifest(source, archive_size, init_tree, config,
                                     script_sha256, audit)
        root_profile.write_file(root, INIT_TREE, init_tree)
        root_profile.write_file(root, AUDIT, audit, mode=0o500)
        root_profile.write_file(root, CONFIG, config)
        encoded = initrd_input.canonical_bytes(manifest)
        root_profile.write_file(root, MANIFEST, encoded)
        os.fsync(root)
    finally:
        os.close(root)
    return result(manifest, encoded)


def verify_profile(metadata, archives, artifact, rust_bundle, revision, profile, workspace):
    profile = root_profile.checked_profile_path(profile, workspace)
    source, binary, script_sha256, audit = checked_inputs(
        metadata, archives, artifact, rust_bundle, revision, workspace)
    init_tree = init_tree_bytes(binary)
    config = config_bytes(profile)
    root = guest.open_directory(profile, "mkosi initrd directory profile")
    try:
        if (stat.S_IMODE(os.fstat(root).st_mode) != 0o700
                or {entry.name for entry in os.scandir(root)} !=
                {"input", INIT_TREE, AUDIT, CONFIG, MANIFEST}):
            raise ValueError("mkosi initrd profile has unreviewed inputs")
        input_fd = os.open("input", builder.DIRECTORY_FLAGS, dir_fd=root)
        try:
            if (stat.S_IMODE(os.fstat(input_fd).st_mode) != 0o500
                    or {entry.name for entry in os.scandir(input_fd)} != {ARCHIVE}):
                raise ValueError("mkosi initrd BaseTrees input differs")
            archive = root_profile.verified_file(
                input_fd, ARCHIVE, source["source_bound_archive_size"])
        finally:
            os.close(input_fd)
        if hashlib.sha256(archive).hexdigest() != source["source_bound_archive_sha256"]:
            raise ValueError("mkosi initrd BaseTrees archive differs from signed source")
        if root_profile.verified_file(root, INIT_TREE, len(init_tree)) != init_tree:
            raise ValueError("mkosi initrd /init tree differs from Rust receipt")
        if root_profile.verified_file(root, AUDIT, len(audit), mode=0o500) != audit:
            raise ValueError("mkosi initrd audit differs from selected source")
        if root_profile.verified_file(root, CONFIG, len(config)) != config:
            raise ValueError("mkosi initrd config differs from no-package profile")
        manifest = expected_manifest(source, len(archive), init_tree, config,
                                     script_sha256, audit)
        encoded = initrd_input.canonical_bytes(manifest)
        if root_profile.verified_file(root, MANIFEST, len(encoded)) != encoded:
            raise ValueError("mkosi initrd profile manifest differs from signed source")
    finally:
        os.close(root)
    return result(manifest, encoded)


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(min(1024 * 1024, size - len(data)))
        if not chunk:
            raise ValueError("truncated initrd CPIO member")
        data.extend(chunk)
    return bytes(data)


def padded(stream, size):
    if any(exact(stream, -size % 4)):
        raise ValueError("nonzero initrd CPIO padding")


def parent_directory(root_fd, parts):
    current = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, builder.DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def extract_cpio(stream, root):
    """Parse mkosi's pinned GNU newc output without following archive links."""
    root_fd = guest.open_directory(root, "CPIO audit scratch")
    seen = set()
    try:
        while True:
            header = exact(stream, 110)
            if header[:6] != b"070701":
                raise ValueError("initrd CPIO is not GNU newc")
            try:
                fields = [int(header[offset:offset + 8], 16)
                          for offset in range(6, 110, 8)]
            except ValueError as error:
                raise ValueError("invalid initrd CPIO header") from error
            mode, uid, gid, nlink, size, namesize = (
                fields[1], fields[2], fields[3], fields[4], fields[6], fields[11])
            # Linux path components and the CPIO name's final NUL must fit
            # the host's actual pathname contract, not an invented limit.
            if not 1 <= namesize <= os.pathconf(root, "PC_PATH_MAX"):
                raise ValueError("initrd CPIO member name exceeds Linux path bound")
            raw_name = exact(stream, namesize)
            padded(stream, 110 + namesize)
            if not raw_name.endswith(b"\0") or b"\0" in raw_name[:-1]:
                raise ValueError("initrd CPIO member name is not NUL terminated")
            try:
                name = raw_name[:-1].decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("initrd CPIO member name is not UTF-8") from error
            if name == "TRAILER!!!":
                if size != 0:
                    raise ValueError("initrd CPIO trailer has data")
                if any(stream.read()):
                    raise ValueError("initrd CPIO has nonzero trailing data")
                break
            if name.startswith("./"):
                name = name[2:]
            parts = name.split("/")
            kind = stat.S_IFMT(mode)
            if (name.startswith("/") or not name or any(part in ("", ".", "..") for part in parts)
                    or name in seen or uid != 0 or gid != 0 or nlink < 1
                    or (kind != stat.S_IFDIR and nlink != 1)
                    or mode & (stat.S_ISUID | stat.S_ISGID)):
                raise ValueError("initrd CPIO member path or metadata is unsafe")
            seen.add(name)
            parent_fd = parent_directory(root_fd, parts[:-1])
            try:
                leaf = parts[-1]
                if kind == stat.S_IFDIR:
                    if size != 0:
                        raise ValueError("initrd CPIO directory has data")
                    os.mkdir(leaf, mode=0o700, dir_fd=parent_fd)
                    child = os.open(leaf, builder.DIRECTORY_FLAGS, dir_fd=parent_fd)
                    try:
                        os.fchmod(child, stat.S_IMODE(mode))
                    finally:
                        os.close(child)
                elif kind == stat.S_IFREG:
                    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                 dir_fd=parent_fd)
                    try:
                        remaining = size
                        while remaining:
                            chunk = exact(stream, min(remaining, 1024 * 1024))
                            view = memoryview(chunk)
                            while view:
                                view = view[os.write(fd, view):]
                            remaining -= len(chunk)
                        os.fchmod(fd, stat.S_IMODE(mode))
                    finally:
                        os.close(fd)
                elif kind == stat.S_IFLNK:
                    if size > os.pathconf(root, "PC_PATH_MAX"):
                        raise ValueError("initrd CPIO symlink exceeds Linux path bound")
                    target_bytes = exact(stream, size)
                    if not target_bytes or b"\0" in target_bytes:
                        raise ValueError("initrd CPIO symlink target is invalid")
                    try:
                        target = target_bytes.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise ValueError("initrd CPIO symlink target is not UTF-8") from error
                    os.symlink(target, leaf, dir_fd=parent_fd)
                else:
                    raise ValueError("initrd CPIO contains an unsupported file type")
            finally:
                os.close(parent_fd)
            padded(stream, size)
        if "init" not in seen:
            raise ValueError("initrd CPIO omits /init")
        return len(seen)
    finally:
        os.close(root_fd)


def audit_cpio(output, audit, workspace, expected_audit_sha256):
    """Run the selected initrd audit; this is not a complete runtime closure."""
    output = Path(output)
    if (output.parent.is_symlink() or output.is_symlink()
            or output.parent.resolve(strict=True) != output.parent
            or not output.is_file()):
        raise ValueError("mkosi CPIO output is missing or redirected")
    fd = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("mkosi CPIO output is not one regular file")
        with tempfile.TemporaryDirectory(prefix="zrpc-initrd-cpio-audit-",
                                         dir=workspace) as scratch:
            process = subprocess.Popen(
                ["/usr/bin/zstd", "--decompress", "--stdout", "--quiet"],
                stdin=fd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                if process.stdout is None:
                    raise ValueError("initrd CPIO decompressor has no output stream")
                count = extract_cpio(process.stdout, Path(scratch))
                process.stdout.close()
                if process.wait() != 0:
                    raise ValueError("initrd CPIO zstd decompression failed")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            audit_fd = os.open(audit, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                audit_before = os.fstat(audit_fd)
                if (not stat.S_ISREG(audit_before.st_mode)
                        or stat.S_IMODE(audit_before.st_mode) != 0o500
                        or audit_before.st_nlink != 1):
                    raise ValueError("initrd audit executable metadata differs")
                with os.fdopen(os.dup(audit_fd), "rb") as audit_stream:
                    observed_audit = hashlib.file_digest(audit_stream, "sha256").hexdigest()
                if (observed_audit != expected_audit_sha256
                        or initrd_input.artifact_identity(os.fstat(audit_fd)) !=
                        initrd_input.artifact_identity(audit_before)):
                    raise ValueError("initrd audit executable differs from selected source")
                os.lseek(audit_fd, 0, os.SEEK_SET)
                subprocess.run([sys.executable, "-I", "-B",
                                f"/proc/self/fd/{audit_fd}", "--root", scratch],
                               pass_fds=(audit_fd,), check=True)
                if initrd_input.artifact_identity(os.fstat(audit_fd)) != \
                        initrd_input.artifact_identity(audit_before):
                    raise ValueError("initrd audit executable changed during output scan")
            finally:
                os.close(audit_fd)
        if initrd_input.artifact_identity(os.fstat(fd)) != initrd_input.artifact_identity(before):
            raise ValueError("mkosi CPIO output changed during post-build audit")
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), "rb") as stream:
            sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        if initrd_input.artifact_identity(os.fstat(fd)) != initrd_input.artifact_identity(before):
            raise ValueError("mkosi CPIO output changed during hashing")
        return {"cpio_sha256": sha256, "cpio_size": before.st_size,
                "cpio_entry_count": count}
    finally:
        os.close(fd)


def build_cpio(metadata, archives, artifact, rust_bundle, revision, profile, workspace):
    """Keep execution blocked until a reviewed builder runner is available."""
    profile = root_profile.checked_profile_path(profile, workspace)
    verify_profile(metadata, archives, artifact, rust_bundle,
                   revision, profile, workspace)
    # The staged BaseTrees/ExtraTrees profile describes the intended CPIO
    # producer, and audit_cpio() is ready to inspect its output. The current
    # builder payload receipt explicitly says complete_builder_toolchain=false;
    # no native runner has authenticated the executable dependency closure
    # and proved an outer no-route namespace. Never invoke ambient mkosi.
    raise ValueError("CPIO build blocked: reviewed runnable builder toolchain and "
                     "verified outer no-route namespace are unavailable")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "build"))
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--rust-bundle", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        action = {"prepare": prepare_profile, "verify": verify_profile,
                  "build": build_cpio}[args.command]
        report = action(args.metadata, args.archives, args.artifact,
                        args.rust_bundle, args.revision, args.profile, args.workspace)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            subprocess.CalledProcessError) as error:
        report = {"status": "blocked", "reason": str(error),
                  "boot_verified": False, "private_mode_approved": False}
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
