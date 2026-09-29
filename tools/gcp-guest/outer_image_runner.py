#!/usr/bin/env python3
"""Build the staged production GCP disk inside an externally isolated builder.

This consumes a complete, source-bound input lock. A successful result proves
that one mkosi invocation emitted the inspected raw disk and companion files;
it does not approve the signer, firmware policy, boot, TDX, or private mode.
"""

import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import types


ROOT = Path(__file__).resolve(strict=True).parents[2]
HERE = Path(__file__).resolve(strict=True).parent
SCRIPT = "tools/gcp-guest/outer_image_runner.py"
PACKAGE_SCRIPT = "tools/gcp-guest/package_initrd_runner.py"
SECTOR_SIZE = 512  # Pinned by the reviewed production mkosi.conf.
MUTABLE_STAGE_DIRS = {"output", "work", "package-cache"}
OUTPUT_FILES = {
    "zrpc-gcp.raw", "zrpc-gcp.manifest", "zrpc-gcp.SHA256SUMS",
    "zrpc-gcp.efi", "zrpc-gcp.vmlinuz", "zrpc-gcp.initrd",
    "initrd.cpio.zst", "initrd.manifest",
}
OUTPUT_ALIASES = {"zrpc-gcp": "zrpc-gcp.raw", "initrd": "initrd.cpio.zst"}
# Direct and transitive DT_NEEDED providers of the reviewed Debian sfdisk ELF.
# The signed loader's --list result must contain only these sealed objects.
SFDISK_ELF_PROVIDERS = (
    ("libfdisk.so.1", "libfdisk1"),
    ("libsmartcols.so.1", "libsmartcols1"),
    ("libtinfo.so.6", "libtinfo6"),
    ("libreadline.so.8", "libreadline8t64"),
    ("libuuid.so.1", "libuuid1"),
    ("libblkid.so.1", "libblkid1"),
    ("libc.so.6", "libc6"),
)
ADDITIONAL_SCRIPTS = (
    "tools/gcp-guest/verify-package-closure.py",
    "tools/gcp-guest/inspect_raw_gpt.py",
    "tools/gcp-guest/inspect_raw_esp.py",
    "tools/gcp-guest/inspect_raw_verity.py",
    "tools/gcp-guest/inspect_raw_roothash.py",
    "tools/gcp-guest/stage_sbverify_runtime.py",
    "tools/gcp-guest/verify_zebra_release.py",
    "tools/gcp-guest/gcp_import_archive.py",
    "tools/gcp-guest/inspect_final_initrd.py",
    "tools/gcp-guest/inspect_raw_rootfs.py",
    "tools/gcp-guest/prepare_import_disk.py",
    "tools/gcp-guest/inspect_raw_package_components.py",
    "tools/gcp-guest/inspect_raw_forbidden.py",
    "tools/gcp-guest/inspect_raw_generated_kernel.py",
)
STATIC_SOURCE_FILES = (
    "tools/gcp-guest/audit-rootfs.py",
    "tools/gcp-guest/audit-initrd.py",
    "tools/gcp-guest/seal-shadow.py",
    "tools/gcp-guest/sanitize-mount.py",
    "deploy/gcp/builder-closure.lock.json",
    "deploy/gcp/builder-direct-packages.lock.json",
    "deploy/gcp/zebra-release.lock.json",
)
IDENTITY_FIELDS = {
    "schema_version", "status", "distribution", "release", "architecture",
    "mkosi_source", "downloaded_metadata", "required_local_inputs",
    "artifact_hashes", "reviewed_zebra_provenance_receipt_sha256",
    "measurement_values",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path):
    """Read one unchanged regular file without following its final component."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("required source or artifact is not one regular file")
        data = stream.read()
        after = os.fstat(fd)
    if file_identity(before) != file_identity(after):
        raise ValueError("source or artifact changed during read")
    return data


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def hash_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
            raise ValueError("mkosi output is not one nonempty regular file")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(fd)
    if file_identity(before) != file_identity(after):
        raise ValueError("mkosi output changed during hashing")
    return before.st_size, digest


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate source receipt field")
        result[key] = value
    return result


def checked_package_runner_bytes(revision, rust_bundle, package_path):
    """Read the selected package runner before executing any of its code.

    The outer workflow authenticates the selected Rust receipt before mounting
    it in this no-route builder. This local check binds the first Python code
    we execute to that receipt without importing ambient bytecode or requiring
    Git inside the isolated builder. ReceiptSourceArchive repeats and expands
    these checks after the matched source has been compiled directly.
    """
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("exact selected source commit required")
    report = json.loads(regular_bytes(rust_bundle / "guest-inputs/diagnostic-rust-inputs.json"),
                        object_pairs_hook=unique_object)
    manifest_bytes = regular_bytes(rust_bundle / "manifest.json")
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    if (type(report) is not dict or type(manifest) is not dict
            or report.get("status") != "diagnostic-unsigned-x86_64-rust-inputs-unapproved"
            or report.get("source_commit") != revision
            or manifest.get("source_commit") != revision
            or not isinstance(report.get("source_tree"), str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", report["source_tree"])
            or report.get("source_tree") != manifest.get("source_tree")
            or report.get("reproduction_manifest_sha256") != sha256(manifest_bytes)
            or report.get("image_built") is not False
            or report.get("private_mode_approved") is not False
            or not isinstance(manifest.get("source_archive_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["source_archive_sha256"])):
        raise ValueError("selected package runner lacks a matching Rust receipt")
    archive_bytes = regular_bytes(rust_bundle / "source.tar")
    if sha256(archive_bytes) != manifest["source_archive_sha256"]:
        raise ValueError("selected source archive differs from Rust receipt")
    selected_bytes = None
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive:
            path = member.name.rstrip("/") if member.isdir() else member.name
            if (not re.fullmatch(r"[A-Za-z0-9_./-]+", path)
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                    or (member.name != path and not member.isdir())
                    or path in seen):
                raise ValueError("selected source archive has an unsafe or duplicate member")
            seen.add(path)
            if path == PACKAGE_SCRIPT:
                if not member.isfile():
                    raise ValueError("selected package runner is not a regular source file")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("selected package runner cannot be read")
                selected_bytes = source.read()
    if selected_bytes is None or selected_bytes != regular_bytes(package_path):
        raise ValueError("package initrd runner differs from selected source archive")
    return selected_bytes


def bind_file_module(name, relative, selected, revision):
    """Execute a checked selected-HEAD verifier, not ambient pycache bytes."""
    path = ROOT / relative
    expected = selected.output(["show", f"{revision}:{relative}"])
    if regular_bytes(path) != expected:
        raise ValueError(f"outer verifier differs from selected HEAD: {relative}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(expected, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def checked_source_tree(selected, revision, source):
    """Bind copied production recipe, static locks, and trust roots to HEAD."""
    for relative in (SCRIPT, "tools/gcp-guest/package_initrd_runner.py",
                     *ADDITIONAL_SCRIPTS, *STATIC_SOURCE_FILES):
        if regular_bytes(ROOT / relative) != selected.output(
                ["show", f"{revision}:{relative}"]):
            raise ValueError(f"production source differs from selected HEAD: {relative}")
    for prefix in ("deploy/gcp/guest", "tools/gcp-guest/trust"):
        selected_paths = {name for name in selected.members
                          if name == prefix or name.startswith(prefix + "/")}
        root = ROOT / prefix
        local_paths = {prefix} | {path.relative_to(ROOT).as_posix()
                                  for path in root.rglob("*")}
        if selected_paths != local_paths:
            raise ValueError(f"production source inventory differs from selected HEAD: {prefix}")
        for relative in sorted(local_paths):
            local = ROOT / relative
            member = selected.members[relative]
            if local.is_symlink():
                if not member.issym() or os.readlink(local) != member.linkname:
                    raise ValueError("production source symlink differs from selected HEAD")
            elif local.is_dir():
                if not member.isdir():
                    raise ValueError("production source directory differs from selected HEAD")
            elif not member.isfile() or regular_bytes(local) != selected.output(
                    ["show", f"{revision}:{relative}"]):
                raise ValueError("production source file differs from selected HEAD")
    source.guest.prepare.validate_boot_profile()


def source_context(revision, rust_bundle):
    """Use the native Rust receipt's Git archive as the selected source reader."""
    package_path = HERE / "package_initrd_runner.py"
    package_bytes = checked_package_runner_bytes(revision, rust_bundle, package_path)
    package = types.ModuleType("outer_package_initrd_runner")
    package.__file__ = str(package_path)
    sys.modules[package.__name__] = package
    try:
        exec(compile(package_bytes, str(package_path), "exec"), package.__dict__)
    except BaseException:
        sys.modules.pop(package.__name__, None)
        raise
    selected = package.ReceiptSourceArchive(rust_bundle, revision)
    for relative in (SCRIPT, package.SCRIPT):
        if regular_bytes(ROOT / relative) != selected.output(
                ["show", f"{revision}:{relative}"]):
            raise ValueError(f"outer runner differs from selected HEAD: {relative}")
    package.preflight_rust_receipt(revision, selected, rust_bundle)
    source = package.source_module(revision, selected)
    checked_source_tree(selected, revision, source)
    gpt = bind_file_module("inspect_raw_gpt", ADDITIONAL_SCRIPTS[1], selected, revision)
    esp = bind_file_module("inspect_raw_esp", ADDITIONAL_SCRIPTS[2], selected, revision)
    verity = bind_file_module("inspect_raw_verity", ADDITIONAL_SCRIPTS[3], selected, revision)
    final_initrd = bind_file_module(
        "inspect_final_initrd", ADDITIONAL_SCRIPTS[8], selected, revision)
    forbidden = bind_file_module(
        "inspect_raw_forbidden", ADDITIONAL_SCRIPTS[12], selected, revision)
    bind_file_module("inspect_raw_generated_kernel", ADDITIONAL_SCRIPTS[13],
                     selected, revision)
    package_components = bind_file_module(
        "inspect_raw_package_components", ADDITIONAL_SCRIPTS[11], selected, revision)
    return types.SimpleNamespace(
        selected=selected, source=source, package=package, gpt=gpt, esp=esp,
        verity=verity, package_components=package_components, forbidden=forbidden,
        packages=bind_file_module("outer_package_closure", ADDITIONAL_SCRIPTS[0],
                                  selected, revision),
        roothash=bind_file_module("inspect_raw_roothash", ADDITIONAL_SCRIPTS[4],
                                  selected, revision),
        sbverify=bind_file_module("stage_sbverify_runtime", ADDITIONAL_SCRIPTS[5],
                                  selected, revision),
        zebra=bind_file_module("outer_zebra_release", ADDITIONAL_SCRIPTS[6],
                                selected, revision),
        importer=bind_file_module("outer_gcp_import_archive", ADDITIONAL_SCRIPTS[7],
                                  selected, revision),
        final_initrd=final_initrd,
        rootfs=bind_file_module("outer_raw_rootfs", ADDITIONAL_SCRIPTS[9],
                                selected, revision),
        import_disk=bind_file_module("outer_prepare_import_disk", ADDITIONAL_SCRIPTS[10],
                                     selected, revision),
    )


def diagnostic_verify_uki(stage, builder_archives, workspace, rust_bundle,
                          revision, uki_sha256):
    """Verify a synthetic signed UKI in a fresh selected-source process."""
    context = source_context(revision, rust_bundle)
    manifest = json.loads(regular_bytes(rust_bundle / "manifest.json"),
                          object_pairs_hook=context.source.guest.prepare.unique_object)
    binary = rust_bundle / "artifacts/zrpc-uki-digest"
    if hash_regular(binary)[1] != manifest["artifact_sha256"]["zrpc-uki-digest"]:
        raise ValueError("diagnostic UKI verifier differs from native Rust receipt")
    output = stage / "output"
    files = checked_outputs(output)
    if files["zrpc-gcp.efi"][1] != uki_sha256:
        raise ValueError("signed UKI differs from inspected ESP")
    certificate = stage / "artifacts/secure_boot_certificate"
    certificate_bytes = regular_bytes(certificate)
    with tempfile.TemporaryDirectory(prefix="zrpc-diagnostic-sbverify-",
                                     dir=workspace) as temporary:
        runtime = Path(temporary) / "runtime"
        staged = context.sbverify.stage(builder_archives, runtime)
        if staged["status"] != "diagnostic-sbverify-objects-staged-unapproved":
            raise ValueError("signed sbverify runtime stage differs")
        command = [str(binary), "verify-signature", str(output / "zrpc-gcp.efi"),
                   uki_sha256, str(files["zrpc-gcp.efi"][0]),
                   str(runtime / "sbverify"), str(certificate),
                   sha256(certificate_bytes), str(len(certificate_bytes)),
                   *(str(runtime / name) for name in (
                       "ld-linux-x86-64.so.2", "libc.so.6", "libz.so.1",
                       "libzstd.so.1", "libcrypto.so.3"))]
        result = subprocess.run(command, capture_output=True, check=False,
                                stdin=subprocess.DEVNULL,
                                env={"HOME": "/nonexistent", "LC_ALL": "C",
                                     "PATH": "/usr/bin:/bin"})
        if result.returncode:
            try:
                blocked = json.loads(result.stdout,
                                     object_pairs_hook=context.source.guest.prepare.unique_object)
                reason = blocked.get("reason") if type(blocked) is dict else None
            except (ValueError, UnicodeError, TypeError):
                reason = None
            if (type(reason) is not str or not reason.isascii()
                    or len(reason) > 128 or "\n" in reason or "\r" in reason):
                reason = "no bounded verifier reason"
            raise ValueError("pinned verifier rejected synthetic signed UKI: " + reason)
        signature = json.loads(result.stdout,
                               object_pairs_hook=context.source.guest.prepare.unique_object)
        if (type(signature) is not dict
                or signature.get("status") !=
                    "diagnostic-supplied-signer-signature-verified-unapproved"
                or signature.get("signed_uki_checked") is not True
                or signature.get("uki_sha256") != uki_sha256
                or signature.get("signer_certificate_sha256") != sha256(certificate_bytes)
                or signature.get("private_mode_approved") is not False):
            raise ValueError("reviewed UKI signature report differs from image bytes")
        changed_path = Path(temporary) / "changed-kernel.efi"
        changed_sha256, changed_offset = changed_kernel_uki(
            output, files, changed_path)
        changed_command = command.copy()
        changed_command[2:5] = [str(changed_path), changed_sha256,
                                str(files["zrpc-gcp.efi"][0])]
        changed_result = subprocess.run(
            changed_command, capture_output=True, check=False,
            stdin=subprocess.DEVNULL,
            env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        try:
            rejected = json.loads(changed_result.stdout,
                                  object_pairs_hook=context.source.guest.prepare.unique_object)
        except (ValueError, UnicodeError, TypeError) as error:
            raise ValueError("changed signed kernel has no bounded verifier rejection") from error
        if (changed_result.returncode != 1 or changed_result.stderr
                or type(rejected) is not dict or rejected.get("schema_version") != 2
                or rejected.get("status") != "blocked"
                or rejected.get("reason") !=
                    "UKI Authenticode signature rejected by reviewed sbverify binary"
                or rejected.get("signed_uki_checked") is not False
                or rejected.get("release_approved") is not False
                or rejected.get("private_mode_approved") is not False):
            raise ValueError("changed signed kernel was not rejected by pinned sbverify")
    require_unchanged_outputs(output, files)
    return {"status": "diagnostic-signed-kernel-negative-check-unapproved",
            "signature": signature,
            "source_uki_sha256": uki_sha256,
            "changed_uki_sha256": changed_sha256,
            "changed_kernel_byte_offset": changed_offset,
            "signed_kernel_byte_mutation_rejected": True,
            "private_mode_approved": False}


def changed_kernel_uki(output, files, destination):
    """Change one byte in the exact split .linux payload, never the PE header."""
    uki = regular_bytes(output / "zrpc-gcp.efi")
    kernel = regular_bytes(output / "zrpc-gcp.vmlinuz")
    if (not kernel or len(uki) != files["zrpc-gcp.efi"][0]
            or sha256(uki) != files["zrpc-gcp.efi"][1]
            or len(kernel) != files["zrpc-gcp.vmlinuz"][0]
            or sha256(kernel) != files["zrpc-gcp.vmlinuz"][1]):
        raise ValueError("signed UKI or split kernel changed before negative check")
    start = uki.find(kernel)
    if start < 0 or uki.find(kernel, start + 1) >= 0:
        raise ValueError("signed UKI has no unique exact split kernel payload")
    changed_offset = start + len(kernel) // 2
    changed = bytearray(uki)
    changed[changed_offset] ^= 1
    with destination.open("xb") as stream:
        stream.write(changed)
    changed_sha256 = sha256(changed)
    if changed_sha256 == files["zrpc-gcp.efi"][1]:
        raise ValueError("signed kernel negative check did not change the UKI")
    return changed_sha256, changed_offset


def checked_zebra(context, lock, inputs, receipt_path, now=None):
    """Require eligible pinned ELF bytes and a source-reviewed staging receipt.

    The receipt pin rejects caller-written success fields. It does not
    independently recheck GitHub attestations or current advisories here.
    """
    release, release_sha256 = context.zebra.load_lock()
    prepare = context.source.guest.prepare
    identities = json.loads(regular_bytes(prepare.PROFILE / "input-identities.json"),
                            object_pairs_hook=prepare.unique_object)
    if (type(identities) is not dict or set(identities) != IDENTITY_FIELDS
            or type(identities["schema_version"]) is not int
            or identities["schema_version"] != 1
            or identities["status"] != "incomplete-non-deployable"
            or identities["distribution"] != "debian"
            or identities["release"] != "trixie"
            or identities["architecture"] != "x86_64"):
        raise ValueError("source-reviewed Zebra receipt identity schema differs")
    receipt_pin = identities["reviewed_zebra_provenance_receipt_sha256"]
    if not isinstance(receipt_pin, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_pin):
        raise ValueError("Zebra provenance receipt has no source-reviewed digest")
    asset = release["asset"]
    eligible = context.zebra.utc(asset["created_at"]) + timedelta(
        days=release["minimum_age_days"])
    now = datetime.now(timezone.utc) if now is None else now
    if now < eligible or not release["zebrad_elf_sha256"] or not release["zebrad_elf_size"] \
            or not release["gh_verifier_executable_sha256"]:
        raise ValueError("reviewed Zebra release remains ineligible or incomplete")
    zebra = lock["artifacts"]["zebra"]
    executable = inputs / zebra["path"]
    size, digest = hash_regular(executable)
    if (size, digest) != (release["zebrad_elf_size"], release["zebrad_elf_sha256"]):
        raise ValueError("Zebra input differs from eligible reviewed ELF")
    receipt_bytes = regular_bytes(receipt_path)
    if sha256(receipt_bytes) != receipt_pin:
        raise ValueError("Zebra provenance receipt differs from source-reviewed bytes")
    receipt = json.loads(receipt_bytes, object_pairs_hook=prepare.unique_object)
    if (receipt.get("status") != "staged-diagnostic-unapproved"
            or receipt.get("image_built") is not False
            or receipt.get("private_mode_approved") is not False
            or receipt.get("release_lock_sha256") != release_sha256
            or receipt.get("asset_sha256") != asset["sha256"]
            or receipt.get("zebrad_elf_sha256") != digest
            or receipt.get("zebrad_elf_size") != size
            or receipt.get("gh_verifier_executable_sha256") !=
            release["gh_verifier_executable_sha256"]
            or type(receipt.get("verified_attestation_count")) is not int
            or receipt["verified_attestation_count"] <= 0
            or context.zebra.utc(receipt.get("eligible_at_utc")) != eligible
            or context.zebra.utc(receipt.get("checked_at_utc")) < eligible):
        raise ValueError("Zebra staging consistency receipt differs from reviewed release")
    return {"zebrad_elf_sha256": digest, "zebra_release_lock_sha256": release_sha256,
            "reviewed_zebra_provenance_receipt_sha256": receipt_pin}


def checked_signing_key(certificate, key):
    """Require the fixed private key on a root-owned tmpfs and match its public key."""
    if key != Path("/run/zrpc-build-signing/secure-boot.key"):
        raise ValueError("external signing key reference differs from reviewed path")
    mount = key.parent
    if mount.is_symlink() or not mount.is_dir() or not os.path.ismount(mount):
        raise ValueError("signing key directory is not a private mount")
    mount_info = mount.stat()
    if mount_info.st_uid != 0 or stat.S_IMODE(mount_info.st_mode) & 0o077:
        raise ValueError("signing key mount is not root-owned private storage")
    matches = [line.split(" - ", 1) for line in Path("/proc/self/mountinfo").read_text().splitlines()
               if " - " in line and line.split(" - ", 1)[0].split()[4] == str(mount)]
    if len(matches) != 1 or matches[0][1].split()[0] != "tmpfs":
        raise ValueError("signing key is not supplied from an exact tmpfs mount")
    fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_size <= 0
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("signing key is not a root-owned private regular file")
    finally:
        os.close(fd)
    certificate_bytes = regular_bytes(certificate)
    if not certificate_bytes:
        raise ValueError("staged signing certificate is empty")
    environment = {"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
                   "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": "/nonexistent"}
    commands = (
        ["/usr/bin/openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        ["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout", "-passin", "pass:"],
    )
    public = []
    for command in commands:
        result = subprocess.run(command, capture_output=True, check=False, env=environment,
                                stdin=subprocess.DEVNULL)
        if result.returncode or not result.stdout.startswith(b"-----BEGIN PUBLIC KEY-----\n"):
            raise ValueError("signing certificate or private key cannot be matched")
        public.append(result.stdout)
    if public[0] != public[1]:
        raise ValueError("signing key does not match staged certificate")
    return sha256(certificate_bytes)


def checked_mkosi_recipe(config):
    # Pinned mkosi 25.3 otherwise mounts --directory as its default build
    # source and rejects a workspace beneath it. No finalize script needs
    # /work/src, so the staged recipe must explicitly reset that default.
    if (config.count(b"SectorSize=512\n") != 1
            or b"OutputDirectory=output\n" not in config
            or config.count(b"FinalizeScripts=seal-shadow.py,sanitize-mount.py,audit-rootfs.py\n") != 1
            or config.count(b"\nBuildSources=\n") != 1
            or b"\n[Build]\nBuildSources=\nWorkspaceDirectory=work\nPackageCacheDirectory=package-cache\n" not in config):
        raise ValueError("staged production sector, output, or source layout differs")


def immutable_stage_inventory(stage, manifest):
    """Recheck source inputs while allowing only mkosi's three mutable dirs."""
    expected = manifest["entries"]
    if not isinstance(expected, dict) or not expected:
        raise ValueError("candidate manifest has no immutable inventory")
    cache = expected.get("package-cache")
    if (not isinstance(cache, dict) or set(cache) != {"type", "mode"}
            or cache["type"] != "directory" or type(cache["mode"]) is not int):
        raise ValueError("candidate manifest lacks the reviewed package cache")
    if "output" in expected or "work" in expected:
        raise ValueError("candidate manifest already contains mutable output")
    root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    observed = {}

    def visit(parent_fd, prefix=""):
        with os.scandir(parent_fd) as children:
            for child in children:
                relative = f"{prefix}/{child.name}" if prefix else child.name
                if not prefix and relative in MUTABLE_STAGE_DIRS:
                    info = os.stat(child.name, dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISDIR(info.st_mode) or (relative == "package-cache" and
                            stat.S_IMODE(info.st_mode) != expected[relative]["mode"]):
                        raise ValueError("mkosi mutable directory redirects or changes mode")
                    continue
                if relative == "candidate-manifest.json":
                    continue
                wanted = expected.get(relative)
                if wanted is None:
                    raise ValueError("unexpected source input appeared during mkosi build")
                before = os.stat(child.name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISDIR(before.st_mode):
                    fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
                    try:
                        opened = os.fstat(fd)
                        entry = {"type": "directory", "mode": stat.S_IMODE(opened.st_mode)}
                        if (before.st_dev, before.st_ino, before.st_mode) != \
                                (opened.st_dev, opened.st_ino, opened.st_mode):
                            raise ValueError("staged source directory changed")
                        observed[relative] = entry
                        visit(fd, relative)
                        after = os.fstat(fd)
                        if (opened.st_dev, opened.st_ino, opened.st_mode) != \
                                (after.st_dev, after.st_ino, after.st_mode):
                            raise ValueError("staged source directory changed")
                    finally:
                        os.close(fd)
                elif stat.S_ISLNK(before.st_mode):
                    entry = {"type": "symlink", "target": os.readlink(child.name, dir_fd=parent_fd)}
                    after = os.stat(child.name, dir_fd=parent_fd, follow_symlinks=False)
                    if (before.st_dev, before.st_ino, before.st_ctime_ns) != \
                            (after.st_dev, after.st_ino, after.st_ctime_ns):
                        raise ValueError("staged source symlink changed")
                    observed[relative] = entry
                elif stat.S_ISREG(before.st_mode):
                    fd = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent_fd)
                    with os.fdopen(fd, "rb") as stream:
                        opened = os.fstat(fd)
                        entry = {"type": "file", "sha256": hashlib.file_digest(
                            stream, "sha256").hexdigest(), "mode": stat.S_IMODE(opened.st_mode)}
                        after = os.fstat(fd)
                    if file_identity(opened) != file_identity(after):
                        raise ValueError("staged source file changed")
                    observed[relative] = entry
                else:
                    raise ValueError("unsupported staged source entry appeared")
                if observed[relative] != wanted:
                    raise ValueError("source-bound stage input changed during mkosi build")

    try:
        visit(root_fd)
    finally:
        os.close(root_fd)
    immutable = set(expected) - {"package-cache"}
    if set(observed) != immutable:
        raise ValueError("source-bound stage input disappeared during mkosi build")
    return len(observed)


def checked_outputs(output):
    if output.is_symlink() or not output.is_dir() or \
            set(os.listdir(output)) != OUTPUT_FILES | set(OUTPUT_ALIASES):
        raise ValueError("mkosi production output set differs")
    for name, target in OUTPUT_ALIASES.items():
        alias = output / name
        if not alias.is_symlink() or os.readlink(alias) != target:
            raise ValueError("mkosi output alias differs")
    files = {name: hash_regular(output / name) for name in OUTPUT_FILES}
    checksums = regular_bytes(output / "zrpc-gcp.SHA256SUMS").decode("ascii").splitlines()
    checksummed = {"zrpc-gcp.raw", "zrpc-gcp.efi", "zrpc-gcp.vmlinuz", "zrpc-gcp.initrd"}
    expected = {f"{files[name][1]} *{name}" for name in checksummed}
    if len(checksums) != len(expected) or set(checksums) != expected:
        raise ValueError("mkosi checksum list differs from exact image outputs")
    return files


def require_unchanged_outputs(output, expected):
    if checked_outputs(output) != expected:
        raise ValueError("mkosi outputs changed after inspection")


def checked_split_initrd(cpio, split):
    """Pinned mkosi/ukify joins the supplied CPIO before the module CPIO."""
    fd = os.open(split, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            header = stream.read(cpio.stat().st_size)
        if header != regular_bytes(cpio):
            raise ValueError("signed UKI initrd has an unreviewed prefix or omits the audited CPIO")
    finally:
        os.close(fd)


def selected_initrd_packages(manifest_path, kernel_name):
    """Select the already-verified closure's exact kernel and depmod archives."""
    manifest = json.loads(regular_bytes(manifest_path), object_pairs_hook=unique_object)
    if type(manifest) is not list:
        raise ValueError("reviewed package manifest is not a list")
    selected = {}
    for name in (kernel_name, "kmod", "libkmod2"):
        entries = [item for item in manifest if type(item) is dict and item.get("name") == name]
        if len(entries) != 1:
            raise ValueError("final initrd lacks exact kernel or depmod package")
        selected[name] = entries[0]
    return selected


def inspect_outputs(context, stage, rust_bundle, metadata, builder_archives,
                    workspace, lock, files, manifest):
    output = stage / "output"
    raw = output / "zrpc-gcp.raw"
    raw_bytes, raw_sha256 = files["zrpc-gcp.raw"]
    inrelease = metadata / "InRelease"
    index = metadata / "Packages.xz"
    packages = context.packages.verify(
        stage / "inputs.lock.json", stage / "artifacts/package_manifest",
        output / "zrpc-gcp.manifest", output / "initrd.manifest")
    gpt = context.gpt.inspect(raw, raw_sha256, raw_bytes, SECTOR_SIZE)
    esp = context.esp.inspect(raw, raw_sha256, raw_bytes, SECTOR_SIZE,
                              inrelease, index, builder_archives, workspace)
    verity = context.verity.inspect(raw, raw_sha256, raw_bytes, SECTOR_SIZE,
                                    inrelease, index, builder_archives, workspace)
    if verity.get("one_byte_root_change_rejected") is not True:
        raise ValueError("raw root did not pass the signed verity negative check")
    binding = context.roothash.inspect(gpt, esp, verity, raw_sha256, raw_bytes)
    rootfs = context.rootfs.inspect(raw, raw_sha256, raw_bytes, SECTOR_SIZE,
                                    gpt, verity, inrelease, index, builder_archives,
                                    stage, manifest, workspace)
    if (rootfs.get("status") != context.rootfs.STATUS
            or rootfs.get("raw_disk_sha256") != raw_sha256
            or rootfs.get("raw_disk_bytes") != raw_bytes
            or rootfs.get("root_partition_guid") != verity.get("root_partition_guid")
            or rootfs.get("reader_executable_matches_signed_package") is not True
            or rootfs.get("forbidden_surfaces_checked") is not True
            or type(rootfs.get("raw_root_inventory_entries")) is not int
            or rootfs["raw_root_inventory_entries"] <= 0
            or type(rootfs.get("authenticated_package_components_checked")) is not dict
            or set(rootfs["authenticated_package_components_checked"])
            != {"regular", "directory", "symlink", "removed"}
            or any(type(count) is not int or count < 0 for count in
                   rootfs["authenticated_package_components_checked"].values())
            or rootfs["authenticated_package_components_checked"]["regular"] == 0
            or rootfs.get("private_mode_approved") is not False):
        raise ValueError("raw rootfs workload inspection did not bind output")
    if (files["zrpc-gcp.efi"][1] != esp["uki_sha256"]
            or files["zrpc-gcp.vmlinuz"][1] != esp["uki_sections"][".linux"]["sha256"]
            or files["zrpc-gcp.initrd"][1] != esp["uki_sections"][".initrd"]["sha256"]):
        raise ValueError("split UKI outputs differ from inspected ESP bytes")
    cpio = output / "initrd.cpio.zst"
    audit = stage / "mkosi.images/initrd/audit-initrd.py"
    with tempfile.TemporaryDirectory(prefix="zrpc-outer-audit-", dir=workspace) as temporary:
        copied_audit = Path(temporary) / "audit-initrd.py"
        copied_audit.write_bytes(regular_bytes(audit))
        copied_audit.chmod(0o500)
        cpio_report = context.source.audit_cpio(cpio, copied_audit, workspace,
                                                 sha256(regular_bytes(audit)))
    if (cpio_report["cpio_sha256"] != files["initrd.cpio.zst"][1]
            or cpio_report["cpio_size"] != files["initrd.cpio.zst"][0]):
        raise ValueError("audited initrd CPIO differs from mkosi output")
    checked_split_initrd(cpio, output / "zrpc-gcp.initrd")
    package_entries = selected_initrd_packages(
        stage / "artifacts/package_manifest", context.source.guest.prepare.KERNEL_PACKAGE)
    kernel_entry = package_entries[context.source.guest.prepare.KERNEL_PACKAGE]
    kmod_entry = package_entries["kmod"]
    libkmod_entry = package_entries["libkmod2"]
    with tempfile.TemporaryDirectory(prefix="zrpc-outer-sbverify-", dir=workspace) as temporary:
        runtime = Path(temporary) / "runtime"
        staged = context.sbverify.stage(builder_archives, runtime)
        if staged["status"] != "diagnostic-sbverify-objects-staged-unapproved":
            raise ValueError("signed sbverify runtime staging differs")
        final_initrd = context.final_initrd.inspect(
            files["initrd.cpio.zst"][1], files["initrd.cpio.zst"][0],
            output / "zrpc-gcp.initrd", files["zrpc-gcp.initrd"][1],
            files["zrpc-gcp.initrd"][0],
            stage / "packages" / (kernel_entry["sha256"] + ".deb"), kernel_entry,
            stage / "packages" / (kmod_entry["sha256"] + ".deb"), kmod_entry,
            stage / "packages" / (libkmod_entry["sha256"] + ".deb"), libkmod_entry,
            runtime / "libzstd.so.1", workspace, context.source)
        if (final_initrd.get("status") != context.final_initrd.STATUS
                or final_initrd.get("final_initrd_sha256") != files["zrpc-gcp.initrd"][1]
                or final_initrd.get("final_initrd_bytes") != files["zrpc-gcp.initrd"][0]
                or final_initrd.get("private_mode_approved") is not False):
            raise ValueError("complete final initrd inspection did not bind output")
        binary = rust_bundle / "artifacts/zrpc-uki-digest"
        manifest = json.loads(regular_bytes(rust_bundle / "manifest.json"),
                              object_pairs_hook=context.source.guest.prepare.unique_object)
        if hash_regular(binary)[1] != manifest["artifact_sha256"]["zrpc-uki-digest"]:
            raise ValueError("UKI verifier differs from native Rust receipt")
        certificate = stage / "artifacts/secure_boot_certificate"
        certificate_bytes = regular_bytes(certificate)
        command = [str(binary), "verify-signature", str(output / "zrpc-gcp.efi"),
                   esp["uki_sha256"], str(files["zrpc-gcp.efi"][0]),
                   str(runtime / "sbverify"), str(certificate), sha256(certificate_bytes),
                   str(len(certificate_bytes)),
                   *(str(runtime / name) for name in (
                       "ld-linux-x86-64.so.2", "libc.so.6", "libz.so.1",
                       "libzstd.so.1", "libcrypto.so.3"))]
        result = subprocess.run(command, capture_output=True, check=False,
                                env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        if result.returncode:
            raise ValueError("reviewed UKI signature verifier rejected output")
        signature = json.loads(result.stdout,
                               object_pairs_hook=context.source.guest.prepare.unique_object)
        if (signature.get("status") != "diagnostic-supplied-signer-signature-verified-unapproved"
                or signature.get("signed_uki_checked") is not True
                or signature.get("uki_sha256") != esp["uki_sha256"]
                or signature.get("signer_certificate_sha256") != sha256(certificate_bytes)
                or signature.get("private_mode_approved") is not False):
            raise ValueError("reviewed UKI signature report differs from image bytes")
    require_unchanged_outputs(output, files)
    eligible = (raw_bytes % context.importer.GIB == 0
                and raw_bytes // context.importer.GIB <= context.importer.MAX_IMPORT_GIB)
    return {"raw_disk_sha256": raw_sha256, "raw_disk_bytes": raw_bytes,
            "uki_sha256": esp["uki_sha256"], "roothash": binding["roothash"],
            "root_package_count": packages["root_package_count"],
            "initrd_package_count": packages["initrd_package_count"],
            "root_manifest_sha256": packages["root_manifest_sha256"],
            "initrd_manifest_sha256": packages["initrd_manifest_sha256"],
            "cpio_sha256": cpio_report["cpio_sha256"],
            "final_initrd_audit": final_initrd,
            "raw_rootfs_audit": rootfs,
            "signed_uki_checked": True, "verity_userspace_verified": True,
            "gpt_roothash_matched": True,
            "gcp_import_package_size_eligible": eligible}


def write_diagnostic(path, report):
    if type(report) is not dict or report.get("private_mode_approved") is not False:
        raise ValueError("import diagnostic cannot approve private mode")
    data = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    if regular_bytes(path) != data:
        raise ValueError("written import diagnostic changed")
    return {"path": str(path), "sha256": sha256(data)}


def inspected_uki_digest(context, rust_bundle, output, boot):
    binary = rust_bundle / "artifacts/zrpc-uki-digest"
    manifest = json.loads(regular_bytes(rust_bundle / "manifest.json"),
                          object_pairs_hook=context.source.guest.prepare.unique_object)
    if hash_regular(binary)[1] != manifest["artifact_sha256"]["zrpc-uki-digest"]:
        raise ValueError("UKI digest executable differs from native Rust receipt")
    uki = output / "zrpc-gcp.efi"
    if hash_regular(uki) != (boot["uki_bytes"], boot["uki_sha256"]):
        raise ValueError("import ESP UKI differs from signed mkosi output")
    result = subprocess.run(
        [str(binary), str(uki), boot["uki_sha256"], str(boot["uki_bytes"])],
        capture_output=True, check=False, stdin=subprocess.DEVNULL,
        env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    if result.returncode:
        raise ValueError("reviewed UKI digest executable rejected import UKI")
    report = json.loads(result.stdout,
                        object_pairs_hook=context.source.guest.prepare.unique_object)
    if (report.get("schema_version") != 1
            or report.get("status") != "diagnostic-uki-pe-coff-sha384-unapproved"
            or report.get("uki_sha256") != boot["uki_sha256"]
            or report.get("uki_bytes") != boot["uki_bytes"]
            or report.get("signed_uki_checked") is not False
            or report.get("boot_measurement_checked") is not False
            or report.get("release_approved") is not False
            or report.get("private_mode_approved") is not False):
        raise ValueError("UKI digest report differs from inspected import disk")
    return report


def checked_sfdisk_package(context, metadata, builder_archives, sfdisk):
    """Reconstruct sfdisk and its initial ELF objects from signed builder debs."""
    import debian_snapshot
    import verify_builder_closure as closure

    guest = context.source.guest
    lock_bytes = regular_bytes(closure.LOCK)
    if (len(lock_bytes) != closure.LOCK_BYTES
            or sha256(lock_bytes) != closure.LOCK_SHA256):
        raise ValueError("builder closure lock differs from selected source")
    lock = json.loads(lock_bytes, object_pairs_hook=guest.prepare.unique_object)
    if lock.get("snapshot") != guest.SNAPSHOT:
        raise ValueError("sfdisk package uses another Debian snapshot")
    epoch, (index_hash, index_size), index_bytes = (
        debian_snapshot.authenticated_index_bytes(
            metadata / "InRelease", metadata / "Packages.xz",
            guest.INRELEASE_SHA256))
    if (epoch != guest.SIGNED_RELEASE_EPOCH
            or index_hash != guest.PACKAGES_SHA256
            or index_size != guest.PACKAGES_SIZE):
        raise ValueError("sfdisk package index differs from signed guest snapshot")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    selected = [entry for entry in lock["packages"] if entry["name"] == "fdisk"]
    if (len(selected) != 1
            or selected[0]["sha256"] != context.import_disk.SFDISK_PACKAGE_SHA256):
        raise ValueError("sfdisk package identity differs from builder closure")
    entry = selected[0]
    record = records.get(("fdisk", entry["version"], entry["architecture"]))
    archive = closure.indexed_archive(entry, record, builder_archives, keep_bytes=True)
    executable = None
    with tarfile.open(fileobj=io.BytesIO(closure.deb_data_tar(archive)), mode="r:xz") as members:
        for member in members:
            if member.name not in {"./usr/sbin/sfdisk", "usr/sbin/sfdisk"}:
                continue
            if executable is not None or not member.isfile() or not member.mode & 0o111:
                raise ValueError("signed fdisk archive has no unique executable sfdisk")
            source = members.extractfile(member)
            if source is None:
                raise ValueError("signed sfdisk executable cannot be read")
            executable = source.read()
            if len(executable) != member.size or source.read(1):
                raise ValueError("signed sfdisk executable size differs")
    if (executable is None or not executable.startswith(b"\x7fELF")
            or sha256(executable) != context.import_disk.SFDISK_SHA256
            or hash_regular(sfdisk)[1] != context.import_disk.SFDISK_SHA256):
        raise ValueError("sfdisk executable differs from signed fdisk package")
    needed = {"libc6", *(package for _, package in SFDISK_ELF_PROVIDERS)}
    runtime_entries = {}
    for candidate in lock["packages"]:
        if candidate["name"] in needed:
            if candidate["name"] in runtime_entries:
                raise ValueError("duplicate signed sfdisk runtime provider")
            runtime_entries[candidate["name"]] = candidate
    if set(runtime_entries) != needed:
        raise ValueError("signed sfdisk runtime provider missing")
    runtime_archives = {}
    for name, candidate in runtime_entries.items():
        record = records.get((name, candidate["version"], candidate["architecture"]))
        runtime_archives[name] = closure.indexed_archive(
            candidate, record, builder_archives, keep_bytes=True)
    loader = closure.package_elf(runtime_archives["libc6"], "ld-linux-x86-64.so.2")
    libraries = tuple(
        closure.package_elf(runtime_archives[package], soname)
        for soname, package in SFDISK_ELF_PROVIDERS)
    report = {"sfdisk_sha256": context.import_disk.SFDISK_SHA256,
              "sfdisk_package_archive_sha256": entry["sha256"],
              "sfdisk_archive_membership_rechecked": True,
              "sfdisk_dynamic_runtime_authenticated": False}
    return report, (executable, loader, libraries)


def signed_sfdisk_runtime(runtime, scratch, disk=None):
    """Inspect sealed initial ELF objects, then optionally relocate one GPT.

    This does not establish absence of later dynamic loads or approve an image.
    The caller must separately authenticate the disk and re-inspect its output.
    """
    import verify_builder_closure as closure

    if scratch.is_symlink() or not scratch.is_dir():
        raise ValueError("signed sfdisk scratch directory missing or redirected")
    program_bytes, loader_bytes, libraries = runtime
    with (tempfile.TemporaryDirectory(prefix="zrpc-sfdisk-libs-", dir=scratch) as empty_lib,
          ExitStack() as stack):
        program, program_fd = stack.enter_context(closure.sealed_elf_bytes(program_bytes))
        loader, loader_fd = stack.enter_context(closure.sealed_elf_bytes(loader_bytes))
        preloads = []
        descriptors = [program_fd, loader_fd]
        for data in libraries:
            library, descriptor = stack.enter_context(closure.sealed_elf_bytes(data))
            preloads.append(library)
            descriptors.append(descriptor)
        prefix = [str(loader), "--inhibit-cache", "--preload",
                  ":".join(map(str, preloads)), "--library-path", empty_lib]
        environment = {"LC_ALL": "C", "PATH": empty_lib, "HOME": empty_lib}
        inspected = subprocess.run(
            [*prefix, "--list", str(program)], pass_fds=descriptors,
            env=environment, capture_output=True, text=True, check=False)
        closure.check_loader_report(inspected, loader, preloads)
        if disk is not None:
            result = subprocess.run(
                [*prefix, str(program), "--relocate", "gpt-bak-std", str(disk)],
                pass_fds=descriptors, env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode:
                raise ValueError("signed sfdisk could not relocate the backup GPT")


def reinspect_import(stage, inputs, rust_bundle, revision, metadata, builder_archives,
                     workspace, import_directory, sfdisk, source_sha256,
                     source_bytes, expected_rust_manifest_sha256, zebra_receipt,
                     parent_network_namespace,
                     parent_mount_namespace):
    """Convert one verified mkosi output, then inspect the new disk identity."""
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("native x86_64 Linux import inspection required")
    workspace = Path(workspace).resolve(strict=True)
    import_directory = Path(import_directory)
    stage = Path(stage)
    if (not workspace.is_dir() or not workspace.is_relative_to(ROOT)
            or not stage.is_absolute() or stage.is_symlink()
            or stage.resolve(strict=True) != stage
            or not stage.is_relative_to(ROOT / ".codex-tmp")
            or not import_directory.is_absolute() or import_directory.exists()
            or import_directory.is_symlink()
            or import_directory.parent.resolve(strict=True) != import_directory.parent
            or not import_directory.parent.is_relative_to(workspace)
            or import_directory.is_relative_to(stage)
            or not stage.is_relative_to(ROOT)):
        raise ValueError("fresh import output and source stage must stay on workspace")
    for path in (inputs, rust_bundle, metadata, builder_archives, zebra_receipt):
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or not path.is_relative_to(ROOT)
                or import_directory.is_relative_to(path)):
            raise ValueError("import source inputs must be real disjoint workspace paths")
    if (type(expected_rust_manifest_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", expected_rust_manifest_sha256)
            or sha256(regular_bytes(rust_bundle / "manifest.json")) !=
               expected_rust_manifest_sha256):
        raise ValueError("import Rust bundle differs from original mkosi build")
    context = source_context(revision, rust_bundle)
    prepare = context.source.guest.prepare
    checked_source_tree(context.selected, revision, context.source)
    manifest_bytes = regular_bytes(stage / "candidate-manifest.json")
    manifest_sha256 = sha256(manifest_bytes)
    prepare.verify_stage(stage, manifest_sha256, len(manifest_bytes))
    manifest = json.loads(manifest_bytes, object_pairs_hook=prepare.unique_object)
    count = immutable_stage_inventory(stage, manifest)
    lock = json.loads(regular_bytes(stage / "inputs.lock.json"),
                      object_pairs_hook=prepare.unique_object)
    prepare.validate_lock(lock, inputs)
    rust = context.source.rust_inputs.inspect(
        rust_bundle, revision, selected_output=context.selected.output)
    for role in ("wrapper", "broker", "guard", "cookie", "early_init"):
        if lock["artifacts"][role]["sha256"] != rust["artifacts"][role]["sha256"]:
            raise ValueError("import source guest role differs from native Rust receipt")
    checked_zebra(context, lock, inputs, zebra_receipt)
    namespace = context.package.check_loopback_only_ip_state(
        parent_network_namespace, parent_mount_namespace)
    sfdisk_membership, sfdisk_runtime = checked_sfdisk_package(
        context, metadata, builder_archives, sfdisk)
    signed_sfdisk_runtime(sfdisk_runtime, workspace / ".codex-tmp")
    output = stage / "output"
    files = checked_outputs(output)
    if files["zrpc-gcp.raw"] != (source_bytes, source_sha256):
        raise ValueError("mkosi source disk differs from recorded exact identity")
    original = inspect_outputs(context, stage, rust_bundle, metadata,
                               builder_archives, workspace, lock, files, manifest)
    import_directory.mkdir(mode=0o700)
    raw = import_directory / "disk.raw"
    sizing = context.import_disk._prepare(
        output / "zrpc-gcp.raw", source_sha256, source_bytes, raw, sfdisk,
        gpt_module=context.gpt,
        sfdisk_runner=lambda disk: signed_sfdisk_runtime(
            sfdisk_runtime, import_directory, disk))
    if (sizing.get("status") != "diagnostic-import-sized-gpt-unapproved"
            or sizing.get("mkosi_disk_sha256") != source_sha256
            or sizing.get("mkosi_disk_bytes") != source_bytes
            or sizing.get("sfdisk_sha256") != context.import_disk.SFDISK_SHA256
            or sizing.get("sfdisk_package_archive_sha256") !=
               context.import_disk.SFDISK_PACKAGE_SHA256
            or sfdisk_membership["sfdisk_sha256"] != sizing.get("sfdisk_sha256")
            or sfdisk_membership["sfdisk_package_archive_sha256"] !=
               sizing.get("sfdisk_package_archive_sha256")
            or sfdisk_membership["sfdisk_archive_membership_rechecked"] is not True
            or sfdisk_membership["sfdisk_dynamic_runtime_authenticated"] is not False
            or sizing.get("sfdisk_archive_membership_rechecked") is not False
            or sizing.get("sfdisk_dynamic_runtime_authenticated") is not False
            or sizing.get("import_package_ready") is not False
            or sizing.get("private_mode_approved") is not False):
        raise ValueError("import sizing report differs from verified mkosi output")
    final_sha256 = sizing["raw_disk_sha256"]
    final_bytes = sizing["raw_disk_bytes"]
    args = (raw, final_sha256, final_bytes, SECTOR_SIZE)
    inrelease = metadata / "InRelease"
    index = metadata / "Packages.xz"
    layout = context.gpt.inspect(*args)
    boot = context.esp.inspect(*args, inrelease, index, builder_archives, workspace)
    hashes = context.verity.inspect(*args, inrelease, index, builder_archives, workspace)
    binding = context.roothash.inspect(layout, boot, hashes, final_sha256, final_bytes)
    workload = context.rootfs.inspect(*args, layout, hashes, inrelease, index,
                                      builder_archives, stage, manifest, workspace)
    uki_digest = inspected_uki_digest(context, rust_bundle, output, boot)
    if (layout.get("raw_disk_sha256") != final_sha256
            or layout.get("raw_disk_bytes") != final_bytes
            or boot.get("raw_disk_sha256") != final_sha256
            or boot.get("raw_disk_bytes") != final_bytes
            or hashes.get("raw_disk_sha256") != final_sha256
            or hashes.get("raw_disk_bytes") != final_bytes
            or hashes.get("verity_userspace_verified") is not True
            or workload.get("status") != context.rootfs.STATUS
            or workload.get("raw_disk_sha256") != final_sha256
            or workload.get("raw_disk_bytes") != final_bytes
            or workload.get("root_partition_sha256") !=
               original["raw_rootfs_audit"]["root_partition_sha256"]
            or workload.get("reader_executable_matches_signed_package") is not True
            or workload.get("forbidden_surfaces_checked") is not True
            or workload.get("raw_root_inventory_entries") !=
               original["raw_rootfs_audit"]["raw_root_inventory_entries"]
            or workload.get("authenticated_package_components_checked") !=
               original["raw_rootfs_audit"]["authenticated_package_components_checked"]
            or workload.get("private_mode_approved") is not False
            or boot.get("uki_sha256") != original["uki_sha256"]
            or binding.get("roothash") != original["roothash"]
            or hash_regular(raw) != (final_bytes, final_sha256)):
        raise ValueError("final import disk inspection differs from signed mkosi output")
    checked_source_tree(context.selected, revision, context.source)
    if (immutable_stage_inventory(stage, manifest) != count
            or sha256(regular_bytes(stage / "candidate-manifest.json")) != manifest_sha256
            or context.package.check_loopback_only_ip_state(
                parent_network_namespace, parent_mount_namespace) != namespace):
        raise ValueError("source-bound import inputs or namespace changed")
    require_unchanged_outputs(output, files)
    if sha256(regular_bytes(rust_bundle / "manifest.json")) != expected_rust_manifest_sha256:
        raise ValueError("import Rust bundle changed during reinspection")
    reports = {}
    for name, report in (("sizing", sizing), ("gpt", layout), ("esp", boot),
                         ("verity", hashes), ("roothash", binding),
                         ("rootfs", workload), ("uki-digest", uki_digest)):
        reports[name] = write_diagnostic(import_directory / (name + ".json"), report)
    receipt = {
        "schema_version": 1,
        "status": "diagnostic-import-disk-reinspected-unapproved",
        "source_commit": revision,
        "stage_manifest_sha256": manifest_sha256,
        "input_lock_sha256": manifest["input_lock_sha256"],
        "native_rust_manifest_sha256": expected_rust_manifest_sha256,
        "mkosi_disk_sha256": source_sha256,
        "mkosi_disk_bytes": source_bytes,
        "raw_disk_sha256": final_sha256,
        "raw_disk_bytes": final_bytes,
        **sfdisk_membership,
        "disk_raw": str(raw),
        "reports": reports,
        "package_diagnostics": {
            "esp_diagnostic": reports["esp"],
            "uki_digest_diagnostic": reports["uki-digest"],
            "verity_diagnostic": reports["verity"],
        },
        "import_archive_created": False,
        "import_package_ready": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }
    receipt_artifact = write_diagnostic(import_directory / "reinspection.json", receipt)
    if hash_regular(raw) != (final_bytes, final_sha256):
        raise ValueError("import disk changed after diagnostic publication")
    return {**receipt, "receipt_artifact": receipt_artifact}


def build(lock_path, inputs, zebra_receipt, rust_bundle, revision, stage,
          metadata, builder_archives, workspace,
          parent_network_namespace, parent_mount_namespace):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("native x86_64 Linux builder required")
    workspace = Path(workspace).resolve(strict=True)
    stage = Path(stage)
    build_root = ROOT / ".codex-tmp"
    if (not stage.is_absolute() or stage.exists() or stage.is_symlink()
            or stage.parent.resolve(strict=True) != stage.parent
            or build_root.is_symlink() or not build_root.is_dir()
            or not stage.parent.is_relative_to(build_root)
            or not stage.parent.is_relative_to(workspace)):
        raise ValueError("fresh stage in the real workspace build root required")
    for path in (lock_path, inputs, zebra_receipt, rust_bundle, metadata,
                 builder_archives):
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or not path.is_relative_to(workspace)):
            raise ValueError("outer build inputs must be real workspace paths")
        if stage.is_relative_to(path) or path.is_relative_to(stage):
            raise ValueError("fresh stage must be disjoint from every reviewed input")
    rust_manifest_sha256 = sha256(regular_bytes(rust_bundle / "manifest.json"))
    context = source_context(revision, rust_bundle)
    prepare = context.source.guest.prepare
    lock = json.loads(regular_bytes(lock_path), object_pairs_hook=prepare.unique_object)
    prepare.validate_lock(lock, inputs)
    rust = context.source.rust_inputs.inspect(
        rust_bundle, revision, selected_output=context.selected.output)
    for role in ("wrapper", "broker", "guard", "cookie", "early_init"):
        if lock["artifacts"][role]["sha256"] != rust["artifacts"][role]["sha256"]:
            raise ValueError("guest Rust role differs from selected native receipt")
    zebra = checked_zebra(context, lock, inputs, zebra_receipt)
    key = Path(prepare.EXTERNAL_SECURE_BOOT_KEY)
    certificate_sha256 = checked_signing_key(
        inputs / lock["artifacts"]["secure_boot_certificate"]["path"], key)
    namespace = context.package.check_loopback_only_ip_state(
        parent_network_namespace, parent_mount_namespace)
    builder = context.package.verified_mkosi(context.source, metadata, builder_archives)
    temporary_directory = context.package.checked_mkosi_tmpdir()
    staged = prepare.stage(lock_path, inputs, stage)
    checked_source_tree(context.selected, revision, context.source)
    verified = prepare.verify_stage(stage, staged["manifest_sha256"],
                                    staged["manifest_bytes"])
    if verified["status"] != "staged-inputs-match-pinned-manifest":
        raise ValueError("source-bound production stage verification failed")
    if sha256(regular_bytes(stage / "artifacts/secure_boot_certificate")) != certificate_sha256:
        raise ValueError("staged signing certificate changed")
    if checked_signing_key(stage / "artifacts/secure_boot_certificate", key) != certificate_sha256:
        raise ValueError("signing key changed before mkosi execution")
    config = regular_bytes(stage / "mkosi.conf")
    checked_mkosi_recipe(config)
    manifest = json.loads(regular_bytes(stage / "candidate-manifest.json"),
                          object_pairs_hook=prepare.unique_object)
    if (stage / "output").exists() or (stage / "work").exists() or \
            os.listdir(stage / "package-cache"):
        raise ValueError("fresh mkosi output, work, and cache required")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
                   "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "TMPDIR": temporary_directory}
    result = subprocess.run(["/usr/bin/mkosi", f"--directory={stage}", "build"],
                            env=environment, check=False)
    if result.returncode:
        raise ValueError("pinned mkosi production disk build failed")
    checked_source_tree(context.selected, revision, context.source)
    count = immutable_stage_inventory(stage, manifest)
    if sha256(regular_bytes(stage / "candidate-manifest.json")) != staged["manifest_sha256"]:
        raise ValueError("candidate manifest changed during mkosi build")
    if checked_signing_key(stage / "artifacts/secure_boot_certificate", key) != certificate_sha256:
        raise ValueError("signing key changed during mkosi build")
    files = checked_outputs(stage / "output")
    inspected = inspect_outputs(context, stage, rust_bundle, metadata, builder_archives,
                                workspace, lock, files, manifest)
    if immutable_stage_inventory(stage, manifest) != count or \
            sha256(regular_bytes(stage / "candidate-manifest.json")) != staged["manifest_sha256"] or \
            context.package.check_loopback_only_ip_state(
                parent_network_namespace, parent_mount_namespace) != namespace:
        raise ValueError("source-bound inputs or outer namespace changed during inspection")
    require_unchanged_outputs(stage / "output", files)
    if sha256(regular_bytes(rust_bundle / "manifest.json")) != rust_manifest_sha256:
        raise ValueError("Rust bundle changed during mkosi build or inspection")
    return {"schema_version": 1, "status": "candidate-outer-image-built-unapproved",
            "source_commit": revision,
            "native_rust_manifest_sha256": rust_manifest_sha256,
            "input_lock_sha256": staged["input_lock_sha256"],
            "candidate_manifest_sha256": staged["manifest_sha256"],
            "immutable_stage_entries_checked": count,
            "secure_boot_certificate_sha256": certificate_sha256,
            **zebra, **builder, **inspected, **namespace,
            "zebra_attestation_independently_verified": False,
            "mkosi_executed": True, "image_built": True,
            "boot_verified": False, "private_mode_approved": False}


def main(argv=None):
    if not sys.flags.isolated:
        print(json.dumps({"status": "blocked", "reason": "run with Python -I",
                          "image_built": False, "private_mode_approved": False}))
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("build")
    for name in ("lock", "inputs", "zebra-receipt", "rust-bundle", "stage",
                 "metadata", "builder-archives", "workspace"):
        builder.add_argument("--" + name, type=Path, required=True)
    builder.add_argument("--report-path", type=Path)
    importer = commands.add_parser("reinspect-import")
    for name in ("inputs", "zebra-receipt", "rust-bundle", "stage", "metadata",
                 "builder-archives", "workspace", "import-directory", "sfdisk"):
        importer.add_argument("--" + name, type=Path, required=True)
    importer.add_argument("--mkosi-disk-sha256", required=True)
    importer.add_argument("--mkosi-disk-bytes", type=int, required=True)
    importer.add_argument("--native-rust-manifest-sha256", required=True)
    signature = commands.add_parser("diagnostic-verify-uki")
    for name in ("stage", "builder-archives", "workspace", "rust-bundle"):
        signature.add_argument("--" + name, type=Path, required=True)
    signature.add_argument("--revision", required=True)
    signature.add_argument("--uki-sha256", required=True)
    for command in (builder, importer):
        command.add_argument("--revision", required=True)
        command.add_argument("--parent-network-namespace", required=True)
        command.add_argument("--parent-mount-namespace", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            report = build(args.lock, args.inputs, args.zebra_receipt, args.rust_bundle,
                           args.revision, args.stage, args.metadata, args.builder_archives,
                           args.workspace,
                           args.parent_network_namespace, args.parent_mount_namespace)
            if args.report_path is not None:
                write_diagnostic(args.report_path, report)
        elif args.command == "diagnostic-verify-uki":
            report = diagnostic_verify_uki(
                args.stage, args.builder_archives, args.workspace,
                args.rust_bundle, args.revision, args.uki_sha256)
        else:
            report = reinspect_import(
                args.stage, args.inputs, args.rust_bundle, args.revision, args.metadata,
                args.builder_archives, args.workspace, args.import_directory,
                args.sfdisk, args.mkosi_disk_sha256, args.mkosi_disk_bytes,
                args.native_rust_manifest_sha256,
                args.zebra_receipt, args.parent_network_namespace,
                args.parent_mount_namespace)
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError,
            tarfile.TarError, subprocess.SubprocessError) as error:
        report = {"status": "blocked", "reason": str(error),
                  "image_built": False, "boot_verified": False,
                  "private_mode_approved": False}
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
