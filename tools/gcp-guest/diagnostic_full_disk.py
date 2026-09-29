#!/usr/bin/env python3
"""Build and inspect non-approving GCP diagnostic disks.

The unsigned modes rehearse the production mkosi/repart source with only the
explicit ``--secure-boot=no`` invocation override. The original rehearsal
uses invalid ELF fixtures for every guest executable. The boot-input modes
use only an exact-HEAD, double-built Rust receipt's early init; all service
executables remain invalid. The signed mode accepts a throwaway certificate
whose key is held on the builder's private tmpfs and uses the unchanged
production Secure Boot recipe. No mode has real Zebra, live TDX evidence, or
a path into the approved-release catalog. Never import or boot a diagnostic
disk as a service.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

# The native workflow invokes this exact-commit, read-only script with -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fetch_guest_closure as guest
import inspect_raw_esp as esp
import inspect_raw_gpt as gpt
import inspect_raw_rootfs as rootfs
import inspect_raw_roothash as roothash
import inspect_raw_verity as verity
import outer_image_runner as outer
import package_initrd_runner as package_runner
import prepare
import prepare_guest_disk_basetree_profile as builder
import export_rust_inputs as rust_inputs


_package_spec = importlib.util.spec_from_file_location(
    "diagnostic_verify_package_closure", Path(__file__).with_name("verify-package-closure.py"))
packages = importlib.util.module_from_spec(_package_spec)
_package_spec.loader.exec_module(packages)


STATUS = "diagnostic-unsigned-synthetic-full-disk-unapproved"
BOOT_STATUS = "diagnostic-unsigned-early-init-boot-disk-unapproved"
SIGNED_BOOT_STATUS = "diagnostic-signed-synthetic-boot-disk-unapproved"
REBUILD_STATUS = "diagnostic-root-rebuild-comparison-unapproved"
SYNTHETIC_MARKER = b"ZRPC_SYNTHETIC_UNEXECUTABLE_FULL_DISK_REHEARSAL"
# The header satisfies the staging architecture check, but this is not a
# runnable ELF: it has no entry point, program header, or loadable segments.
_synthetic = bytearray(128)
_synthetic[:6] = b"\x7fELF\x02\x01"
_synthetic[18:20] = b"\x3e\x00"
_synthetic[64:64 + len(SYNTHETIC_MARKER)] = SYNTHETIC_MARKER
SYNTHETIC_ELF = bytes(_synthetic)
SYNTHETIC_CERTIFICATE = b"ZRPC_SYNTHETIC_NOT_A_CERTIFICATE\n"
SYNTHETIC_BOOT_POLICY = b"ZRPC_SYNTHETIC_NOT_A_BOOT_POLICY\n"
SYNTHETIC_ROLES = frozenset(prepare.BINARIES) | {prepare.EARLY_INIT_ROLE}
SECURE_BOOT_OVERRIDE = "--secure-boot=no"
SOURCE_REVISION = re.compile(r"[0-9a-f]{40}\Z")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_diagnostic_inputs(lock, inputs, early_init, *, certificate=SYNTHETIC_CERTIFICATE):
    """Only the separately verified early-init role may differ from fixtures."""
    if type(lock) is not dict or type(lock.get("artifacts")) is not dict:
        raise ValueError("synthetic input lock is malformed")
    for role in SYNTHETIC_ROLES | {"secure_boot_certificate", "boot_policy"}:
        entry = lock["artifacts"].get(role)
        if type(entry) is not dict or set(entry) != {"path", "sha256"}:
            raise ValueError("synthetic role identity is absent")
        expected = (early_init if role == prepare.EARLY_INIT_ROLE else
                    SYNTHETIC_ELF if role in SYNTHETIC_ROLES else
                    certificate if role == "secure_boot_certificate" else
                    SYNTHETIC_BOOT_POLICY)
        path = inputs / entry["path"]
        if outer.regular_bytes(path) != expected or entry["sha256"] != sha256(expected):
            raise ValueError("rehearsal refuses non-synthetic workload or boot input: " + role)
    return sorted(SYNTHETIC_ROLES)


def checked_synthetic_inputs(lock, inputs):
    """The original disk mode accepts no real guest executable."""
    return checked_diagnostic_inputs(lock, inputs, SYNTHETIC_ELF)


def selected_boot_source(rust_bundle, revision):
    """Use the receipt's authenticated Git archive; the builder has no Git."""
    package_path = Path(__file__).with_name("package_initrd_runner.py")
    outer.checked_package_runner_bytes(revision, rust_bundle, package_path)
    selected = package_runner.ReceiptSourceArchive(rust_bundle, revision)
    producer = "tools/gcp-guest/diagnostic_full_disk.py"
    if outer.regular_bytes(Path(__file__)) != selected.output(
            ["show", f"{revision}:{producer}"]):
        raise ValueError("boot diagnostic producer differs from exact HEAD")
    return selected


def checked_boot_receipt(rust_bundle, revision):
    """Bind the one runnable guest role to both exact-HEAD native builds."""
    if (not SOURCE_REVISION.fullmatch(revision)
            or not rust_bundle.is_absolute() or rust_bundle.is_symlink()):
        raise ValueError("exact-HEAD native Rust receipt path and revision required")
    selected = selected_boot_source(rust_bundle, revision)
    report = rust_inputs.inspect(rust_bundle, revision,
                                 selected_output=selected.output)
    if report != selected.report:
        raise ValueError("native Rust receipt differs from selected source archive")
    artifacts = report.get("artifacts") if type(report) is dict else None
    early = artifacts.get(prepare.EARLY_INIT_ROLE) if type(artifacts) is dict else None
    manifest_sha256 = report.get("reproduction_manifest_sha256") if type(report) is dict else None
    if (type(report) is not dict
            or report.get("status") != "diagnostic-unsigned-x86_64-rust-inputs-unapproved"
            or report.get("source_commit") != revision
            or report.get("image_built") is not False
            or report.get("private_mode_approved") is not False
            or type(manifest_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)
            or type(early) is not dict
            or early.get("path") != prepare.EARLY_INIT_ROLE
            or type(early.get("sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", early["sha256"])):
        raise ValueError("native Rust receipt cannot supply boot early init")
    binary = rust_inputs.regular_bytes(
        rust_bundle / "artifacts/zrpc-gcp-early-init")
    if (binary == SYNTHETIC_ELF or not rust_inputs.x86_64_elf(binary)
            or sha256(binary) != early["sha256"]):
        raise ValueError("boot early init differs from exact-HEAD native Rust receipt")
    return binary, manifest_sha256


def _create_inputs(metadata, guest_archives, inputs, lock_path, early_init,
                   *, certificate=SYNTHETIC_CERTIFICATE):
    """Write fresh signed-package-backed inputs; callers choose the one init."""
    if inputs.exists() or inputs.is_symlink() or lock_path.exists() or lock_path.is_symlink():
        raise ValueError("synthetic input and lock destinations must be fresh")
    checked = guest.verify_cached_archives(metadata, guest_archives)
    if (checked["status"] != "diagnostic-guest-archives-matched-signed-snapshot-unbuilt"
            or checked["signed_snapshot_rechecked"] is not True
            or checked["private_mode_approved"] is not False):
        raise ValueError("signed guest package cache did not verify")
    package_bytes, manifest = guest.reviewed_manifest()
    inputs.mkdir(mode=0o700)
    (inputs / "debs").mkdir(mode=0o700)
    artifacts = {}
    fixed = {**{role: SYNTHETIC_ELF for role in SYNTHETIC_ROLES},
             prepare.EARLY_INIT_ROLE: early_init,
             "secure_boot_certificate": certificate,
             "boot_policy": SYNTHETIC_BOOT_POLICY,
             "package_manifest": package_bytes,
             "snapshot_inrelease": outer.regular_bytes(metadata / "InRelease"),
             "packages_index": outer.regular_bytes(metadata / "Packages.xz")}
    for role, data in fixed.items():
        path = inputs / role
        path.write_bytes(data)
        artifacts[role] = {"path": role, "sha256": sha256(data)}
    for package in manifest:
        source = guest_archives / (package["sha256"] + ".deb")
        target = inputs / package["path"]
        shutil.copyfile(source, target)
        if target.stat().st_size != package["size"] or prepare.digest(target) != package["sha256"]:
            raise ValueError("copied signed package changed")
    for role, package in prepare.DISK_TOOL_PACKAGES.items():
        source = guest_archives / (package["sha256"] + ".deb")
        target = inputs / role
        shutil.copyfile(source, target)
        if target.stat().st_size != package["size"] or prepare.digest(target) != package["sha256"]:
            raise ValueError("copied signed public-disk tool archive changed: " + role)
        artifacts[role] = {"path": role, "sha256": package["sha256"]}
    # These are the schema's minimum positive values, solely to render dead
    # service units in a disk that has no executable application payload.
    runtime = {name: 1 for name in ("listen_port", "max_connections", "max_quotes",
                                    "quote_spacing_ms", "node_startup_timeout_secs",
                                    "node_poll_interval_ms")}
    lock = {"schema_version": 6, "mkosi_source_commit": prepare.SOURCE_COMMIT,
            "source_date_epoch": guest.SIGNED_RELEASE_EPOCH,
            "kernel_version": prepare.KERNEL_VERSION, "snapshot": guest.SNAPSHOT,
            "artifacts": artifacts, "runtime": runtime}
    checked_diagnostic_inputs(lock, inputs, early_init, certificate=certificate)
    prepare.validate_lock(lock, inputs)
    lock_path.write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n")
    return {"status": "diagnostic-synthetic-inputs-staged-unapproved",
            "synthetic_workload": True, "signed_guest_packages_checked": len(manifest),
            "input_lock_sha256": prepare.digest(lock_path),
            "image_built": False, "private_mode_approved": False}


def create_inputs(metadata, guest_archives, inputs, lock_path):
    """Preserve the original entirely unexecutable synthetic rehearsal."""
    return _create_inputs(metadata, guest_archives, inputs, lock_path, SYNTHETIC_ELF)


def create_boot_inputs(metadata, guest_archives, inputs, lock_path,
                       rust_bundle, revision):
    """Use real early init only; keep every service input unexecutable."""
    early_init, manifest_sha256 = checked_boot_receipt(rust_bundle, revision)
    report = _create_inputs(metadata, guest_archives, inputs, lock_path, early_init)
    report.update({"status": "diagnostic-boot-inputs-staged-unapproved",
                   "synthetic_workload": False,
                   "synthetic_service_payloads": True,
                   "native_early_init_sha256": sha256(early_init),
                   "native_rust_manifest_sha256": manifest_sha256,
                   "source_commit": revision,
                   "boot_verified": False})
    return report


def create_signed_boot_inputs(metadata, guest_archives, inputs, lock_path,
                              rust_bundle, revision, certificate_path):
    """Stage only a signed boot diagnostic with an unexecutable service set."""
    early_init, manifest_sha256 = checked_boot_receipt(rust_bundle, revision)
    certificate = outer.regular_bytes(certificate_path)
    if (certificate == SYNTHETIC_CERTIFICATE
            or not certificate.startswith(b"-----BEGIN CERTIFICATE-----\n")
            or not certificate.endswith(b"-----END CERTIFICATE-----\n")):
        raise ValueError("signed diagnostic requires a PEM certificate")
    if outer.checked_signing_key(certificate_path,
                                 Path(prepare.EXTERNAL_SECURE_BOOT_KEY)) != sha256(certificate):
        raise ValueError("diagnostic certificate changed while matching key")
    report = _create_inputs(metadata, guest_archives, inputs, lock_path,
                            early_init, certificate=certificate)
    if outer.checked_signing_key(inputs / "secure_boot_certificate",
                                 Path(prepare.EXTERNAL_SECURE_BOOT_KEY)) != sha256(certificate):
        raise ValueError("copied diagnostic certificate differs from signing key")
    report.update({"status": "diagnostic-signed-boot-inputs-staged-unapproved",
                   "synthetic_workload": False, "synthetic_service_payloads": True,
                   "native_early_init_sha256": sha256(early_init),
                   "native_rust_manifest_sha256": manifest_sha256,
                   "diagnostic_signer_certificate_sha256": sha256(certificate),
                   "source_commit": revision, "boot_verified": False})
    return report


def checked_override(stage, manifest_sha256, manifest_bytes):
    """Use exact production source bytes and one invocation-only override."""
    verified = prepare.verify_stage(stage, manifest_sha256, manifest_bytes)
    if verified["status"] != "staged-inputs-match-pinned-manifest":
        raise ValueError("production-source stage did not verify")
    config = outer.regular_bytes(stage / "mkosi.conf")
    if (config.count(b"SecureBoot=yes\n") != 1
            or config.count(b"SecureBootKey=" +
                            prepare.EXTERNAL_SECURE_BOOT_KEY.encode() + b"\n") != 1
            or config.count(b"SecureBootCertificate=artifacts/secure_boot_certificate\n") != 1
            or config.count(b"Bootloader=uki\n") != 1
            or config.count(b"RepartDirectories=repart\n") != 1
            or config.count(b"BuildSources=\n") != 1
            or config.count(b"WorkspaceDirectory=work\n") != 1):
        raise ValueError("unsigned override does not derive from the production image recipe")
    return SECURE_BOOT_OVERRIDE


def inspect(stage, metadata, builder_archives, workspace, manifest):
    """Inspect real raw bytes without calling the production signature gate."""
    output = stage / "output"
    files = outer.checked_outputs(output)
    raw_size, raw_sha = files["zrpc-gcp.raw"]
    raw = output / "zrpc-gcp.raw"
    args = (raw, raw_sha, raw_size, outer.SECTOR_SIZE)
    layout = gpt.inspect(*args)
    boot = esp.inspect(*args, metadata / "InRelease", metadata / "Packages.xz",
                       builder_archives, workspace)
    hashes = verity.inspect(*args, metadata / "InRelease", metadata / "Packages.xz",
                            builder_archives, workspace)
    binding = roothash.inspect(layout, boot, hashes, raw_sha, raw_size)
    workload = rootfs.inspect(*args, layout, hashes, metadata / "InRelease",
                              metadata / "Packages.xz", builder_archives,
                              stage, manifest, workspace)
    if (workload.get("status") != rootfs.STATUS
            or workload.get("raw_disk_sha256") != raw_sha
            or workload.get("root_partition_guid") != hashes.get("root_partition_guid")
            or type(workload.get("root_partition_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", workload["root_partition_sha256"])
            or type(hashes.get("verity_partition_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", hashes["verity_partition_sha256"])
            or hashes.get("one_byte_root_change_rejected") is not True
            or workload.get("reader_executable_matches_signed_package") is not True
            or workload.get("private_mode_approved") is not False):
        raise ValueError("synthetic workload bytes did not match the raw root")
    superblock = rootfs.checked_superblock_metadata(workload)
    if (files["zrpc-gcp.efi"][1] != boot["uki_sha256"]
            or files["zrpc-gcp.vmlinuz"][1] != boot["uki_sections"][".linux"]["sha256"]
            or files["zrpc-gcp.initrd"][1] != boot["uki_sections"][".initrd"]["sha256"]):
        raise ValueError("split UKI bytes differ from inspected ESP")
    package_report = packages.verify(stage / "inputs.lock.json",
                                     stage / "artifacts/package_manifest",
                                     output / "zrpc-gcp.manifest",
                                     output / "initrd.manifest")
    if package_report.get("status") != "diagnostic_supplied_package_lists_match_only":
        raise ValueError("installed package lists differ from signed input closure")
    outer.checked_split_initrd(output / "initrd.cpio.zst", output / "zrpc-gcp.initrd")
    outer.require_unchanged_outputs(output, files)
    return {"raw_disk_sha256": raw_sha, "raw_disk_bytes": raw_size,
            "uki_sha256": boot["uki_sha256"], "roothash": binding["roothash"],
            "root_partition_sha256": workload["root_partition_sha256"],
            **superblock,
            "verity_partition_sha256": hashes["verity_partition_sha256"],
            "one_byte_root_change_rejected": True,
            "synthetic_workload_files_checked": workload["overlay_entries_checked"]["file"],
            "gpt_esp_verity_uki_inspected": True,
            "installed_package_lists_matched": True,
            "complete_initrd_runtime_audited": False}


def verify_diagnostic_signature(stage, builder_archives, workspace,
                                rust_bundle, revision, uki_sha256):
    """Use a fresh source-bound process to verify the synthetic signature."""
    output = stage / "output"
    files = outer.checked_outputs(output)
    if files["zrpc-gcp.efi"][1] != uki_sha256:
        raise ValueError("signed UKI differs from inspected ESP")
    certificate = stage / "artifacts/secure_boot_certificate"
    cert_bytes = outer.regular_bytes(certificate)
    command = ["/usr/bin/python3", "-I", "-B", str(outer.ROOT / outer.SCRIPT),
               "diagnostic-verify-uki", "--stage", str(stage),
               "--builder-archives", str(builder_archives),
               "--workspace", str(workspace), "--rust-bundle", str(rust_bundle),
               "--revision", revision, "--uki-sha256", uki_sha256]
    result = subprocess.run(command, capture_output=True, check=False,
                            stdin=subprocess.DEVNULL,
                            env={"HOME": "/nonexistent", "LC_ALL": "C",
                                 "PATH": "/usr/bin:/bin"})
    if result.returncode:
        try:
            blocked = json.loads(result.stdout, object_pairs_hook=prepare.unique_object)
            reason = (blocked.get("reason") if type(blocked) is dict
                      and blocked.get("status") == "blocked"
                      and blocked.get("private_mode_approved") is False else None)
        except (ValueError, UnicodeError, TypeError):
            reason = None
        if (type(reason) is not str or not reason.isascii()
                or not reason.isprintable() or len(reason) > 128):
            reason = "no bounded verifier reason"
        raise ValueError("pinned verifier rejected synthetic signed UKI: " + reason)
    evidence = json.loads(result.stdout, object_pairs_hook=prepare.unique_object)
    signature = evidence.get("signature") if type(evidence) is dict else None
    changed_hash = evidence.get("changed_uki_sha256") if type(evidence) is dict else None
    changed_offset = evidence.get("changed_kernel_byte_offset") if type(evidence) is dict else None
    if (type(evidence) is not dict
            or evidence.get("status") != "diagnostic-signed-kernel-negative-check-unapproved"
            or evidence.get("source_uki_sha256") != uki_sha256
            or type(changed_hash) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", changed_hash)
            or changed_hash == uki_sha256
            or type(changed_offset) is not int
            or not 0 <= changed_offset < files["zrpc-gcp.efi"][0]
            or evidence.get("signed_kernel_byte_mutation_rejected") is not True
            or evidence.get("private_mode_approved") is not False
            or type(signature) is not dict
            or signature.get("status") !=
                "diagnostic-supplied-signer-signature-verified-unapproved"
            or signature.get("signed_uki_checked") is not True
            or signature.get("uki_sha256") != uki_sha256
            or signature.get("signer_certificate_sha256") != sha256(cert_bytes)
            or signature.get("private_mode_approved") is not False):
        raise ValueError("synthetic signed UKI verification report differs")
    outer.require_unchanged_outputs(output, files)
    return evidence


def build(lock_path, inputs, stage, metadata, guest_archives, builder_archives,
          workspace, apt_scratch, parent_net_ns, parent_user_ns, parent_pid_ns,
          *, boot_receipt=None, signed_boot=False):
    if signed_boot and boot_receipt is None:
        raise ValueError("signed diagnostic requires exact native boot receipt")
    early_init = SYNTHETIC_ELF
    if boot_receipt is not None:
        early_init, receipt_sha256 = checked_boot_receipt(*boot_receipt)
    lock = json.loads(outer.regular_bytes(lock_path), object_pairs_hook=prepare.unique_object)
    certificate = (outer.regular_bytes(inputs / "secure_boot_certificate")
                   if signed_boot else SYNTHETIC_CERTIFICATE)
    checked_diagnostic_inputs(lock, inputs, early_init, certificate=certificate)
    certificate_sha256 = None
    if signed_boot:
        certificate_sha256 = outer.checked_signing_key(
            inputs / "secure_boot_certificate",
            Path(prepare.EXTERNAL_SECURE_BOOT_KEY))
        if certificate_sha256 != sha256(certificate):
            raise ValueError("diagnostic signer changed before staging")
    if stage.exists() or stage.is_symlink() or not workspace.is_dir():
        raise ValueError("fresh rehearsal stage and workspace required")
    execution = builder.verify_execution_context(
        metadata, builder_archives, parent_net_ns, apt_scratch,
        parent_user_ns, parent_pid_ns,
        external_signing_mount=signed_boot)
    if execution["status"] != "diagnostic-signed-staged-builder-no-route":
        raise ValueError("no-route signed builder context did not verify")
    guest_receipt = guest.verify_cached_archives(metadata, guest_archives)
    if guest_receipt["signed_snapshot_rechecked"] is not True:
        raise ValueError("guest package signature was not rechecked")
    staged = prepare.stage(lock_path, inputs, stage)
    override = checked_override(stage, staged["manifest_sha256"], staged["manifest_bytes"])
    if signed_boot and outer.checked_signing_key(
            stage / "artifacts/secure_boot_certificate",
            Path(prepare.EXTERNAL_SECURE_BOOT_KEY)) != certificate_sha256:
        raise ValueError("diagnostic signer changed before mkosi")
    manifest = json.loads(outer.regular_bytes(stage / "candidate-manifest.json"),
                          object_pairs_hook=prepare.unique_object)
    initial = outer.immutable_stage_inventory(stage, manifest)
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
                   "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "TMPDIR": str(apt_scratch / "tmp")}
    command = ["/usr/bin/mkosi", f"--directory={stage}"]
    if not signed_boot:
        command.append(override)
    command.append("build")
    result = subprocess.run(command, env=environment, check=False)
    if result.returncode:
        raise ValueError("synthetic mkosi full-disk rehearsal failed")
    if (outer.immutable_stage_inventory(stage, manifest) != initial
            or prepare.digest(stage / "candidate-manifest.json") != staged["manifest_sha256"]):
        raise ValueError("source-bound image inputs changed during rehearsal")
    observed = inspect(stage, metadata, builder_archives, workspace, manifest)
    signature_evidence = None
    if signed_boot:
        if outer.checked_signing_key(
                stage / "artifacts/secure_boot_certificate",
                Path(prepare.EXTERNAL_SECURE_BOOT_KEY)) != certificate_sha256:
            raise ValueError("diagnostic signer changed during mkosi build")
        signature_evidence = verify_diagnostic_signature(
            stage, builder_archives, workspace, boot_receipt[0],
            boot_receipt[1], observed["uki_sha256"])
    if boot_receipt is not None:
        final_early_init, final_receipt_sha256 = checked_boot_receipt(*boot_receipt)
        if final_early_init != early_init or final_receipt_sha256 != receipt_sha256:
            raise ValueError("native Rust receipt changed during boot disk build")
    report = {"schema_version": 1,
            "status": SIGNED_BOOT_STATUS if signed_boot else
                      BOOT_STATUS if boot_receipt is not None else STATUS,
            "production_image": False,
            "synthetic_workload": boot_receipt is None,
            "source_profile_sha256": prepare.digest(prepare.PROFILE / "mkosi.conf"),
            "stage_manifest_sha256": staged["manifest_sha256"],
            "secure_boot_override": None if signed_boot else override,
            "secure_boot_signature_checked": signature_evidence is not None,
            "mkosi_executed": True, "diagnostic_disk_built": True,
            **observed, "boot_verified": False, "hardware_verified": False,
            "private_mode_approved": False}
    if boot_receipt is not None:
        report.update({"synthetic_service_payloads": True,
                       "native_early_init_sha256": sha256(early_init),
                       "native_rust_manifest_sha256": receipt_sha256,
                       "source_commit": boot_receipt[1]})
    if signed_boot:
        report.update({"diagnostic_signer_certificate_sha256": certificate_sha256,
                       "synthetic_signature_report": signature_evidence["signature"],
                       "signed_kernel_byte_mutation_rejected":
                           signature_evidence["signed_kernel_byte_mutation_rejected"],
                       "changed_kernel_uki_sha256":
                           signature_evidence["changed_uki_sha256"]})
    return report


def build_boot(lock_path, inputs, stage, metadata, guest_archives,
               builder_archives, workspace, apt_scratch, parent_net_ns,
               parent_user_ns, parent_pid_ns, rust_bundle, revision):
    return build(lock_path, inputs, stage, metadata, guest_archives,
                 builder_archives, workspace, apt_scratch, parent_net_ns,
                 parent_user_ns, parent_pid_ns,
                 boot_receipt=(rust_bundle, revision))


def build_signed_boot(lock_path, inputs, stage, metadata, guest_archives,
                      builder_archives, workspace, apt_scratch, parent_net_ns,
                      parent_user_ns, parent_pid_ns, rust_bundle, revision):
    return build(lock_path, inputs, stage, metadata, guest_archives,
                 builder_archives, workspace, apt_scratch, parent_net_ns,
                 parent_user_ns, parent_pid_ns,
                 boot_receipt=(rust_bundle, revision), signed_boot=True)


def debugfs_output(reader, image, command, descriptor):
    result = subprocess.run([str(reader), "-R", command, str(image)],
                            stdin=subprocess.DEVNULL, capture_output=True,
                            env=rootfs.SUPER_ENV, pass_fds=(descriptor,), check=False)
    if result.returncode or result.stderr != rootfs.READER_BANNER:
        raise ValueError("signed debugfs block ownership query failed")
    try:
        return result.stdout.decode("ascii")
    except UnicodeError as error:
        raise ValueError("signed debugfs block ownership report is malformed") from error


def describe_changed_block(reader, image, byte_offset, descriptor):
    stats = debugfs_output(reader, image, "stats -h", descriptor)
    sizes = re.findall(r"(?m)^Block size:\s+([1-9][0-9]*)$", stats)
    if sizes != ["4096"]:
        raise ValueError("root ext4 block size differs from pinned mkfs recipe")
    block = byte_offset // 4096
    lines = debugfs_output(reader, image, f"icheck {block}", descriptor).splitlines()
    if len(lines) != 2 or lines[0] != "Block\tInode number":
        raise ValueError("signed debugfs block owner report is malformed")
    row = lines[1].split("\t")
    if len(row) != 2 or row[0] != str(block):
        raise ValueError("signed debugfs block owner report is malformed")
    if row[1] == "<block not found>":
        inode = None
        paths = []
    elif re.fullmatch(r"[1-9][0-9]*", row[1]):
        inode = int(row[1])
        names = debugfs_output(reader, image, f"ncheck {inode}", descriptor).splitlines()
        if not names or names[0] != "Inode\tPathname":
            raise ValueError("signed debugfs inode path report is malformed")
        paths = []
        for line in names[1:]:
            prefix = str(inode) + "\t"
            if not line.startswith(prefix) or not line[len(prefix):].startswith("/"):
                raise ValueError("signed debugfs inode path report is malformed")
            paths.append(line[len(prefix):])
    else:
        raise ValueError("signed debugfs block owner report is malformed")
    return {"block_size": 4096, "block": block, "inode": inode,
            "paths": paths, "byte_offset_in_block": byte_offset % 4096}


def signed_block_owners(disks, byte_offset, metadata, builder_archives, workspace):
    workspace = verity.esp.workspace_scratch(workspace)
    signed_reader, _ = rootfs.signed_reader_bytes(
        metadata / "InRelease", metadata / "Packages.xz", builder_archives)
    rootfs.checked_reader(signed_reader)
    with tempfile.TemporaryDirectory(prefix="zrpc-root-rebuild-", dir=workspace) as temporary:
        scratch = Path(temporary)
        images = []
        for index, (raw, size, expected_sha, _, sector_size, layout) in enumerate(disks):
            target = scratch / str(index)
            target.mkdir()
            partitions = verity.partition_images(raw, layout, expected_sha,
                                                  size, sector_size, target)
            images.append(partitions["root-x86-64"][0])
        with verity.closure.sealed_elf_bytes(signed_reader) as (reader, descriptor):
            return [describe_changed_block(reader, image, byte_offset, descriptor)
                    for image in images]


def first_changed_bytes(left, right, left_start, right_start, overlap):
    offset = 0
    while offset < overlap:
        count = min(1024 * 1024, overlap - offset)
        first = gpt.read_at(left, left_start + offset, count)
        second = gpt.read_at(right, right_start + offset, count)
        if first != second:
            return offset + next(index for index, pair in enumerate(zip(first, second))
                                 if pair[0] != pair[1])
        offset += count
    return None


def disk_region(layout, offset):
    for partition in layout["partitions"]:
        start = partition["first_lba"] * layout["sector_size"]
        end = (partition["last_lba"] + 1) * layout["sector_size"]
        if start <= offset < end:
            return partition["type"]
    return "outside-partitions"


def compare_material_outputs(outputs):
    """Distinguish a changed UKI input from changed PE/FAT packaging."""
    compared = {}
    for name in ("initrd.cpio.zst", "zrpc-gcp.vmlinuz", "zrpc-gcp.initrd",
                 "zrpc-gcp.efi"):
        identities = [files[name] for _, files in outputs]
        descriptors = []
        try:
            for (directory, _), (size, _) in zip(outputs, identities):
                fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                descriptors.append(fd)
                record = os.fstat(fd)
                if not stat.S_ISREG(record.st_mode) or record.st_size != size:
                    raise ValueError("rebuild output changed before comparison")
            left, right = (os.fstat(fd) for fd in descriptors)
            if (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino):
                raise ValueError("rebuilds refer to the same material output")
            first_difference = None
            if identities[0] != identities[1]:
                first_difference = first_changed_bytes(
                    descriptors[0], descriptors[1], 0, 0,
                    min(identities[0][0], identities[1][0]))
                if first_difference is None and identities[0][0] == identities[1][0]:
                    raise ValueError("different material hashes lack a changed byte")
            for fd, (size, expected_sha) in zip(descriptors, identities):
                if os.fstat(fd).st_size != size or gpt.digest(fd, size) != expected_sha:
                    raise ValueError("rebuild output changed during comparison")
        finally:
            for fd in descriptors:
                os.close(fd)
        compared[name] = {
            "first_sha256": identities[0][1], "second_sha256": identities[1][1],
            "first_bytes": identities[0][0], "second_bytes": identities[1][0],
            "byte_identical": identities[0] == identities[1],
            "first_difference_kind": "byte" if first_difference is not None else
                                     "length" if identities[0][0] != identities[1][0] else None,
            "first_difference_offset_bytes": first_difference,
        }
    return compared


def compare_root_rebuilds(first_stage, second_stage, *, metadata=None,
                          builder_archives=None, workspace=None):
    """Locate root and whole-disk differences in two source-identical diagnostics."""
    if first_stage.resolve() == second_stage.resolve():
        raise ValueError("two distinct rehearsal stages required")
    manifest = outer.regular_bytes(first_stage / "candidate-manifest.json")
    if manifest != outer.regular_bytes(second_stage / "candidate-manifest.json"):
        raise ValueError("rebuilds do not have identical staged inputs")
    disks = []
    outputs = []
    for stage in (first_stage, second_stage):
        output = stage / "output"
        raw = output / "zrpc-gcp.raw"
        files = outer.checked_outputs(output)
        outputs.append((output, files))
        size, expected_sha = files["zrpc-gcp.raw"]
        layout = gpt.inspect(raw, expected_sha, size, outer.SECTOR_SIZE)
        root = next(partition for partition in layout["partitions"]
                    if partition["type"] == "root-x86-64")
        disks.append((raw, size, expected_sha, root, layout["sector_size"], layout))
    first, second = disks
    if first[4] != second[4]:
        raise ValueError("rebuild disk sector sizes differ")
    starts = [item[3]["first_lba"] * item[4] for item in disks]
    lengths = [(item[3]["last_lba"] - item[3]["first_lba"] + 1) * item[4]
               for item in disks]
    overlap = min(lengths)
    descriptors = []
    try:
        for raw, size, _, _, _, _ in disks:
            fd = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                raise ValueError("rebuild disk changed before comparison")
        left_info, right_info = (os.fstat(fd) for fd in descriptors)
        if (left_info.st_dev, left_info.st_ino) == (right_info.st_dev, right_info.st_ino):
            raise ValueError("rebuilds refer to the same disk file")
        first_difference = first_changed_bytes(descriptors[0], descriptors[1],
                                               starts[0], starts[1], overlap)
        disk_difference = None
        if first[1] != second[1] or first[2] != second[2]:
            disk_difference = first_changed_bytes(descriptors[0], descriptors[1],
                                                  0, 0, min(first[1], second[1]))
            if disk_difference is None and first[1] == second[1]:
                raise ValueError("different raw disk hashes lack a changed byte")
        for fd, (_, size, expected_sha, _, _, _) in zip(descriptors, disks):
            if os.fstat(fd).st_size != size or gpt.digest(fd, size) != expected_sha:
                raise ValueError("rebuild disk changed during comparison")
    finally:
        for fd in descriptors:
            os.close(fd)
    owners = None
    if metadata is not None or builder_archives is not None or workspace is not None:
        if metadata is None or builder_archives is None or workspace is None:
            raise ValueError("complete signed block-owner inputs required")
        if first_difference is not None:
            owners = signed_block_owners(disks, first_difference, metadata,
                                         builder_archives, workspace)
    material_outputs = compare_material_outputs(outputs)
    return {"status": REBUILD_STATUS,
            "source_manifest_sha256": sha256(manifest),
            "material_outputs": material_outputs,
            "first_disk_sha256": first[2], "second_disk_sha256": second[2],
            "first_disk_bytes": first[1], "second_disk_bytes": second[1],
            "disk_byte_identical": first[1] == second[1] and first[2] == second[2],
            "first_disk_difference_kind": "byte" if disk_difference is not None else
                                          "length" if first[1] != second[1] else None,
            "first_disk_difference_offset_bytes": disk_difference,
            "first_disk_difference_regions": None if disk_difference is None else {
                "first": disk_region(first[5], disk_difference),
                "second": disk_region(second[5], disk_difference)},
            "first_root_partition": first[3],
            "second_root_partition": second[3],
            "root_partition_layout_identical": first[3] == second[3],
            "first_root_partition_bytes": lengths[0],
            "second_root_partition_bytes": lengths[1],
            "root_partition_byte_identical": first_difference is None and lengths[0] == lengths[1],
            "first_difference_kind": "byte" if first_difference is not None else
                                     "length" if lengths[0] != lengths[1] else None,
            "first_difference_root_offset_bytes": first_difference,
            "first_difference_first_disk_offset_bytes": None if first_difference is None else starts[0] + first_difference,
            "first_difference_second_disk_offset_bytes": None if first_difference is None else starts[1] + first_difference,
            "first_changed_block_owners": owners,
            "production_image": False, "hardware_verified": False,
            "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("create-inputs", "create-boot-inputs",
                 "create-signed-boot-inputs"):
        create = sub.add_parser(name)
        for flag in ("metadata", "guest-archives", "inputs", "lock"):
            create.add_argument("--" + flag, required=True, type=Path)
        if name != "create-inputs":
            create.add_argument("--rust-bundle", required=True, type=Path)
            create.add_argument("--revision", required=True)
        if name == "create-signed-boot-inputs":
            create.add_argument("--certificate", required=True, type=Path)
    for name in ("build", "build-boot", "build-signed-boot"):
        run = sub.add_parser(name)
        for flag in ("lock", "inputs", "stage", "metadata", "guest-archives",
                     "builder-archives", "workspace", "apt-scratch"):
            run.add_argument("--" + flag, required=True, type=Path)
        for flag in ("parent-net-ns", "parent-user-ns", "parent-pid-ns"):
            run.add_argument("--" + flag, required=True)
        if name != "build":
            run.add_argument("--rust-bundle", required=True, type=Path)
            run.add_argument("--revision", required=True)
    compare = sub.add_parser("compare-roots")
    compare.add_argument("--first-stage", required=True, type=Path)
    compare.add_argument("--second-stage", required=True, type=Path)
    compare.add_argument("--metadata", required=True, type=Path)
    compare.add_argument("--builder-archives", required=True, type=Path)
    compare.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "compare-roots":
            report = compare_root_rebuilds(
                args.first_stage, args.second_stage, metadata=args.metadata,
                builder_archives=args.builder_archives, workspace=args.workspace)
        elif args.command == "create-inputs":
            report = create_inputs(args.metadata, args.guest_archives,
                                   args.inputs, args.lock)
        elif args.command == "create-boot-inputs":
            report = create_boot_inputs(args.metadata, args.guest_archives,
                                        args.inputs, args.lock,
                                        args.rust_bundle, args.revision)
        elif args.command == "create-signed-boot-inputs":
            report = create_signed_boot_inputs(
                args.metadata, args.guest_archives, args.inputs, args.lock,
                args.rust_bundle, args.revision, args.certificate)
        elif args.command == "build-boot":
            report = build_boot(args.lock, args.inputs, args.stage,
                                args.metadata, args.guest_archives,
                                args.builder_archives, args.workspace,
                                args.apt_scratch, args.parent_net_ns,
                                args.parent_user_ns, args.parent_pid_ns,
                                      args.rust_bundle, args.revision)
        elif args.command == "build-signed-boot":
            report = build_signed_boot(
                args.lock, args.inputs, args.stage, args.metadata,
                args.guest_archives, args.builder_archives, args.workspace,
                args.apt_scratch, args.parent_net_ns, args.parent_user_ns,
                args.parent_pid_ns, args.rust_bundle, args.revision)
        else:
            report = build(args.lock, args.inputs, args.stage, args.metadata,
                           args.guest_archives, args.builder_archives,
                           args.workspace, args.apt_scratch,
                           args.parent_net_ns, args.parent_user_ns,
                           args.parent_pid_ns)
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        report = {"status": "blocked", "reason": str(error),
                  "production_image": False, "private_mode_approved": False}
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
