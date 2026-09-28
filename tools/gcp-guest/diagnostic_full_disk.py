#!/usr/bin/env python3
"""Build and inspect one unsigned, unbootable-by-design synthetic GCP disk.

This rehearses the production mkosi/repart source with only the explicit
``--secure-boot=no`` invocation override. All application executables are
the same deliberately invalid ELF fixture. The output is diagnostic evidence
only: it has no Secure Boot signature, real Zebra, live TDX evidence, or path
into the approved-release catalog. Never import or boot this disk as a service.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

# The native workflow invokes this exact-commit, read-only script with -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fetch_guest_closure as guest
import inspect_raw_esp as esp
import inspect_raw_gpt as gpt
import inspect_raw_rootfs as rootfs
import inspect_raw_roothash as roothash
import inspect_raw_verity as verity
import outer_image_runner as outer
import prepare
import prepare_guest_disk_basetree_profile as builder


_package_spec = importlib.util.spec_from_file_location(
    "diagnostic_verify_package_closure", Path(__file__).with_name("verify-package-closure.py"))
packages = importlib.util.module_from_spec(_package_spec)
_package_spec.loader.exec_module(packages)


STATUS = "diagnostic-unsigned-synthetic-full-disk-unapproved"
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


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_synthetic_inputs(lock, inputs):
    """A caller cannot substitute a real executable or certificate here."""
    if type(lock) is not dict or type(lock.get("artifacts")) is not dict:
        raise ValueError("synthetic input lock is malformed")
    for role in SYNTHETIC_ROLES | {"secure_boot_certificate", "boot_policy"}:
        entry = lock["artifacts"].get(role)
        if type(entry) is not dict or set(entry) != {"path", "sha256"}:
            raise ValueError("synthetic role identity is absent")
        expected = (SYNTHETIC_ELF if role in SYNTHETIC_ROLES else
                    SYNTHETIC_CERTIFICATE if role == "secure_boot_certificate" else
                    SYNTHETIC_BOOT_POLICY)
        path = inputs / entry["path"]
        if outer.regular_bytes(path) != expected or entry["sha256"] != sha256(expected):
            raise ValueError("rehearsal refuses non-synthetic workload or boot input: " + role)
    return sorted(SYNTHETIC_ROLES)


def create_inputs(metadata, guest_archives, inputs, lock_path):
    """Write a fresh, signed-package-backed lock with only invalid guest code."""
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
             "secure_boot_certificate": SYNTHETIC_CERTIFICATE,
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
    # These are the schema's minimum positive values, solely to render dead
    # service units in a disk that has no executable application payload.
    runtime = {name: 1 for name in ("listen_port", "max_connections", "max_quotes",
                                    "quote_spacing_ms", "node_startup_timeout_secs",
                                    "node_poll_interval_ms")}
    lock = {"schema_version": 6, "mkosi_source_commit": prepare.SOURCE_COMMIT,
            "source_date_epoch": guest.SIGNED_RELEASE_EPOCH,
            "kernel_version": prepare.KERNEL_VERSION, "snapshot": guest.SNAPSHOT,
            "artifacts": artifacts, "runtime": runtime}
    checked_synthetic_inputs(lock, inputs)
    prepare.validate_lock(lock, inputs)
    lock_path.write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n")
    return {"status": "diagnostic-synthetic-inputs-staged-unapproved",
            "synthetic_workload": True, "signed_guest_packages_checked": len(manifest),
            "input_lock_sha256": prepare.digest(lock_path),
            "image_built": False, "private_mode_approved": False}


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
            or workload.get("reader_executable_matches_signed_package") is not True
            or workload.get("private_mode_approved") is not False):
        raise ValueError("synthetic workload bytes did not match the raw root")
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
            "synthetic_workload_files_checked": workload["overlay_entries_checked"]["file"],
            "gpt_esp_verity_uki_inspected": True,
            "installed_package_lists_matched": True,
            "complete_initrd_runtime_audited": False}


def build(lock_path, inputs, stage, metadata, guest_archives, builder_archives,
          workspace, apt_scratch, parent_net_ns, parent_user_ns, parent_pid_ns):
    lock = json.loads(outer.regular_bytes(lock_path), object_pairs_hook=prepare.unique_object)
    checked_synthetic_inputs(lock, inputs)
    if stage.exists() or stage.is_symlink() or not workspace.is_dir():
        raise ValueError("fresh rehearsal stage and workspace required")
    execution = builder.verify_execution_context(
        metadata, builder_archives, parent_net_ns, apt_scratch,
        parent_user_ns, parent_pid_ns)
    if execution["status"] != "diagnostic-signed-staged-builder-no-route":
        raise ValueError("no-route signed builder context did not verify")
    guest_receipt = guest.verify_cached_archives(metadata, guest_archives)
    if guest_receipt["signed_snapshot_rechecked"] is not True:
        raise ValueError("guest package signature was not rechecked")
    staged = prepare.stage(lock_path, inputs, stage)
    override = checked_override(stage, staged["manifest_sha256"], staged["manifest_bytes"])
    manifest = json.loads(outer.regular_bytes(stage / "candidate-manifest.json"),
                          object_pairs_hook=prepare.unique_object)
    initial = outer.immutable_stage_inventory(stage, manifest)
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
                   "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "TMPDIR": str(apt_scratch / "tmp")}
    command = ["/usr/bin/mkosi", f"--directory={stage}", override, "build"]
    result = subprocess.run(command, env=environment, check=False)
    if result.returncode:
        raise ValueError("unsigned synthetic mkosi full-disk rehearsal failed")
    if (outer.immutable_stage_inventory(stage, manifest) != initial
            or prepare.digest(stage / "candidate-manifest.json") != staged["manifest_sha256"]):
        raise ValueError("source-bound image inputs changed during rehearsal")
    observed = inspect(stage, metadata, builder_archives, workspace, manifest)
    return {"schema_version": 1, "status": STATUS,
            "production_image": False, "synthetic_workload": True,
            "source_profile_sha256": prepare.digest(prepare.PROFILE / "mkosi.conf"),
            "stage_manifest_sha256": staged["manifest_sha256"],
            "secure_boot_override": override,
            "secure_boot_signature_checked": False,
            "mkosi_executed": True, "diagnostic_disk_built": True,
            **observed, "boot_verified": False, "hardware_verified": False,
            "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-inputs")
    create.add_argument("--metadata", required=True, type=Path)
    create.add_argument("--guest-archives", required=True, type=Path)
    create.add_argument("--inputs", required=True, type=Path)
    create.add_argument("--lock", required=True, type=Path)
    run = sub.add_parser("build")
    for flag in ("lock", "inputs", "stage", "metadata", "guest-archives",
                 "builder-archives", "workspace", "apt-scratch"):
        run.add_argument("--" + flag, required=True, type=Path)
    for flag in ("parent-net-ns", "parent-user-ns", "parent-pid-ns"):
        run.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create-inputs":
            report = create_inputs(args.metadata, args.guest_archives,
                                   args.inputs, args.lock)
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
