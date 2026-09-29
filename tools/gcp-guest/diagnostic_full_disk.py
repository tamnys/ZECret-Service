#!/usr/bin/env python3
"""Build and inspect unsigned, non-approving GCP diagnostic disks.

This rehearses the production mkosi/repart source with only the explicit
``--secure-boot=no`` invocation override. The original rehearsal uses invalid
ELF fixtures for every guest executable. The separate boot-input variant uses
only an exact-HEAD, double-built Rust receipt's early init; all service
executables remain invalid. Neither output has a Secure Boot signature, real
Zebra, live TDX evidence, or a path into the approved-release catalog. Never
import or boot either disk as a service.
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


def checked_diagnostic_inputs(lock, inputs, early_init):
    """Only the separately verified early-init role may differ from fixtures."""
    if type(lock) is not dict or type(lock.get("artifacts")) is not dict:
        raise ValueError("synthetic input lock is malformed")
    for role in SYNTHETIC_ROLES | {"secure_boot_certificate", "boot_policy"}:
        entry = lock["artifacts"].get(role)
        if type(entry) is not dict or set(entry) != {"path", "sha256"}:
            raise ValueError("synthetic role identity is absent")
        expected = (early_init if role == prepare.EARLY_INIT_ROLE else
                    SYNTHETIC_ELF if role in SYNTHETIC_ROLES else
                    SYNTHETIC_CERTIFICATE if role == "secure_boot_certificate" else
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


def _create_inputs(metadata, guest_archives, inputs, lock_path, early_init):
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
    checked_diagnostic_inputs(lock, inputs, early_init)
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
            "synthetic_workload_files_checked": workload["overlay_entries_checked"]["file"],
            "gpt_esp_verity_uki_inspected": True,
            "installed_package_lists_matched": True,
            "complete_initrd_runtime_audited": False}


def build(lock_path, inputs, stage, metadata, guest_archives, builder_archives,
          workspace, apt_scratch, parent_net_ns, parent_user_ns, parent_pid_ns,
          *, boot_receipt=None):
    early_init = SYNTHETIC_ELF
    if boot_receipt is not None:
        early_init, receipt_sha256 = checked_boot_receipt(*boot_receipt)
    lock = json.loads(outer.regular_bytes(lock_path), object_pairs_hook=prepare.unique_object)
    checked_diagnostic_inputs(lock, inputs, early_init)
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
    if boot_receipt is not None:
        final_early_init, final_receipt_sha256 = checked_boot_receipt(*boot_receipt)
        if final_early_init != early_init or final_receipt_sha256 != receipt_sha256:
            raise ValueError("native Rust receipt changed during boot disk build")
    report = {"schema_version": 1,
            "status": BOOT_STATUS if boot_receipt is not None else STATUS,
            "production_image": False,
            "synthetic_workload": boot_receipt is None,
            "source_profile_sha256": prepare.digest(prepare.PROFILE / "mkosi.conf"),
            "stage_manifest_sha256": staged["manifest_sha256"],
            "secure_boot_override": override,
            "secure_boot_signature_checked": False,
            "mkosi_executed": True, "diagnostic_disk_built": True,
            **observed, "boot_verified": False, "hardware_verified": False,
            "private_mode_approved": False}
    if boot_receipt is not None:
        report.update({"synthetic_service_payloads": True,
                       "native_early_init_sha256": sha256(early_init),
                       "native_rust_manifest_sha256": receipt_sha256,
                       "source_commit": boot_receipt[1]})
    return report


def build_boot(lock_path, inputs, stage, metadata, guest_archives,
               builder_archives, workspace, apt_scratch, parent_net_ns,
               parent_user_ns, parent_pid_ns, rust_bundle, revision):
    return build(lock_path, inputs, stage, metadata, guest_archives,
                 builder_archives, workspace, apt_scratch, parent_net_ns,
                 parent_user_ns, parent_pid_ns,
                 boot_receipt=(rust_bundle, revision))


def compare_root_rebuilds(first_stage, second_stage):
    """Locate the first changed root byte in two source-identical diagnostics."""
    if first_stage.resolve() == second_stage.resolve():
        raise ValueError("two distinct rehearsal stages required")
    manifest = outer.regular_bytes(first_stage / "candidate-manifest.json")
    if manifest != outer.regular_bytes(second_stage / "candidate-manifest.json"):
        raise ValueError("rebuilds do not have identical staged inputs")
    disks = []
    for stage in (first_stage, second_stage):
        output = stage / "output"
        raw = output / "zrpc-gcp.raw"
        size, expected_sha = outer.checked_outputs(output)["zrpc-gcp.raw"]
        layout = gpt.inspect(raw, expected_sha, size, outer.SECTOR_SIZE)
        root = next(partition for partition in layout["partitions"]
                    if partition["type"] == "root-x86-64")
        disks.append((raw, size, expected_sha, root, layout["sector_size"]))
    first, second = disks
    if (first[3] != second[3] or first[4] != second[4]):
        raise ValueError("rebuild root partition identity or extent differs")
    start = first[3]["first_lba"] * first[4]
    length = (first[3]["last_lba"] - first[3]["first_lba"] + 1) * first[4]
    descriptors = []
    try:
        for raw, size, _, _, _ in disks:
            fd = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                raise ValueError("rebuild disk changed before comparison")
        left_info, right_info = (os.fstat(fd) for fd in descriptors)
        if (left_info.st_dev, left_info.st_ino) == (right_info.st_dev, right_info.st_ino):
            raise ValueError("rebuilds refer to the same disk file")
        first_difference = None
        offset = 0
        while offset < length:
            count = min(1024 * 1024, length - offset)
            left = gpt.read_at(descriptors[0], start + offset, count)
            right = gpt.read_at(descriptors[1], start + offset, count)
            if left != right:
                first_difference = offset + next(index for index, pair in enumerate(zip(left, right))
                                                 if pair[0] != pair[1])
                break
            offset += count
        for fd, (_, size, expected_sha, _, _) in zip(descriptors, disks):
            if os.fstat(fd).st_size != size or gpt.digest(fd, size) != expected_sha:
                raise ValueError("rebuild disk changed during comparison")
    finally:
        for fd in descriptors:
            os.close(fd)
    return {"status": REBUILD_STATUS,
            "source_manifest_sha256": sha256(manifest),
            "root_partition_bytes": length,
            "root_partition_byte_identical": first_difference is None,
            "first_difference_root_offset_bytes": first_difference,
            "first_difference_disk_offset_bytes": None if first_difference is None else start + first_difference,
            "production_image": False, "hardware_verified": False,
            "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("create-inputs", "create-boot-inputs"):
        create = sub.add_parser(name)
        for flag in ("metadata", "guest-archives", "inputs", "lock"):
            create.add_argument("--" + flag, required=True, type=Path)
        if name == "create-boot-inputs":
            create.add_argument("--rust-bundle", required=True, type=Path)
            create.add_argument("--revision", required=True)
    for name in ("build", "build-boot"):
        run = sub.add_parser(name)
        for flag in ("lock", "inputs", "stage", "metadata", "guest-archives",
                     "builder-archives", "workspace", "apt-scratch"):
            run.add_argument("--" + flag, required=True, type=Path)
        for flag in ("parent-net-ns", "parent-user-ns", "parent-pid-ns"):
            run.add_argument("--" + flag, required=True)
        if name == "build-boot":
            run.add_argument("--rust-bundle", required=True, type=Path)
            run.add_argument("--revision", required=True)
    compare = sub.add_parser("compare-roots")
    compare.add_argument("--first-stage", required=True, type=Path)
    compare.add_argument("--second-stage", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "compare-roots":
            report = compare_root_rebuilds(args.first_stage, args.second_stage)
        elif args.command == "create-inputs":
            report = create_inputs(args.metadata, args.guest_archives,
                                   args.inputs, args.lock)
        elif args.command == "create-boot-inputs":
            report = create_boot_inputs(args.metadata, args.guest_archives,
                                        args.inputs, args.lock,
                                        args.rust_bundle, args.revision)
        elif args.command == "build-boot":
            report = build_boot(args.lock, args.inputs, args.stage,
                                args.metadata, args.guest_archives,
                                args.builder_archives, args.workspace,
                                args.apt_scratch, args.parent_net_ns,
                                args.parent_user_ns, args.parent_pid_ns,
                                args.rust_bundle, args.revision)
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
