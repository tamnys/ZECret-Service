#!/usr/bin/env python3
"""Assemble source-reviewed, unsigned GCP guest inputs without approving them.

The selected commit must pin the exact certificate, boot-policy and runtime
policy bytes in deploy/gcp/guest/input-identities.json's artifact_hashes. A
missing pin blocks assembly. This does not sign, build, deploy or approve an
image, and does not fetch any input.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import outer_image_runner as outer


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "tools/gcp-guest/assemble_production_inputs.py"
IDENTITIES = "deploy/gcp/guest/input-identities.json"
WORKSPACE = Path("/workspace")
REVIEWED_HASHES = {"secure_boot_certificate", "boot_policy", "runtime_policy"}
RUNTIME_FIELDS = {"listen_port", "max_connections", "max_quotes",
                  "quote_spacing_ms", "node_startup_timeout_secs",
                  "node_poll_interval_ms"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise ValueError("nonstandard JSON number: " + value)


def selected_bytes(selected, revision, relative):
    return selected.output(["show", f"{revision}:{relative}"])


def exact_checkout(context, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("exact full selected commit required")
    if context.selected.output(["rev-parse", "HEAD"]).decode().strip() != revision:
        raise ValueError("selected commit differs from checkout HEAD")
    if outer.regular_bytes(ROOT / SCRIPT) != selected_bytes(
            context.selected, revision, SCRIPT):
        raise ValueError("assembler producer differs from selected commit")


def reviewed_hashes(selected, revision):
    identities = json.loads(selected_bytes(selected, revision, IDENTITIES),
                            object_pairs_hook=unique_object,
                            parse_constant=reject_nonfinite)
    if (type(identities) is not dict or set(identities) != outer.IDENTITY_FIELDS
            or identities.get("schema_version") != 1
            or identities.get("status") != "incomplete-non-deployable"):
        raise ValueError("reviewed input identity manifest differs")
    hashes = identities.get("artifact_hashes")
    if (type(hashes) is not dict or set(hashes) != REVIEWED_HASHES
            or any(type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in hashes.values())):
        raise ValueError("certificate, boot-policy and runtime pins are not source-reviewed")
    return hashes


def reviewed_file(selected, revision, path, expected, label):
    if not path.is_absolute():
        raise ValueError(label + " must be an absolute source path")
    if path.resolve(strict=True) != path or not path.is_relative_to(ROOT):
        raise ValueError(label + " must be a real path in the selected checkout")
    relative = path.relative_to(ROOT).as_posix()
    data = outer.regular_bytes(path)
    if not data or data != selected_bytes(selected, revision, relative) or sha256(data) != expected:
        raise ValueError(label + " differs from source-reviewed identity")
    return data


def runtime_policy(data):
    runtime = json.loads(data, object_pairs_hook=unique_object,
                         parse_constant=reject_nonfinite)
    if (type(runtime) is not dict or set(runtime) != RUNTIME_FIELDS
            or any(type(value) is not int or value <= 0 for value in runtime.values())
            or runtime["listen_port"] > 65535):
        raise ValueError("source-reviewed runtime fields are missing or invalid")
    return runtime


def real_directory(path, label):
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.resolve(strict=True) != path):
        raise ValueError(label + " must be a real absolute directory")
    return path


def copy_checked(source, target, expected, size=None):
    if source.is_symlink() or source.resolve(strict=True) != source:
        raise ValueError("artifact source redirects through a symlink")
    with target.open("xb") as output:
        with source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output)
    actual_size, actual_digest = outer.hash_regular(target)
    if actual_digest != expected or (size is not None and actual_size != size):
        raise ValueError("copied input differs from reviewed identity")
    return actual_digest


def assemble(*, revision, rust_bundle, zebra_stage, guest_metadata,
             guest_archives, certificate, boot_policy, runtime_json, output):
    for path, label in ((rust_bundle, "Rust bundle"), (zebra_stage, "Zebra stage"),
                        (guest_metadata, "guest metadata"),
                        (guest_archives, "guest archives")):
        real_directory(path, label)
    if (not output.is_absolute() or not output.is_relative_to(WORKSPACE)
            or output.exists() or output.is_symlink()
            or output.parent.resolve(strict=True) != output.parent):
        raise ValueError("fresh output on the real /workspace volume required")
    context = outer.source_context(revision, rust_bundle)
    exact_checkout(context, revision)
    selected = context.selected
    prepare = context.source.guest.prepare
    guest = context.source.guest
    rust = context.source.rust_inputs
    pins = reviewed_hashes(selected, revision)
    reviewed_file(selected, revision, certificate, pins["secure_boot_certificate"],
                  "certificate")
    reviewed_file(selected, revision, boot_policy, pins["boot_policy"],
                  "boot policy")
    runtime_bytes = reviewed_file(selected, revision, runtime_json,
                                  pins["runtime_policy"], "runtime policy")
    runtime = runtime_policy(runtime_bytes)
    rust_receipt = selected.report
    zebra_receipt = zebra_stage / "receipt.json"
    zebra_checked = outer.checked_zebra(
        context, {"artifacts": {"zebra": {"path": "zebrad"}}}, zebra_stage,
        zebra_receipt)
    guest_checked = guest.verify_cached_archives(guest_metadata, guest_archives)
    if (guest_checked.get("signed_snapshot_rechecked") is not True
            or guest_checked.get("archive_bytes_checked") is not True
            or guest_checked.get("private_mode_approved") is not False):
        raise ValueError("guest archive verification did not complete")
    manifest_bytes, packages = guest.reviewed_manifest()

    output.mkdir(mode=0o700)
    inputs = output / "inputs"
    inputs.mkdir(mode=0o700)
    (inputs / "debs").mkdir(mode=0o700)
    artifacts = {}
    for role, entry in rust_receipt["artifacts"].items():
        if role not in rust.EXPECTED_GUEST_BINARIES or entry["path"] != role:
            raise ValueError("Rust receipt role differs from selected guest profile")
        name = rust.EXPECTED_GUEST_BINARIES[role]
        copy_checked(rust_bundle / "artifacts" / name, inputs / role,
                     entry["sha256"])
        artifacts[role] = {"path": role, "sha256": entry["sha256"]}
    fixed = {
        "zebra": (zebra_stage / "zebrad", zebra_checked["zebrad_elf_sha256"]),
        "secure_boot_certificate": (certificate, pins["secure_boot_certificate"]),
        "boot_policy": (boot_policy, pins["boot_policy"]),
        "package_manifest": (None, sha256(manifest_bytes)),
        "snapshot_inrelease": (guest_metadata / "InRelease", guest.INRELEASE_SHA256),
        "packages_index": (guest_metadata / "Packages.xz", guest.PACKAGES_SHA256),
    }
    for role, (source, digest) in fixed.items():
        if source is None:
            (inputs / role).write_bytes(manifest_bytes)
            if outer.hash_regular(inputs / role)[1] != digest:
                raise ValueError("copied package manifest changed")
        else:
            copy_checked(source, inputs / role, digest)
        artifacts[role] = {"path": role, "sha256": digest}
    for package in packages:
        source = guest_archives / (package["sha256"] + ".deb")
        target = inputs / package["path"]
        copy_checked(source, target, package["sha256"], package["size"])
    for role, package in prepare.DISK_TOOL_PACKAGES.items():
        source = guest_archives / (package["sha256"] + ".deb")
        copy_checked(source, inputs / role, package["sha256"], package["size"])
        artifacts[role] = {"path": role, "sha256": package["sha256"]}
    if set(artifacts) != prepare.ROLES:
        raise ValueError("assembled roles differ from production schema")
    lock = {"schema_version": 6, "mkosi_source_commit": prepare.SOURCE_COMMIT,
            "source_date_epoch": guest.SIGNED_RELEASE_EPOCH,
            "kernel_version": prepare.KERNEL_VERSION, "snapshot": guest.SNAPSHOT,
            "artifacts": artifacts, "runtime": runtime}
    prepare.validate_lock(lock, inputs)
    outer.checked_zebra(context, lock, inputs, zebra_receipt)
    copy_checked(zebra_receipt, output / "zebra-provenance.json",
                 zebra_checked["reviewed_zebra_provenance_receipt_sha256"])
    exact_checkout(context, revision)
    lock_path = output / "inputs.lock.json"
    lock_path.write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n")
    report = {"status": "production-inputs-staged-unbuilt-unapproved",
              "selected_source_commit": revision,
              "input_lock_sha256": outer.hash_regular(lock_path)[1],
              "rust_reproduction_manifest_sha256":
                  rust_receipt["reproduction_manifest_sha256"],
              "zebra_release_lock_sha256":
                  zebra_checked["zebra_release_lock_sha256"],
              "reviewed_zebra_provenance_receipt_sha256":
                  zebra_checked["reviewed_zebra_provenance_receipt_sha256"],
              "signed_guest_package_count": len(packages), "image_built": False,
              "signed": False, "boot_verified": False,
              "hardware_verified": False, "private_mode_approved": False}
    (output / "assembly-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    for option in ("rust-bundle", "zebra-stage", "guest-metadata",
                   "guest-archives", "certificate", "boot-policy",
                   "runtime-json", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    try:
        report = assemble(revision=args.revision, rust_bundle=args.rust_bundle,
                          zebra_stage=args.zebra_stage,
                          guest_metadata=args.guest_metadata,
                          guest_archives=args.guest_archives,
                          certificate=args.certificate,
                          boot_policy=args.boot_policy,
                          runtime_json=args.runtime_json, output=args.output)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
