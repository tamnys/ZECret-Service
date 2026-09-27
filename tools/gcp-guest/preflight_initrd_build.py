#!/usr/bin/env python3
"""Check local inputs for a diagnostic initrd build without running a builder.

The source-bound BaseTrees archive is checked against signed Debian package
data. A Rust /init is accepted only from a matching, reproducible x86_64
source receipt. This preflight never runs mkosi, package scripts, or network
operations and cannot establish an initrd, boot, or private-mode approval.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import assemble_initrd_base_tree as initrd_input
import export_rust_inputs as rust_inputs
import prepare


FULL_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def preflight(metadata, archives, artifact, rust_bundle=None, revision=None):
    source = initrd_input.verify(metadata, archives, artifact)
    if (source.get("status") != initrd_input.STATUS
            or any(source.get(field) is not False for field in (
                "package_control_scripts_executed", "runtime_closure_verified",
                "initrd_built", "boot_verified", "private_mode_approved"))):
        raise ValueError("source-bound initrd input changed diagnostic state")
    prepare.validate_boot_profile()
    report = {
        "schema_version": 1,
        "status": "blocked",
        "source_bound_archive_sha256": source["archive_sha256"],
        "source_bound_manifest_sha256": source["manifest_sha256"],
        "mkosi_source_commit": prepare.SOURCE_COMMIT,
        "early_init_sha256": None,
        "signed_snapshot_rechecked": True,
        "package_control_scripts_executed": False,
        "network_used_for_build": False,
        "mkosi_executed": False,
        "initrd_built": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }
    if rust_bundle is None or revision is None:
        report["reason"] = "matching reproducible x86_64 /init receipt and exact source revision required"
        return report
    if not FULL_COMMIT.fullmatch(revision):
        raise ValueError("exact full source commit required")
    selected = rust_inputs.git_output(["rev-parse", "HEAD"]).decode().strip()
    if revision != selected:
        raise ValueError("Rust receipt source commit differs from selected source HEAD")
    receipt = rust_inputs.inspect(Path(rust_bundle), revision)
    if (receipt.get("status") != "diagnostic-unsigned-x86_64-rust-inputs-unapproved"
            or receipt.get("image_built") is not False
            or receipt.get("private_mode_approved") is not False):
        raise ValueError("Rust receipt changed diagnostic state")
    early_init = receipt["artifacts"]["early_init"]
    if early_init["path"] != "early_init":
        raise ValueError("Rust receipt early-init role differs")
    binary = rust_inputs.regular_bytes(Path(rust_bundle) / "artifacts/zrpc-gcp-early-init")
    digest = hashlib.sha256(binary).hexdigest()
    if digest != early_init["sha256"] or not rust_inputs.x86_64_elf(binary):
        raise ValueError("early init differs from reproducible x86_64 receipt")
    report["early_init_sha256"] = digest
    report["rust_source_commit"] = revision
    report["rust_receipt_sha256"] = receipt["reproduction_manifest_sha256"]
    report["reason"] = "pinned mkosi CPIO build and post-build audit have not been executed"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--rust-bundle", type=Path)
    parser.add_argument("--revision")
    args = parser.parse_args(argv)
    try:
        report = preflight(args.metadata, args.archives, args.artifact,
                           args.rust_bundle, args.revision)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report = {
            "schema_version": 1, "status": "blocked", "reason": str(error),
            "package_control_scripts_executed": False,
            "network_used_for_build": False, "mkosi_executed": False,
            "initrd_built": False, "boot_verified": False,
            "private_mode_approved": False,
        }
    print(json.dumps(report, sort_keys=True))
    return 1


if __name__ == "__main__":
    sys.exit(main())
