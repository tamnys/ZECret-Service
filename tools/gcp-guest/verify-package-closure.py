#!/usr/bin/env python3
"""Compare supplied mkosi package lists with a staged lock; never approve a release.

The pinned mkosi 25.3 build emits JSON manifests for both the root image and
the initrd. This check does not authenticate the Debian archive, inspect image
bytes, reconstruct measurements, or establish that mkosi produced the files.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import prepare


def read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("package-list input must be a regular file")
        data = stream.read()
    return data, json.loads(data, object_pairs_hook=prepare.unique_object)


def locked_packages(lock, manifest_bytes):
    if (
        not isinstance(lock, dict)
        or set(lock) != {"schema_version", "mkosi_source_commit", "source_date_epoch", "kernel_version", "snapshot", "artifacts", "runtime"}
        or lock["schema_version"] != 5
        or lock["mkosi_source_commit"] != prepare.SOURCE_COMMIT
        or lock["kernel_version"] != prepare.KERNEL_VERSION
        or not isinstance(lock["artifacts"], dict)
        or set(lock["artifacts"]) != prepare.ROLES
    ):
        raise ValueError("unsupported staged input lock")
    identity = lock["artifacts"]["package_manifest"]
    if (
        not isinstance(identity, dict)
        or set(identity) != {"path", "sha256"}
        or not isinstance(identity["sha256"], str)
        or len(identity["sha256"]) != 64
        or any(c not in "0123456789abcdef" for c in identity["sha256"])
        or hashlib.sha256(manifest_bytes).hexdigest() != identity["sha256"]
    ):
        raise ValueError("Debian package list differs from staged lock")
    manifest = json.loads(manifest_bytes, object_pairs_hook=prepare.unique_object)
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("locked Debian package list is empty or malformed")
    packages = {}
    for entry in manifest:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"name", "version", "architecture", "filename", "size", "sha256", "path"}
            or not isinstance(entry["name"], str)
            or not entry["name"]
            or not isinstance(entry["version"], str)
            or not entry["version"]
            or entry["architecture"] not in {"amd64", "all"}
            or entry["name"] in packages
        ):
            raise ValueError("locked Debian package identity is malformed or repeated")
        packages[entry["name"]] = (entry["version"], entry["architecture"])
    if (
        set(packages) & prepare.FORBIDDEN_PACKAGES
        or not prepare.INITRD_PACKAGES <= set(packages)
        or sum(name.startswith("linux-image-") for name in packages) != 1
        or packages.get(prepare.KERNEL_PACKAGE)
        != (prepare.KERNEL_PACKAGE_VERSION, "amd64")
    ):
        raise ValueError("locked Debian package list violates guest package policy")
    return packages


def mkosi_packages(manifest, label):
    if not isinstance(manifest, dict) or set(manifest) != {"manifest_version", "config", "packages"} or manifest["manifest_version"] != 1:
        raise ValueError(f"unsupported {label} mkosi manifest")
    config = manifest["config"]
    if (
        not isinstance(config, dict)
        or not {"name", "distribution", "architecture", "release"} <= set(config)
        or set(config) - {"name", "distribution", "architecture", "release", "version"}
        or not isinstance(config["name"], str)
        or not config["name"]
        or config["distribution"] != "debian"
        or config["architecture"] != "x86-64"
        or config["release"] != "trixie"
        or ("version" in config and not isinstance(config["version"], str))
        or not isinstance(manifest["packages"], list)
        or not manifest["packages"]
    ):
        raise ValueError(f"wrong {label} mkosi distribution or package list")
    packages = {}
    for entry in manifest["packages"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"type", "name", "version", "architecture"}
            or entry["type"] != "deb"
            or not isinstance(entry["name"], str)
            or not entry["name"]
            or not isinstance(entry["version"], str)
            or not entry["version"]
            or entry["architecture"] not in {"amd64", "all"}
            or entry["name"] in packages
        ):
            raise ValueError(f"malformed or repeated {label} mkosi package")
        packages[entry["name"]] = (entry["version"], entry["architecture"])
    return packages


def verify(lock_path, package_manifest_path, root_manifest_path, initrd_manifest_path):
    lock_bytes, lock = read_json(lock_path)
    package_bytes, _ = read_json(package_manifest_path)
    expected = locked_packages(lock, package_bytes)
    root_bytes, root_manifest = read_json(root_manifest_path)
    initrd_bytes, initrd_manifest = read_json(initrd_manifest_path)
    root = mkosi_packages(root_manifest, "root")
    initrd = mkosi_packages(initrd_manifest, "initrd")
    if root != expected:
        raise ValueError("root package closure differs from locked Debian package list")
    if not prepare.INITRD_PACKAGES <= set(initrd):
        raise ValueError("initrd is missing required systemd/verity package seeds")
    if any(expected.get(name) != identity for name, identity in initrd.items()):
        raise ValueError("initrd contains an unlocked package or version")
    return {
        "schema_version": 1,
        "status": "diagnostic_supplied_package_lists_match_only",
        "input_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "package_manifest_sha256": hashlib.sha256(package_bytes).hexdigest(),
        "root_manifest_sha256": hashlib.sha256(root_bytes).hexdigest(),
        "initrd_manifest_sha256": hashlib.sha256(initrd_bytes).hexdigest(),
        "root_package_count": len(root),
        "initrd_package_count": len(initrd),
        "archive_signature_checked_here": False,
        "image_bytes_checked": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--package-manifest", required=True, type=Path)
    parser.add_argument("--root-manifest", required=True, type=Path)
    parser.add_argument("--initrd-manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.lock, args.package_manifest, args.root_manifest, args.initrd_manifest)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "private_mode_approved": False}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
