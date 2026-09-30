#!/usr/bin/env python3
"""Stage an unbuilt paid rootfs overlay from one pinned free GCP stage.

This produces reviewable image inputs, not an image or private-mode approval.
The issuer private key and spent database are never accepted as inputs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

import prepare
import export_rust_inputs


ROOT = prepare.ROOT
STATUS = "paid-overlay-staged-unbuilt-unapproved"
FILES = {
    "issuer_public_der": "issuer.der",
    "crypto_helper": "zrpc-payment-crypto",
}
UNIT_DIR = Path("usr/lib/systemd/system")
GUARDED_UNITS = {
    "zrpc-node.service": "zebra",
    "zrpc-gcp-quote.service": "broker",
    "zrpc-cookie.service": "cookie",
    "zrpc-wrapper.service": "wrapper",
}
PAID_ROOTFS_FILES = frozenset({
    "etc/fstab", "usr/lib/udev/rules.d/65-gce-disk-naming.rules",
    "usr/lib/tmpfiles.d/zrpc.conf", "etc/zrpc/issuer.der",
    "usr/lib/zrpc/zrpc-payment-crypto",
    *(str(UNIT_DIR / unit) for unit in GUARDED_UNITS),
})


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def exact_replace(data, old, new):
    if data.count(old) != 1:
        raise ValueError("free guest input differs from paid overlay source contract")
    return data.replace(old, new)


def checked_name(name):
    if (not isinstance(name, str) or len(name) > 253
            or any(len(part) > 63 or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part)
                for part in name.split("."))):
        raise ValueError("common issuer name is not a canonical DNS name")
    return name


def regular_bytes(path, *, executable=False):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_mode & 0o022 or (executable and not before.st_mode & 0o111)):
        raise ValueError("paid input is missing, mutable, redirected, or not executable")
    data = path.read_bytes()
    after = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                             item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise ValueError("paid input changed during inspection")
    return data


def checked_artifact(path, record, *, executable=False):
    if (not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}
            or record["path"] != path.name or type(record["size"]) is not int
            or record["size"] <= 0 or not isinstance(record["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
        raise ValueError("paid artifact identity is not pinned")
    data = regular_bytes(path, executable=executable)
    if len(data) != record["size"] or sha256(data) != record["sha256"]:
        raise ValueError("paid artifact differs from lock")
    return data


def checked_inputs(lock_path, inputs, base_manifest_sha256, native_report):
    lock_bytes = regular_bytes(lock_path)
    lock = json.loads(lock_bytes, object_pairs_hook=prepare.unique_object,
                      parse_constant=prepare.reject_nonfinite_constant)
    if (not isinstance(lock, dict)
            or set(lock) != {"schema_version", "base_stage_manifest_sha256",
                             "native_source_commit", "native_rust_manifest_sha256",
                             "issuer_name", "artifacts"}
            or type(lock["schema_version"]) is not int or lock["schema_version"] != 1
            or lock["base_stage_manifest_sha256"] != base_manifest_sha256
            or lock["native_source_commit"] != native_report["source_commit"]
            or lock["native_rust_manifest_sha256"] != native_report["reproduction_manifest_sha256"]
            or not isinstance(lock["artifacts"], dict)
            or set(lock["artifacts"]) != set(FILES)):
        raise ValueError("paid input lock differs from verified free stage")
    issuer_name = checked_name(lock["issuer_name"])
    if (not inputs.is_absolute() or inputs.is_symlink() or not inputs.is_dir()
            or {item.name for item in inputs.iterdir()} != set(FILES.values())):
        raise ValueError("paid inputs must contain only the public key and helper")
    artifacts = {
        role: checked_artifact(inputs / name, lock["artifacts"][role],
                               executable=role == "crypto_helper")
        for role, name in FILES.items()
    }
    if lock["artifacts"]["crypto_helper"]["sha256"] != native_report["payment_crypto_sha256"]:
        raise ValueError("paid crypto helper differs from verified native receipt")
    public = artifacts["issuer_public_der"]
    helper = artifacts["crypto_helper"]
    if len(public) > 65535:
        raise ValueError("issuer public key exceeds the runtime frame limit")
    if (len(helper) < 20 or helper[:4] != b"\x7fELF" or helper[4:6] != b"\x02\x01"
            or helper[18:20] != b"\x3e\x00"):
        raise ValueError("crypto helper is not an x86-64 Linux ELF")
    return lock_bytes, issuer_name, artifacts


def render_paid_rootfs(base_rootfs, issuer_name):
    """Return only changed or added rootfs files, relative to rootfs."""
    overlay = {}
    fstab = regular_bytes(base_rootfs / "etc/fstab")
    rule_path = "usr/lib/udev/rules.d/65-gce-disk-naming.rules"
    rules = regular_bytes(base_rootfs / rule_path)
    for relative, data in (("etc/fstab", fstab), (rule_path, rules)):
        if sha256(data) != prepare.PINNED_DISK_FILES[relative]:
            raise ValueError("free disk source differs from reviewed profile")
    if b"zrpc-spent" in fstab or b"zrpc-spent" in rules:
        raise ValueError("free profile already contains paid disk inputs")
    overlay["etc/fstab"] = fstab + (
        b"/dev/disk/by-id/google-zrpc-spent-data /var/lib/zrpc-spent ext4 "
        b"rw,nosuid,nodev,noexec,x-systemd.requires=zrpc-gcp-disk-trigger.service 0 0\n"
    )
    public_rule = rules.splitlines(keepends=True)[-1]
    if public_rule.count(b"zrpc-public-data") != 4:
        raise ValueError("free disk naming rule differs")
    spent_rule = exact_replace(public_rule, b"zrpc-gcp-disk-id $devnode",
                               b"zrpc-gcp-disk-id --spent $devnode")
    spent_rule = spent_rule.replace(b"zrpc-public-data", b"zrpc-spent-data")
    overlay[rule_path] = rules + spent_rule
    tmpfiles = regular_bytes(base_rootfs / "usr/lib/tmpfiles.d/zrpc.conf")
    if b"zrpc-spent" in tmpfiles:
        raise ValueError("free tmpfiles profile already contains spent state")
    overlay["usr/lib/tmpfiles.d/zrpc.conf"] = (
        tmpfiles + b"d /var/lib/zrpc-spent 0700 zrpc-wrapper zrpc-wrapper -\n"
    )
    for unit, service in GUARDED_UNITS.items():
        path = UNIT_DIR / unit
        data = regular_bytes(base_rootfs / path)
        if b"--paid-" in data or b"zrpc-spent" in data:
            raise ValueError("free service already contains paid access")
        data = exact_replace(data,
            b"zrpc-gcp-guard --mark-start " + service.encode(),
            b"zrpc-gcp-guard --paid-mark-start " + service.encode())
        data = exact_replace(data,
            b"zrpc-gcp-guard --exec " + service.encode(),
            b"zrpc-gcp-guard --paid-exec " + service.encode())
        if service == "wrapper":
            data = exact_replace(data, b"--access free-demo\n",
                (b"--access ticket-required --issuer-public-der /etc/zrpc/issuer.der "
                 b"--issuer-name " + issuer_name.encode() +
                 b" --crypto-helper /usr/lib/zrpc/zrpc-payment-crypto "
                 b"--spent-store /var/lib/zrpc-spent\n"))
            data = exact_replace(data, b"[Service]\n",
                                 b"RequiresMountsFor=/var/lib/zrpc-spent\n\n[Service]\n")
            data = exact_replace(data, b"ProtectSystem=strict\n",
                                 b"ProtectSystem=strict\nReadWritePaths=/var/lib/zrpc-spent\n")
        else:
            data = exact_replace(data, b"InaccessiblePaths=",
                                 b"InaccessiblePaths=/var/lib/zrpc-spent ")
        overlay[(path).as_posix()] = data
    return overlay


def write_overlay(output, files, lock_bytes, base_manifest_sha256):
    if (not output.is_absolute() or not output.parent.resolve().is_relative_to(ROOT.resolve())
            or output.exists() or output.is_symlink()):
        raise ValueError("fresh paid overlay directory on workspace volume required")
    output.mkdir(mode=0o700)
    for relative, (data, mode) in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    (output / "paid-inputs.lock.json").write_bytes(lock_bytes)
    root_fd = prepare.open_stage_directory(output)
    try:
        entries = prepare.staged_inventory(root_fd)
    finally:
        os.close(root_fd)
    manifest = {
        "schema_version": 1,
        "status": STATUS,
        "base_stage_manifest_sha256": base_manifest_sha256,
        "paid_inputs_lock_sha256": sha256(lock_bytes),
        "entries": entries,
        "image_built": False,
        "private_mode_approved": False,
    }
    encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (output / "candidate-manifest.json").write_bytes(encoded)
    return {"status": STATUS, "manifest_sha256": sha256(encoded),
            "manifest_bytes": len(encoded), "image_built": False,
            "private_mode_approved": False}


def stage(base_stage, base_sha256, base_bytes, lock_path, inputs,
          native_bundle, native_revision, output, *, selected_output=None):
    prepare.verify_stage(base_stage, base_sha256, base_bytes)
    destination = output.resolve()
    if (destination.is_relative_to(base_stage.resolve())
            or destination.is_relative_to(inputs.resolve())
            or destination.is_relative_to(native_bundle.resolve())):
        raise ValueError("paid overlay output must not mutate pinned inputs")
    if selected_output is None:
        native_report = export_rust_inputs.inspect(native_bundle, native_revision)
    else:
        native_report = export_rust_inputs.inspect(
            native_bundle, native_revision, selected_output=selected_output)
    lock_bytes, issuer_name, artifacts = checked_inputs(
        lock_path, inputs, base_sha256, native_report)
    files = {
        "rootfs/" + relative: (data, 0o644)
        for relative, data in render_paid_rootfs(base_stage / "rootfs", issuer_name).items()
    }
    files.update({
        "rootfs/etc/zrpc/issuer.der": (artifacts["issuer_public_der"], 0o444),
        "rootfs/usr/lib/zrpc/zrpc-payment-crypto": (artifacts["crypto_helper"], 0o555),
    })
    return write_overlay(output, files, lock_bytes, base_sha256)


def verify(output, manifest_sha256, manifest_bytes):
    if (not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)
            or type(manifest_bytes) is not int or manifest_bytes <= 0):
        raise ValueError("paid overlay manifest identity required")
    root_fd = prepare.open_stage_directory(output)
    try:
        encoded = regular_bytes(output / "candidate-manifest.json")
        if len(encoded) != manifest_bytes or sha256(encoded) != manifest_sha256:
            raise ValueError("paid overlay manifest differs")
        manifest = json.loads(encoded, object_pairs_hook=prepare.unique_object,
                              parse_constant=prepare.reject_nonfinite_constant)
        if (not isinstance(manifest, dict)
                or set(manifest) != {"schema_version", "status", "base_stage_manifest_sha256",
                                         "paid_inputs_lock_sha256", "entries", "image_built",
                                         "private_mode_approved"}
                or manifest["schema_version"] != 1 or manifest["status"] != STATUS
                or manifest["image_built"] is not False
                or manifest["private_mode_approved"] is not False
                or not isinstance(manifest["entries"], dict)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["base_stage_manifest_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["paid_inputs_lock_sha256"])):
            raise ValueError("paid overlay manifest has invalid fields")
        expected_paths = {"paid-inputs.lock.json"}
        for relative in PAID_ROOTFS_FILES:
            path = Path("rootfs") / relative
            expected_paths.add(path.as_posix())
            expected_paths.update(parent.as_posix() for parent in path.parents
                                  if parent != Path("."))
        if (set(manifest["entries"]) != expected_paths
                or any(item["type"] == "symlink"
                       for item in manifest["entries"].values())):
            raise ValueError("paid overlay contains an unreviewed path")
        prepare.staged_inventory(root_fd, manifest["entries"])
        if sha256(regular_bytes(output / "paid-inputs.lock.json")) != manifest["paid_inputs_lock_sha256"]:
            raise ValueError("paid input lock differs from overlay")
    finally:
        os.close(root_fd)
    return {"status": "paid-overlay-matches-pinned-manifest", "image_built": False,
            "private_mode_approved": False}


def render_paid_auditor(base_auditor, overlay):
    if b"__STAGED_MOUNT_SHA256__" in base_auditor:
        raise ValueError("free rootfs audit has not been staged")
    pins = {}
    for relative in sorted(PAID_ROOTFS_FILES):
        path = overlay / "rootfs" / relative
        data = regular_bytes(path, executable=relative.endswith("/zrpc-payment-crypto"))
        pins[relative] = (len(data), sha256(data), stat.S_IMODE(path.stat().st_mode))
    result = base_auditor
    for relative in ("etc/fstab", "usr/lib/udev/rules.d/65-gce-disk-naming.rules"):
        result = exact_replace(result,
            prepare.PINNED_DISK_FILES[relative].encode(), pins[relative][1].encode())
    result = exact_replace(result, b"PAID_PINNED_FILES = {}\n",
                           ("PAID_PINNED_FILES = " + repr(pins) + "\n").encode())
    return result


def apply(base_stage, base_sha256, base_bytes, overlay, overlay_sha256,
          overlay_bytes, output):
    prepare.verify_stage(base_stage, base_sha256, base_bytes)
    verify(overlay, overlay_sha256, overlay_bytes)
    overlay_manifest = json.loads(regular_bytes(overlay / "candidate-manifest.json"),
                                  object_pairs_hook=prepare.unique_object,
                                  parse_constant=prepare.reject_nonfinite_constant)
    if overlay_manifest["base_stage_manifest_sha256"] != base_sha256:
        raise ValueError("paid overlay belongs to another free stage")
    destination = output.resolve()
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not output.parent.resolve().is_relative_to(ROOT.resolve())
            or destination.is_relative_to(base_stage.resolve())
            or destination.is_relative_to(overlay.resolve())):
        raise ValueError("fresh disjoint paid stage on workspace volume required")
    shutil.copytree(base_stage, output, symlinks=True)
    prepare.verify_stage(output, base_sha256, base_bytes)
    for relative in sorted(PAID_ROOTFS_FILES):
        source = overlay / "rootfs" / relative
        target = output / "rootfs" / relative
        parent = output
        for component in Path("rootfs", relative).parts[:-1]:
            parent = parent / component
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError("paid stage file parent redirected")
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError("paid stage file redirected")
        data = regular_bytes(source)
        target.write_bytes(data)
        target.chmod(stat.S_IMODE(source.stat().st_mode))
    for name, source in (("paid-inputs.lock.json", overlay / "paid-inputs.lock.json"),
                         ("paid-overlay-manifest.json", overlay / "candidate-manifest.json")):
        with (output / name).open("xb") as stream:
            stream.write(regular_bytes(source))
    auditor = output / "audit-rootfs.py"
    rendered = render_paid_auditor(regular_bytes(auditor, executable=True), overlay)
    temporary = output / "audit-rootfs.paid.tmp"
    with temporary.open("xb") as stream:
        stream.write(rendered)
    temporary.chmod(0o555)
    temporary.replace(auditor)
    base_manifest = json.loads(regular_bytes(output / "candidate-manifest.json"),
                               object_pairs_hook=prepare.unique_object,
                               parse_constant=prepare.reject_nonfinite_constant)
    root_fd = prepare.open_stage_directory(output)
    try:
        base_manifest["entries"] = prepare.staged_inventory(root_fd)
    finally:
        os.close(root_fd)
    base_manifest["remaining_gates"].extend([
        "paid rootfs finalizer and raw-root audit on exact built image",
        "preinitialized persistent spent disk and measured paid guest boot",
        "operator release approval and live testnet ticket redemption",
    ])
    encoded = (json.dumps(base_manifest, indent=2) + "\n").encode()
    (output / "candidate-manifest.json").write_bytes(encoded)
    result = prepare.verify_stage(output, sha256(encoded), len(encoded))
    return {"status": "paid-stage-staged-unbuilt-unapproved",
            "manifest_sha256": result["manifest_sha256"],
            "manifest_bytes": result["manifest_bytes"],
            "image_built": False, "private_mode_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    staged = sub.add_parser("stage")
    staged.add_argument("--base-stage", type=Path, required=True)
    staged.add_argument("--base-manifest-sha256", required=True)
    staged.add_argument("--base-manifest-bytes", type=int, required=True)
    staged.add_argument("--paid-lock", type=Path, required=True)
    staged.add_argument("--paid-inputs", type=Path, required=True)
    staged.add_argument("--native-rust-bundle", type=Path, required=True)
    staged.add_argument("--native-source-commit", required=True)
    staged.add_argument("--output", type=Path, required=True)
    verified = sub.add_parser("verify")
    verified.add_argument("--output", type=Path, required=True)
    verified.add_argument("--manifest-sha256", required=True)
    verified.add_argument("--manifest-bytes", type=int, required=True)
    applied = sub.add_parser("apply")
    applied.add_argument("--base-stage", type=Path, required=True)
    applied.add_argument("--base-manifest-sha256", required=True)
    applied.add_argument("--base-manifest-bytes", type=int, required=True)
    applied.add_argument("--paid-overlay", type=Path, required=True)
    applied.add_argument("--overlay-manifest-sha256", required=True)
    applied.add_argument("--overlay-manifest-bytes", type=int, required=True)
    applied.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "stage":
            result = stage(args.base_stage, args.base_manifest_sha256,
                           args.base_manifest_bytes, args.paid_lock,
                           args.paid_inputs, args.native_rust_bundle,
                           args.native_source_commit, args.output)
        elif args.command == "apply":
            result = apply(args.base_stage, args.base_manifest_sha256,
                           args.base_manifest_bytes, args.paid_overlay,
                           args.overlay_manifest_sha256,
                           args.overlay_manifest_bytes, args.output)
        else:
            result = verify(args.output, args.manifest_sha256, args.manifest_bytes)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
