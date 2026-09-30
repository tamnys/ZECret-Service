#!/usr/bin/env python3
"""Export diagnostic x86_64 guest Rust inputs from a double-build receipt.

This only prepares partial schema-6 input files. It does not build an image,
approve a release, sign anything, or contact a provider.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_GUEST_BINARIES = {
    "wrapper": "zrpc-node-wrapper",
    "broker": "zrpc-gcp-quote-broker",
    "guard": "zrpc-gcp-guard",
    "disk_id": "zrpc-gcp-disk-id",
    "cookie": "zrpc-gcp-cookie",
    "early_init": "zrpc-gcp-early-init",
}
EXPECTED_ALL_BINARIES = {
    "zrpc", "zrpc-wrapper", "zrpc-node-wrapper", "zrpc-quote-proxy",
    "zrpc-gcp-quote-broker", "zrpc-gcp-guard", "zrpc-gcp-disk-id", "zrpc-gcp-cookie",
    "zrpc-gcp-early-init", "zrpc-gcp-lifecycle", "zrpc-gcp-import-producer",
    "zrpc-uki-digest", "zrpc-payment-crypto",
}
EXPECTED_SELECTED = ({("zrpc-cli", "zrpc"),
                      ("zrpc-lifecycle", "zrpc-gcp-lifecycle"),
                      ("zrpc-lifecycle", "zrpc-gcp-import-producer"),
                      ("zrpc-uki-digest", "zrpc-uki-digest"),
                      ("zrpc-payment-crypto", "zrpc-payment-crypto")}
                     | {("zrpc-server", name) for name in EXPECTED_ALL_BINARIES
                        if name not in {"zrpc", "zrpc-gcp-lifecycle",
                                        "zrpc-gcp-import-producer", "zrpc-uki-digest",
                                        "zrpc-payment-crypto"}})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise ValueError(f"nonstandard JSON number: {value}")


def regular_bytes(path):
    if path.resolve(strict=True) != path.absolute():
        raise ValueError("input path redirects through a symlink")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input is not a regular file")
        data = stream.read()
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                      after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("input changed while reading")
    return data


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_output(arguments):
    # A caller's Git state must not substitute another tree for the selected
    # commit. Match the reproduction command's no-replacement rule for every
    # source read, including the tree identity check.
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith("GIT_")}
    environment.update({"GIT_NO_REPLACE_OBJECTS": "1",
                        "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_OPTIONAL_LOCKS": "0",
                        "GIT_TERMINAL_PROMPT": "0"})
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode:
        raise ValueError("selected commit lacks a required source input")
    return result.stdout


def git_bytes(revision, path):
    return git_output(["show", f"{revision}:{path}"])


def selected_guest_roles(revision, *, selected_output=None):
    read_selected = git_output if selected_output is None else selected_output
    tree = ast.parse(read_selected(["show", f"{revision}:tools/gcp-guest/prepare.py"]))
    values = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id in ("BINARIES", "EARLY_INIT_ROLE"):
                if target.id in values:
                    raise ValueError("guest role declaration is ambiguous")
                values[target.id] = ast.literal_eval(statement.value)
    binaries = values.get("BINARIES")
    early_init = values.get("EARLY_INIT_ROLE")
    if not isinstance(binaries, dict) or early_init != "early_init":
        raise ValueError("guest role declaration differs from review")
    roles = {role: name for role, name in binaries.items() if role != "zebra"}
    roles[early_init] = "zrpc-gcp-early-init"
    if roles != EXPECTED_GUEST_BINARIES or binaries.get("zebra") != "zebrad":
        raise ValueError("guest executable roles differ from reviewed profile")
    return roles


def x86_64_elf(data):
    return (len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01"
            and data[16:18] in (b"\x02\x00", b"\x03\x00")
            and data[18:20] == b"\x3e\x00")


def inspect(bundle, revision, *, selected_output=None):
    read_selected = git_output if selected_output is None else selected_output
    if read_selected(["rev-parse", "HEAD"]).decode().strip() != revision:
        raise ValueError("Rust receipt source commit differs from exact checkout HEAD")
    manifest_bytes = regular_bytes(bundle / "manifest.json")
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object,
                          parse_constant=reject_nonfinite)
    if (not isinstance(manifest, dict)
            or manifest.get("artifact_kind") != "unsigned_native_scaffold"
            or manifest.get("source_commit") != revision
            or manifest.get("compiled_artifacts_are_synthetic") is not False
            or manifest.get("script_matches_source") is not True
            or manifest.get("reproducible") is not True
            or any(manifest.get(key) is not False for key in (
                "approved_release", "private_accepted", "deployment_enabled",
                "published", "signed"))):
        raise ValueError("reproduction receipt is not an unsigned matched build")
    tools = manifest.get("tools")
    rustc = tools.get("rustc") if isinstance(tools, dict) else None
    version = rustc.get("version") if isinstance(rustc, dict) else None
    if (not isinstance(version, str)
            or re.search(r"^host: x86_64-unknown-linux-gnu$", version, re.MULTILINE) is None):
        raise ValueError("reproduction did not use the x86_64 Rust host")
    pin = tomllib.loads(read_selected(["show", f"{revision}:rust-toolchain.toml"]).decode())["toolchain"]["channel"]
    if re.search(r"^release: " + re.escape(pin) + r"$", version, re.MULTILINE) is None:
        raise ValueError("reproduction Rust release differs from committed toolchain pin")
    if manifest.get("source_tree") != read_selected(
            ["show", "-s", "--format=%T", revision]).decode().strip():
        raise ValueError("reproduction source tree differs from selected commit")
    input_hashes = manifest.get("input_sha256")
    if not isinstance(input_hashes, dict):
        raise ValueError("reproduction input identities are missing")
    for path, field in (
        ("Cargo.lock", "Cargo.lock"),
        ("tools/payment-crypto/Cargo.lock", "tools/payment-crypto/Cargo.lock"),
        ("rust-toolchain.toml", "rust-toolchain.toml"),
        ("scripts/reproduce-release.py", "script_in_source_sha256"),
    ):
        expected = sha256(read_selected(["show", f"{revision}:{path}"]))
        actual = input_hashes.get(field) if field in input_hashes else manifest.get(field)
        if actual != expected or (path == "scripts/reproduce-release.py"
                                  and manifest.get("script_sha256") != expected):
            raise ValueError("reproduction source input differs from selected commit")
    if sha256(regular_bytes(bundle / "source.tar")) != manifest.get("source_archive_sha256"):
        raise ValueError("source archive differs from reproduction receipt")
    roles = selected_guest_roles(revision, selected_output=read_selected)
    selected = manifest.get("selected_binaries")
    if (not isinstance(selected, list) or not selected
            or any(not isinstance(item, dict) or set(item) != {"package", "name"}
                   or not isinstance(item["name"], str)
                   or not isinstance(item["package"], str) for item in selected)):
        raise ValueError("reproduction executable inventory is invalid")
    names = [item["name"] for item in selected]
    if (len(names) != len(set(names)) or set(names) != EXPECTED_ALL_BINARIES
            or {(item["package"], item["name"]) for item in selected}
            != EXPECTED_SELECTED):
        raise ValueError("guest executables are missing from reproduction")
    digests = manifest.get("artifact_sha256")
    builds = manifest.get("builds")
    if (not isinstance(digests, dict) or set(digests) != set(names)
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in digests.values())
            or not isinstance(builds, list) or len(builds) != 2
            or any(not isinstance(build, dict) for build in builds)
            or {build.get("directory") for build in builds} != {"build-a", "build-b"}
            or any(build.get("exit_code") != 0
                   or build.get("payment_helper_exit_code") != 0
                   or build.get("static_import_producer_exit_code") != 0
                   or build.get("static_import_producer_no_dynamic_loader") is not True
                   or build.get("artifact_sha256") != digests
                   for build in builds)):
        raise ValueError("two independent binary receipts do not match")
    expected_sums = "".join(f"{digests[name]}  artifacts/{name}\n"
                            for name in sorted(names)).encode()
    if regular_bytes(bundle / "SHA256SUMS") != expected_sums:
        raise ValueError("checksum list differs from binary receipts")
    for name in names:
        expected = digests[name]
        for path in (bundle / "artifacts" / name,
                     bundle / "build-a" / "target" / "release" / name,
                     bundle / "build-b" / "target" / "release" / name):
            data = regular_bytes(path)
            if sha256(data) != expected:
                raise ValueError("binary differs from independent build receipts")
            if not x86_64_elf(data):
                raise ValueError("project binary is not an x86_64 ELF executable")
    return {
        "schema_version": 1,
        "status": "diagnostic-unsigned-x86_64-rust-inputs-unapproved",
        "source_commit": revision,
        "source_tree": manifest["source_tree"],
        "exporter_script_sha256": sha256(regular_bytes(Path(__file__).resolve())),
        "reproduction_manifest_sha256": sha256(manifest_bytes),
        "cargo_lock_sha256": input_hashes["Cargo.lock"],
        "payment_crypto_lock_sha256": input_hashes["tools/payment-crypto/Cargo.lock"],
        "payment_crypto_sha256": digests["zrpc-payment-crypto"],
        "rust_toolchain_sha256": input_hashes["rust-toolchain.toml"],
        "rustc_host": "x86_64-unknown-linux-gnu",
        "artifacts": {role: {"path": role, "sha256": digests[name]}
                      for role, name in sorted(roles.items())},
        "image_built": False,
        "private_mode_approved": False,
    }


def export(bundle, revision, output):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("exact full lowercase source commit required")
    if not bundle.is_absolute() or not output.is_absolute():
        raise ValueError("absolute bundle and output paths required")
    repository = ROOT.resolve(strict=True)
    if (bundle.resolve(strict=True) != bundle or not bundle.is_relative_to(repository)
            or output.parent.resolve(strict=True) != output.parent
            or not output.parent.is_relative_to(repository)
            or output.exists() or output.is_symlink()):
        raise ValueError("bundle and fresh output must stay in the real checkout")
    report = inspect(bundle, revision)
    output.mkdir(mode=0o700)
    for role, entry in report["artifacts"].items():
        name = EXPECTED_GUEST_BINARIES[role]
        data = regular_bytes(bundle / "artifacts" / name)
        path = output / entry["path"]
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o555)
        if sha256(regular_bytes(path)) != entry["sha256"]:
            raise ValueError("copied guest input changed")
    with (output / "diagnostic-rust-inputs.json").open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.bundle, args.revision, args.output), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
