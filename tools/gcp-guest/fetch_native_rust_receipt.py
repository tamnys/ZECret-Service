#!/usr/bin/env python3
"""Fetch a manually selected, digest-pinned native Rust diagnostic receipt.

This is an input transfer for an unsigned image-build diagnostic. The caller
must provide the prior workflow run ID, attempt, and artifact ZIP SHA-256 from
an independently reviewed run. A GitHub API response cannot nominate trust.
"""

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
HEX = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
WORKFLOW = ".github/workflows/gcp-native-cargo-gate.yml"


def digest_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def check_payment_gate(bundle, lock_sha256):
    gate = json.loads((bundle / "dependency-gates/payment-registry-age.json").read_bytes(),
                      object_pairs_hook=unique_object)
    if (gate.get("cargo_lock_sha256") != lock_sha256
            or gate.get("registry_preflight_passed") is not True
            or gate.get("younger_than_hold") != []
            or gate.get("cargo_fetch_executed") is not False
            or gate.get("cargo_build_executed") is not False
            or gate.get("private_mode_approved") is not False):
        raise ValueError("payment helper dependency gate differs from matched build")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate dependency gate field")
        result[key] = value
    return result


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("workflow attempt timestamp missing")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def select_artifact(run, listing, *, repository, revision, run_id, attempt, digest):
    if (not REPOSITORY.fullmatch(repository) or not SHA.fullmatch(revision)
            or not HEX.fullmatch(digest) or type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0):
        raise ValueError("explicit exact run and digest inputs required")
    if (run.get("id") != run_id or run.get("head_sha") != revision
            or run.get("run_attempt") != attempt
            or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("path", "").split("@", 1)[0] != WORKFLOW
            or run.get("repository", {}).get("full_name", "").lower() != repository.lower()):
        raise ValueError("native Rust run does not match selected source and workflow")
    artifacts = listing.get("artifacts")
    if (not isinstance(artifacts, list)
            or listing.get("total_count") != len(artifacts)):
        raise ValueError("native Rust artifact listing is incomplete")
    selected = [item for item in artifacts
                if item.get("name") == f"native-rust-{revision}"]
    if len(selected) != 1:
        raise ValueError("exactly one native Rust artifact required")
    artifact = selected[0]
    owner = artifact.get("workflow_run", {})
    if (type(artifact.get("id")) is not int or artifact["id"] <= 0
            or artifact.get("expired") is not False
            or artifact.get("digest") != "sha256:" + digest
            or owner.get("id") != run_id or owner.get("head_sha") != revision
            or owner.get("repository_id") != run["repository"].get("id")
            or timestamp(artifact.get("created_at")) < timestamp(run.get("run_started_at"))):
        raise ValueError("native Rust artifact differs from pinned successful attempt")
    return artifact["id"]


def safe_name(name):
    # GNU tar -C <bundle> -cf <receipt> . records the root as ".".
    if name in (".", "./"):
        return None
    if not name.startswith("./") or "\\" in name:
        raise ValueError("receipt TAR member has an unsafe name")
    relative = name[2:].rstrip("/")
    if relative in ("", "."):
        return None
    parts = PurePosixPath(relative).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError("receipt TAR member escapes bundle")
    return Path(*parts)


def enable_verified_host_verifier(bundle):
    """Make only the inspected host verifier executable after receipt checks."""
    binary = bundle / "artifacts/zrpc-uki-digest"
    descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            raise ValueError("native UKI verifier is not one regular file")
        os.fchmod(descriptor, 0o500)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o500:
            raise ValueError("native UKI verifier executable mode was not set")
    finally:
        os.close(descriptor)


def unpack_receipt(archive, output, revision, digest):
    if not SHA.fullmatch(revision) or not HEX.fullmatch(digest):
        raise ValueError("exact Rust artifact identity required")
    if digest_file(archive) != digest:
        raise ValueError("downloaded Rust ZIP differs from pinned digest")
    tar_name = f"native-rust-{revision}.tar"
    sum_name = tar_name + ".sha256"
    output.mkdir(mode=0o700)
    tar_path = output / tar_name
    with zipfile.ZipFile(archive) as packed:
        if len(packed.namelist()) != 2 or set(packed.namelist()) != {tar_name, sum_name}:
            raise ValueError("native Rust artifact ZIP contains unexpected files")
        if any(info.is_dir() or info.flag_bits & 1 for info in packed.infolist()):
            raise ValueError("native Rust artifact ZIP contains directory or encrypted entry")
        sums = packed.read(sum_name)
        with packed.open(tar_name) as source, tar_path.open("xb") as target:
            shutil.copyfileobj(source, target)
    tar_digest = digest_file(tar_path)
    if sums != f"{tar_digest}  {tar_name}\n".encode():
        raise ValueError("native Rust TAR differs from its recorded SHA-256")
    bundle = output / "rust-bundle"
    bundle.mkdir(mode=0o700)
    seen = set()
    with tarfile.open(tar_path, mode="r:") as contents:
        for member in contents:
            relative = safe_name(member.name)
            if relative is None:
                if not member.isdir():
                    raise ValueError("receipt TAR root is not a directory")
                continue
            if relative in seen:
                raise ValueError("receipt TAR contains a duplicate path")
            seen.add(relative)
            target = bundle / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=False, mode=0o700)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                payload = contents.extractfile(member)
                if payload is None:
                    raise ValueError("receipt TAR member is unreadable")
                with target.open("xb") as stream:
                    shutil.copyfileobj(payload, stream)
            else:
                raise ValueError("receipt TAR contains a link or special file")
    spec = importlib.util.spec_from_file_location(
        "export_rust_inputs", ROOT / "tools/gcp-guest/export_rust_inputs.py")
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    report = exporter.inspect(bundle, revision)
    check_payment_gate(bundle, report["payment_crypto_lock_sha256"])
    enable_verified_host_verifier(bundle)
    expected_files = {"manifest.json", "SHA256SUMS", "source.tar",
                      "dependency-gates/registry-age.json",
                      "dependency-gates/payment-registry-age.json",
                      "dependency-gates/git-source-age.json",
                      "dependency-gates/git-object.json",
                      "guest-inputs/diagnostic-rust-inputs.json"}
    for name in exporter.EXPECTED_ALL_BINARIES:
        expected_files.update({f"artifacts/{name}",
                               f"build-a/target/release/{name}",
                               f"build-b/target/release/{name}"})
    for role in exporter.EXPECTED_GUEST_BINARIES:
        expected_files.add(f"guest-inputs/{role}")
    observed_files = {path.relative_to(bundle).as_posix()
                      for path in bundle.rglob("*") if path.is_file()}
    if observed_files != expected_files:
        raise ValueError("native Rust TAR contains an unreviewed file inventory")
    for role, identity in report["artifacts"].items():
        if digest_file(bundle / "guest-inputs" / role) != identity["sha256"]:
            raise ValueError("exported guest binary differs from matched builds")
    expected_report = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    if (bundle / "guest-inputs/diagnostic-rust-inputs.json").read_bytes() != expected_report:
        raise ValueError("exported guest Rust receipt differs from matched builds")
    return {"status": "diagnostic-exact-head-native-rust-receipt-downloaded",
            "source_commit": revision, "artifact_zip_sha256": digest,
            "artifact_tar_sha256": tar_digest,
            "reproduction_manifest_sha256": report["reproduction_manifest_sha256"],
            "rust_bundle": str(bundle), "image_built": False,
            "private_mode_approved": False}


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("artifact redirect must use HTTPS")
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(request.full_url).netloc:
            redirected.remove_header("Authorization")
            redirected.unredirected_hdrs.pop("Authorization", None)
        return redirected


def api(opener, repository, endpoint, token):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{endpoint}",
        headers={"Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Authorization": "Bearer " + token})
    return opener.open(request)


def fetch(repository, revision, run_id, attempt, digest, output, token):
    if (not token or not REPOSITORY.fullmatch(repository)
            or not SHA.fullmatch(revision) or not HEX.fullmatch(digest)
            or type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0
            or output.exists() or output.is_symlink()):
        raise ValueError("token and fresh Rust artifact output required")
    opener = urllib.request.build_opener(SafeRedirect())
    with api(opener, repository, f"actions/runs/{run_id}", token) as stream:
        run = json.load(stream)
    with api(opener, repository,
             f"actions/runs/{run_id}/artifacts?per_page=100", token) as stream:
        listing = json.load(stream)
    artifact_id = select_artifact(run, listing, repository=repository,
                                  revision=revision, run_id=run_id,
                                  attempt=attempt, digest=digest)
    output.mkdir(mode=0o700)
    archive = output / "artifact.zip"
    with api(opener, repository, f"actions/artifacts/{artifact_id}/zip", token) as source:
        with archive.open("xb") as target:
            shutil.copyfileobj(source, target)
    if digest_file(archive) != digest:
        raise ValueError("GitHub artifact download differs from explicit pinned digest")
    unpacked = output / "verified"
    report = unpack_receipt(archive, unpacked, revision, digest)
    report.update({"run_id": run_id, "run_attempt": attempt,
                   "artifact_id": artifact_id})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = fetch(args.repository, args.revision, args.run_id,
                       args.run_attempt, args.artifact_digest,
                       args.output, os.environ.get("GITHUB_TOKEN", ""))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            zipfile.BadZipFile, tarfile.TarError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
