#!/usr/bin/env python3
"""Fetch and stage the pinned native ARM64 Zebra for local public Testnet work.

This is a diagnostic local artifact, not a Phala image input or an approved
private-query release. The v6.4.2 age exception is explicit at each invocation.
"""

import argparse
import base64
import binascii
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/gcp-guest"))
import verify_zebra_release as common  # Existing strict metadata and sealed-verifier helpers.

LOCK_PATH = ROOT / "deploy/phala/zebra-arm64-local.lock.json"
ARCHIVE_NAME = "zebrad-6.4.2-aarch64-unknown-linux-gnu.tar.gz"
BUNDLE_NAME = "zebrad-v6.4.2-arm64.attestation.json"
TAR_MEMBERS = {"zebrad", "LICENSE-APACHE", "LICENSE-MIT", "README.md"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def load_lock():
    descriptor, before = common.regular_file(LOCK_PATH)
    with os.fdopen(descriptor, "rb") as stream:
        data = stream.read()
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("local Zebra lock changed while reading")
    lock = common.read_json(data)
    required = {"schema_version", "status", "repository", "release_id", "tag",
                "tag_object_sha", "source_commit", "published_at",
                "minimum_age_days", "asset", "checksum_manifest", "checksum_bundle",
                "attestation_bundle_sha256", "attestation_bundle_name",
                "signer_workflow", "reviewed_advisory_count",
                "reviewed_advisory_snapshot_sha256",
                "reviewed_cosign_advisory_count",
                "reviewed_cosign_advisory_snapshot_sha256",
                "cosign_verifier_source", "zebrad_elf_size", "zebrad_elf_sha256"}
    if (not isinstance(lock, dict) or set(lock) != required
            or lock["schema_version"] != 1
            or lock["status"] != "local-testnet-diagnostic-unapproved"
            or lock["repository"] != "ZcashFoundation/zebra"
            or lock["release_id"] != 396882484
            or lock["tag"] != "v6.4.2"
            or lock["tag_object_sha"] != "40bf166415fa8900f05df766f12ede91c2f7f4e5"
            or lock["source_commit"] != "e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291"
            or lock["minimum_age_days"] != 7
            or lock["attestation_bundle_name"] != BUNDLE_NAME
            or lock["signer_workflow"] !=
            "ZcashFoundation/zebra/.github/workflows/zfnd-release-binaries.yml"
            or not SHA256.fullmatch(lock["attestation_bundle_sha256"])
            or not SHA256.fullmatch(lock["zebrad_elf_sha256"])
            or type(lock["zebrad_elf_size"]) is not int
            or lock["zebrad_elf_size"] <= 0
            or type(lock["reviewed_advisory_count"]) is not int
            or lock["reviewed_advisory_count"] <= 0
            or not SHA256.fullmatch(lock["reviewed_advisory_snapshot_sha256"])
            or type(lock["reviewed_cosign_advisory_count"]) is not int
            or lock["reviewed_cosign_advisory_count"] <= 0
            or not SHA256.fullmatch(lock["reviewed_cosign_advisory_snapshot_sha256"])):
        raise ValueError("local Zebra release lock is incomplete or changed")
    common.utc(lock["published_at"])
    for key, name in (("asset", ARCHIVE_NAME),
                      ("checksum_manifest", "SHA256SUMS"),
                      ("checksum_bundle", "SHA256SUMS.sigstore.json")):
        asset = lock[key]
        if (not isinstance(asset, dict)
                or set(asset) != {"id", "name", "size", "sha256", "created_at", "updated_at"}
                or type(asset["id"]) is not int or asset["id"] <= 0
                or asset["name"] != name
                or type(asset["size"]) is not int or asset["size"] <= 0
                or not SHA256.fullmatch(asset["sha256"])):
            raise ValueError("local Zebra asset lock is malformed")
        common.utc(asset["created_at"])
        common.utc(asset["updated_at"])
    source = lock["cosign_verifier_source"]
    required_source = {"repository", "tag", "published_at", "asset_created_at",
                       "asset_updated_at", "asset_name", "asset_size",
                       "asset_sha256"}
    if (not isinstance(source, dict) or set(source) != required_source
            or source["repository"] != "sigstore/cosign"
            or source["tag"] != "v3.1.3"
            or source["asset_name"] != "cosign-linux-arm64"
            or type(source["asset_size"]) is not int or source["asset_size"] <= 0
            or not SHA256.fullmatch(source["asset_sha256"])):
        raise ValueError("local Zebra verifier-tool lock is malformed")
    common.utc(source["published_at"])
    common.utc(source["asset_created_at"])
    common.utc(source["asset_updated_at"])
    return lock, hashlib.sha256(data).hexdigest()


def asset_matches(release, asset):
    matches = [item for item in release.get("assets", [])
               if isinstance(item, dict) and item.get("name") == asset["name"]]
    return len(matches) == 1 and all(matches[0].get(key) == value for key, value in (
        ("id", asset["id"]), ("size", asset["size"]),
        ("digest", "sha256:" + asset["sha256"]),
        ("created_at", asset["created_at"]),
        ("updated_at", asset["updated_at"]), ("state", "uploaded")))


def live_preflight(lock):
    release, release_time = common.fetch_json(common.API + "/releases/tags/" + lock["tag"])
    tag_ref, ref_time = common.fetch_json(common.API + "/git/ref/tags/" + lock["tag"])
    tag_object, tag_time = common.fetch_json(common.API + "/git/tags/" + lock["tag_object_sha"])
    advisories, advisory_time = common.fetch_json(
        common.API + "/security-advisories?state=published&per_page=100")
    now = min(release_time, ref_time, tag_time, advisory_time)
    report = common.check_metadata(lock, release, tag_ref, tag_object, advisories, now)
    for key in ("checksum_manifest", "checksum_bundle"):
        if not asset_matches(release, lock[key]):
            raise ValueError("official Zebra checksum asset changed or disappeared")
    source = lock["cosign_verifier_source"]
    tool_release, tool_time = common.fetch_json(
        f"https://api.github.com/repos/{source['repository']}/releases/tags/{source['tag']}")
    matches = [item for item in tool_release.get("assets", [])
               if isinstance(item, dict) and item.get("name") == source["asset_name"]]
    if (tool_release.get("published_at") != source["published_at"]
            or tool_release.get("draft") is not False
            or tool_release.get("prerelease") is not False
            or len(matches) != 1
            or matches[0].get("state") != "uploaded"
            or matches[0].get("size") != source["asset_size"]
            or matches[0].get("digest") != "sha256:" + source["asset_sha256"]
            or matches[0].get("created_at") != source["asset_created_at"]
            or matches[0].get("updated_at") != source["asset_updated_at"]
            or min(now, tool_time) < max(common.utc(source["published_at"]),
                                         common.utc(source["asset_created_at"]))
            + timedelta(days=lock["minimum_age_days"])):
        raise ValueError("reviewed Cosign verifier changed or remains age-held")
    tool_advisories, _ = common.fetch_json(
        "https://api.github.com/repos/sigstore/cosign/security-advisories?state=published&per_page=100")
    count, snapshot = common.advisory_snapshot(tool_advisories)
    if (count != lock["reviewed_cosign_advisory_count"]
            or snapshot != lock["reviewed_cosign_advisory_snapshot_sha256"]):
        raise ValueError("Cosign advisories changed; new review required")
    return report


def require_local_age_policy(report, exception):
    held = report["status"] == "held-metadata-only-unapproved"
    if held and not exception:
        raise ValueError("Zebra v6.4.2 age hold requires explicit local-only exception")
    return held


def inside_workspace(path, *, must_exist):
    if not path.is_absolute() or (must_exist and path.resolve(strict=True) != path):
        raise ValueError("absolute non-symlink workspace path required")
    anchor = path if must_exist else path.parent
    if not anchor.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True)):
        raise ValueError("Zebra artifacts must remain on the managed workspace volume")


def download(url, destination, expected_size, expected_hash):
    request = urllib.request.Request(url, headers={"User-Agent": "zrpc-zebra-arm64-local-stage/1"})
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request) as source, destination.open("xb") as target:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > expected_size:
                raise ValueError("download exceeds reviewed size")
            digest.update(chunk)
            target.write(chunk)
    if (size, digest.hexdigest()) != (expected_size, expected_hash):
        raise ValueError("download differs from reviewed digest")


def fetch_bundle(lock, destination):
    url = (common.API + "/attestations/sha256:" + lock["asset"]["sha256"])
    data, _ = common.fetch_json(url)
    matches = data.get("attestations") if isinstance(data, dict) else None
    if (not isinstance(matches, list) or len(matches) != 1
            or not isinstance(matches[0], dict)
            or matches[0].get("repository_id") != 205255683
            or not isinstance(matches[0].get("bundle"), dict)):
        raise ValueError("official Zebra attestation bundle differs")
    encoded = (json.dumps(matches[0]["bundle"], sort_keys=True,
                          separators=(",", ":")) + "\n").encode()
    if hashlib.sha256(encoded).hexdigest() != lock["attestation_bundle_sha256"]:
        raise ValueError("official Zebra attestation bundle differs from reviewed digest")
    destination.write_bytes(encoded)


def fetch(lock, output):
    inside_workspace(output, must_exist=False)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh absolute raw artifact directory required")
    temporary = Path(tempfile.mkdtemp(prefix=".zebra-arm64-fetch-", dir=output.parent))
    try:
        for key in ("asset", "checksum_manifest", "checksum_bundle"):
            asset = lock[key]
            url = (f"https://github.com/{lock['repository']}/releases/download/"
                   f"{lock['tag']}/{asset['name']}")
            download(url, temporary / asset["name"], asset["size"], asset["sha256"])
        source = lock["cosign_verifier_source"]
        url = (f"https://github.com/{source['repository']}/releases/download/"
               f"{source['tag']}/{source['asset_name']}")
        download(url, temporary / source["asset_name"],
                 source["asset_size"], source["asset_sha256"])
        fetch_bundle(lock, temporary / BUNDLE_NAME)
        temporary.rename(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def checked_copy(source, destination, size, digest):
    if common.sha256_file(source) != (size, digest):
        raise ValueError("local Zebra input differs from reviewed identity")
    shutil.copyfile(source, destination)
    if common.sha256_file(destination) != (size, digest):
        raise ValueError("local Zebra input changed while copying")


def parse_manifest(data, asset):
    lines = data.decode("ascii").splitlines()
    entries = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None or match[2] in entries:
            raise ValueError("official Zebra checksum manifest malformed")
        entries[match[2]] = match[1]
    if (set(entries) != {ARCHIVE_NAME, "zebrad-6.4.2-x86_64-unknown-linux-gnu.tar.gz"}
            or entries[ARCHIVE_NAME] != asset["sha256"]):
        raise ValueError("signed Zebra checksum does not match ARM64 archive")


def extract_member(archive, name, destination, expected_size, expected_digest):
    with tarfile.open(archive, "r:gz") as package:
        member = package.getmember(name)
        if not member.isfile() or member.size != expected_size:
            raise ValueError("reviewed executable member differs")
        with package.extractfile(member) as source, destination.open("xb") as target:
            if source is None:
                raise ValueError("reviewed executable member missing")
            shutil.copyfileobj(source, target)
    if common.sha256_file(destination) != (expected_size, expected_digest):
        raise ValueError("reviewed executable digest differs")
    with destination.open("rb") as source:
        header = source.read(20)
    if (header[:6] != b"\x7fELF\x02\x01"
            or header[16:18] not in (b"\x02\x00", b"\x03\x00")
            or header[18:20] != b"\xb7\x00"):
        raise ValueError("reviewed executable is not an ARM64 ELF")
    destination.chmod(0o555)


def sealed_command(executable, expected_hash, args):
    descriptor = common.sealed_verifier_fd(executable, expected_hash)
    try:
        command_path = f"/proc/self/fd/{descriptor}"
        result = subprocess.run([command_path, *args], executable=command_path,
                                pass_fds=(descriptor,), capture_output=True, check=False)
    finally:
        os.close(descriptor)
    if result.returncode:
        raise ValueError("reviewed signature/provenance verifier rejected Zebra release")
    return result.stdout


def validate_statement(lock, bundle_data):
    """Check the payload only after Cosign verifies this same pinned bundle."""
    bundle = common.read_json(bundle_data)
    envelope = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
        raise ValueError("verified Zebra provenance envelope malformed")
    statement = common.read_json(base64.b64decode(envelope["payload"], validate=True))
    if not isinstance(statement, dict):
        raise ValueError("verified Zebra provenance statement malformed")
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    identity = ("https://github.com/" + lock["signer_workflow"] +
                "@refs/tags/" + lock["tag"])
    subject = {"name": ARCHIVE_NAME,
               "digest": {"sha256": lock["asset"]["sha256"]}}
    external = definition.get("externalParameters") if isinstance(definition, dict) else None
    internal = definition.get("internalParameters") if isinstance(definition, dict) else None
    github = internal.get("github") if isinstance(internal, dict) else None
    builder = details.get("builder") if isinstance(details, dict) else None
    if (statement.get("_type") != "https://in-toto.io/Statement/v1"
            or statement.get("subject") != [subject]
            or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
            or not isinstance(definition, dict)
            or definition.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
            or not isinstance(external, dict)
            or external.get("workflow") != {
                "ref": "refs/tags/" + lock["tag"],
                "repository": "https://github.com/" + lock["repository"],
                "path": ".github/workflows/release-binaries.yml"}
            or definition.get("resolvedDependencies") != [{
                "uri": "git+https://github.com/" + lock["repository"] +
                       "@refs/tags/" + lock["tag"],
                "digest": {"gitCommit": lock["source_commit"]}}]
            or not isinstance(github, dict)
            or github.get("event_name") != "release"
            or github.get("repository_id") != "205255683"
            or github.get("runner_environment") != "github-hosted"
            or not isinstance(builder, dict)
            or builder.get("id") != identity):
        raise ValueError("verified Zebra provenance does not match reviewed build")


def verify_signatures(lock, temporary):
    cosign = temporary / lock["cosign_verifier_source"]["asset_name"]
    identity = ("https://github.com/" + lock["signer_workflow"] +
                "@refs/tags/" + lock["tag"])
    sealed_command(cosign, lock["cosign_verifier_source"]["asset_sha256"],
                   ["verify-blob", str(temporary / "SHA256SUMS"),
                    "--bundle", str(temporary / "SHA256SUMS.sigstore.json"),
                    "--certificate-identity", identity,
                    "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"])
    bundle = temporary / BUNDLE_NAME
    archive = temporary / ARCHIVE_NAME
    sealed_command(cosign, lock["cosign_verifier_source"]["asset_sha256"],
                   ["verify-blob-attestation", str(archive),
                    "--bundle", str(bundle),
                    "--certificate-identity", identity,
                    "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                    "--type", "https://slsa.dev/provenance/v1", "--check-claims=true"])
    bundle_data = bundle.read_bytes()
    if hashlib.sha256(bundle_data).hexdigest() != lock["attestation_bundle_sha256"]:
        raise ValueError("verified Zebra attestation bundle changed")
    validate_statement(lock, bundle_data)


def stage(lock, lock_sha256, raw, output, preflight, exception_used):
    inside_workspace(raw, must_exist=True)
    inside_workspace(output, must_exist=False)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh absolute staged-output directory required")
    temporary = Path(tempfile.mkdtemp(prefix=".zebra-arm64-stage-", dir=output.parent))
    try:
        for key in ("asset", "checksum_manifest", "checksum_bundle"):
            asset = lock[key]
            checked_copy(raw / asset["name"], temporary / asset["name"],
                         asset["size"], asset["sha256"])
        source = lock["cosign_verifier_source"]
        checked_copy(raw / source["asset_name"], temporary / source["asset_name"],
                     source["asset_size"], source["asset_sha256"])
        bundle = raw / BUNDLE_NAME
        size, digest = common.sha256_file(bundle)
        if size <= 0 or digest != lock["attestation_bundle_sha256"]:
            raise ValueError("reviewed Zebra attestation bundle differs")
        checked_copy(bundle, temporary / BUNDLE_NAME, size, digest)
        parse_manifest((temporary / "SHA256SUMS").read_bytes(), lock["asset"])
        verify_signatures(lock, temporary)
        archive = temporary / ARCHIVE_NAME
        with tarfile.open(archive, "r:gz") as package:
            members = package.getmembers()
            if (len(members) != len(TAR_MEMBERS)
                    or {member.name for member in members} != TAR_MEMBERS
                    or any(not member.isfile() for member in members)):
                raise ValueError("Zebra ARM64 archive has unexpected members")
        executable = temporary / "zebrad"
        extract_member(archive, "zebrad", executable,
                       lock["zebrad_elf_size"], lock["zebrad_elf_sha256"])
        receipt = {
            "schema_version": 1,
            "status": "local-testnet-staged-diagnostic-unapproved",
            "tag": lock["tag"],
            "architecture": "aarch64-unknown-linux-gnu",
            "checked_at_utc": preflight["checked_at_utc"],
            "eligible_at_utc": preflight["eligible_at_utc"],
            "local_release_age_exception_used": exception_used,
            "release_lock_sha256": lock_sha256,
            "asset_sha256": lock["asset"]["sha256"],
            "zebrad_elf_sha256": lock["zebrad_elf_sha256"],
            "zebrad_elf_size": lock["zebrad_elf_size"],
            "signed_checksum_verified": True,
            "github_provenance_verified_with_cosign": True,
            "cosign_verifier_executable_sha256": lock["cosign_verifier_source"]["asset_sha256"],
            "private_mode_approved": False,
            "phala_image_approved": False,
        }
        (temporary / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        for key in ("asset", "checksum_manifest", "checksum_bundle"):
            (temporary / lock[key]["name"]).unlink()
        (temporary / source["asset_name"]).unlink()
        (temporary / BUNDLE_NAME).unlink()
        temporary.rename(output)
        return receipt
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "fetch", "stage"):
        command = commands.add_parser(name)
        command.add_argument("--allow-local-release-age-exception", action="store_true")
        if name == "fetch":
            command.add_argument("--output", required=True, type=Path)
        if name == "stage":
            command.add_argument("--raw", required=True, type=Path)
            command.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        lock, lock_sha256 = load_lock()
        preflight = live_preflight(lock)
        if args.command == "preflight":
            print(json.dumps(preflight, indent=2))
            return 0 if preflight["status"] != "held-metadata-only-unapproved" else 2
        exception_used = require_local_age_policy(
            preflight, args.allow_local_release_age_exception)
        if args.command == "fetch":
            fetch(lock, args.output)
            report = {"status": "local-testnet-raw-artifacts-fetched-unapproved",
                      "release_lock_sha256": lock_sha256,
                      "local_release_age_exception_used": exception_used,
                      "private_mode_approved": False}
        else:
            report = stage(lock, lock_sha256, args.raw, args.output,
                           preflight, exception_used)
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, binascii.Error,
            tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "error": str(error),
                          "private_mode_approved": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
