#!/usr/bin/env python3
"""Verify and stage a pinned local Tor executable; never deploy or start Tor."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen


HERE = Path(__file__).resolve().parent
LOCK = json.loads((HERE / "bundle.lock.json").read_text(encoding="utf-8"))


def require_release_age(now: datetime | None = None) -> None:
    observed = datetime.fromisoformat(LOCK["signature_last_modified_utc"].replace("Z", "+00:00"))
    eligible = observed + timedelta(days=LOCK["minimum_age_days"])
    if (now or datetime.now(timezone.utc)) < eligible:
        raise ValueError(f"pinned Tor signature is inside the release hold until {eligible.isoformat()}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_hash(path: Path, expected: str) -> None:
    if file_sha256(path) != expected:
        raise ValueError(f"pinned SHA-256 mismatch: {path.name}")


def copy_pinned(source, destination: Path, expected_size: int) -> None:
    with destination.open("xb") as target:
        remaining = expected_size
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("pinned Tor download ended early")
            target.write(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise ValueError("pinned Tor download exceeded its recorded size")


def download(url: str, destination: Path, expected_size: int) -> None:
    with urlopen(url) as source:
        copy_pinned(source, destination, expected_size)


def verify_signature(archive: Path, signature: Path, scratch: Path) -> None:
    key = HERE / "tor-browser-signing-key.asc"
    require_hash(key, LOCK["signing_key_sha256"])
    home = scratch / "gnupg"
    home.mkdir(mode=0o700)
    imported = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--import", str(key)],
        capture_output=True,
        text=True,
        check=False,
    )
    if imported.returncode:
        raise ValueError("pinned Tor signing key could not be imported")
    verified = subprocess.run(
        [
            "gpg", "--homedir", str(home), "--batch", "--status-fd", "1",
            "--verify", str(signature), str(archive),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    valid = [
        line.split()
        for line in verified.stdout.splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    fingerprint = LOCK["signing_key_primary_fingerprint"]
    if verified.returncode or len(valid) != 1 or fingerprint not in (valid[0][2], valid[0][-1]):
        raise ValueError("Tor bundle signature did not validate against the pinned signing key")


def checked_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    names: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("unsafe Tor bundle archive path")
        if not (member.isfile() or member.isdir()):
            raise ValueError("Tor bundle contains a link or special file")
        if member.name in names:
            raise ValueError("Tor bundle contains a duplicate path")
        names.add(member.name)
    return members


def unpack_checked(archive_path: Path, destination: Path) -> None:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = checked_members(archive)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Tor bundle member is unreadable")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def stage(output: Path, archive: Path | None, signature: Path | None) -> dict[str, str]:
    require_release_age()
    if output.exists():
        raise ValueError("output already exists; refusing to replace a local Tor installation")
    if not output.is_absolute() or not output.parent.is_dir():
        raise ValueError("--output must be absolute with an existing parent directory")
    if (archive is None) != (signature is None):
        raise ValueError("--archive and --signature must be supplied together")
    with tempfile.TemporaryDirectory(prefix=".tor-prepare-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        archive_path = scratch / LOCK["bundle"]
        signature_path = scratch / (LOCK["bundle"] + ".asc")
        if archive is None:
            download(LOCK["bundle_url"], archive_path, LOCK["bundle_size"])
            download(LOCK["signature_url"], signature_path, LOCK["signature_size"])
        else:
            if archive.stat().st_size != LOCK["bundle_size"] or signature.stat().st_size != LOCK["signature_size"]:
                raise ValueError("local Tor archive or signature has the wrong size")
            shutil.copyfile(archive, archive_path)
            shutil.copyfile(signature, signature_path)
        require_hash(archive_path, LOCK["bundle_sha256"])
        require_hash(signature_path, LOCK["signature_sha256"])
        verify_signature(archive_path, signature_path, scratch)
        payload = scratch / "payload"
        payload.mkdir(mode=0o755)
        unpack_checked(archive_path, payload)
        executable = payload / "tor" / "tor"
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("verified bundle has no executable Tor binary")
        version = subprocess.run(
            [str(executable), "--version"], capture_output=True, text=True, check=False,
        )
        if version.returncode or f"Tor version {LOCK['tor_version']} " not in version.stdout:
            raise ValueError("verified Tor binary did not run at its pinned version")
        payload.rename(output)
    return {
        "tor_executable": str(output / "tor" / "tor"),
        "bundle_sha256": LOCK["bundle_sha256"],
        "signing_key_primary_fingerprint": LOCK["signing_key_primary_fingerprint"],
        "tor_version": LOCK["tor_version"],
        "distribution_channel": LOCK["distribution_channel"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--signature", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.output, args.archive, args.signature), indent=2))


if __name__ == "__main__":
    main()
