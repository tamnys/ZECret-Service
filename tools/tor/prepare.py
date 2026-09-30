#!/usr/bin/env python3
"""Verify and stage pinned Tor Project Debian Tor without installing it."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen


HERE = Path(__file__).resolve().parent
LOCK_FILE = HERE / "package.lock.json"
LOCK = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
# Operator-approved local age exception for this exact Tor 0.4.9.13 lock only.
LOCAL_AGE_EXCEPTION_LOCK_SHA256 = "02cf93295cc3cb9b554a2d7d388b526f2916bd78c30ec7529376f2bfbe59c8f0"
SIGNING_KEY = HERE / "tor-debian-signing-key.asc"
INRELEASE = HERE / "trixie.InRelease"
PACKAGES = HERE / "trixie-arm64-Packages.gz"


def require_release_age(
    now: datetime | None = None, *, allow_v04913_local_hold_exception: bool = False
) -> bool:
    published = datetime.fromisoformat(
        LOCK["package_last_modified_utc"].replace("Z", "+00:00")
    )
    eligible = published + timedelta(days=LOCK["minimum_age_days"])
    if (now or datetime.now(timezone.utc)) < eligible:
        if not allow_v04913_local_hold_exception:
            raise ValueError(f"pinned Tor package is inside the release hold until {eligible.isoformat()}")
        if (file_sha256(LOCK_FILE) != LOCAL_AGE_EXCEPTION_LOCK_SHA256
                or LOCK["tor_version"] != "0.4.9.13"
                or LOCK["architecture"] != "arm64"):
            raise ValueError("local age exception does not match the reviewed Tor lock")
        return True
    return False


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_hash(path: Path, expected: str) -> None:
    if file_sha256(path) != expected:
        raise ValueError(f"pinned SHA-256 mismatch: {path.name}")


def verify_signed_release(scratch: Path) -> str:
    require_hash(SIGNING_KEY, LOCK["repository_signing_key_sha256"])
    require_hash(INRELEASE, LOCK["inrelease_sha256"])
    home = scratch / "gnupg"
    home.mkdir(mode=0o700)
    key = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--with-colons", "--fingerprint",
         "--show-keys", str(SIGNING_KEY)],
        capture_output=True, text=True, check=False,
    )
    if key.returncode:
        raise ValueError("pinned Tor Debian signing key could not be inspected")
    primary_fingerprints = []
    expecting_primary = False
    for line in key.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            expecting_primary = True
        elif fields[0] == "fpr" and expecting_primary:
            primary_fingerprints.append(fields[9])
            expecting_primary = False
    fingerprint = LOCK["repository_signing_key_primary_fingerprint"]
    if primary_fingerprints != [fingerprint]:
        raise ValueError("Tor Debian signing key has the wrong primary fingerprint")
    imported = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--import", str(SIGNING_KEY)],
        capture_output=True, text=True, check=False,
    )
    if imported.returncode:
        raise ValueError("pinned Tor Debian signing key could not be imported")
    verified = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--no-auto-key-retrieve",
         "--status-fd", "2", "--decrypt", str(INRELEASE)],
        capture_output=True, text=True, check=False,
    )
    signatures = [
        line.split()
        for line in verified.stderr.splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    if (verified.returncode or len(signatures) != 1
            or fingerprint not in (signatures[0][2], signatures[0][-1])):
        raise ValueError("Tor Debian InRelease signature did not validate")
    return verified.stdout


def signed_index_identity(release: str, now: datetime | None = None) -> tuple[str, int]:
    if "Origin: TorProject\n" not in release or "Codename: trixie\n" not in release:
        raise ValueError("signed Tor Debian release has the wrong origin or suite")
    valid_until = [line.partition(": ")[2] for line in release.splitlines()
                   if line.startswith("Valid-Until: ")]
    if len(valid_until) != 1 or (now or datetime.now(timezone.utc)) > parsedate_to_datetime(valid_until[0]):
        raise ValueError("signed Tor Debian release is expired or has no validity bound")
    matches = []
    in_sha256 = False
    for line in release.splitlines():
        if line == "SHA256:":
            in_sha256 = True
            continue
        if in_sha256 and not line.startswith(" "):
            break
        if in_sha256:
            fields = line.split()
            if len(fields) == 3 and fields[2] == "main/binary-arm64/Packages.gz":
                matches.append((fields[0], int(fields[1])))
    if len(matches) != 1:
        raise ValueError("signed Tor Debian release does not identify one arm64 package index")
    return matches[0]


def package_stanza(index: str) -> dict[str, str]:
    matches = []
    for paragraph in index.split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) or ": " not in line:
                continue
            name, value = line.split(": ", 1)
            if name in fields:
                raise ValueError("Tor Debian package index has a duplicate field")
            fields[name] = value
        if fields.get("Package") == LOCK["package"]:
            matches.append(fields)
    if len(matches) != 1:
        raise ValueError("Tor Debian package index does not identify one Tor package")
    return matches[0]


def verify_metadata(scratch: Path, now: datetime | None = None) -> None:
    release = verify_signed_release(scratch)
    signed_hash, signed_size = signed_index_identity(release, now)
    require_hash(PACKAGES, LOCK["packages_gz_sha256"])
    if PACKAGES.stat().st_size != signed_size or file_sha256(PACKAGES) != signed_hash:
        raise ValueError("Tor Debian package index does not match signed InRelease")
    fields = package_stanza(gzip.decompress(PACKAGES.read_bytes()).decode("utf-8"))
    expected = {
        "Package": LOCK["package"],
        "Version": LOCK["version"],
        "Architecture": LOCK["architecture"],
        "Filename": LOCK["package_path"],
        "Size": str(LOCK["package_size"]),
        "SHA256": LOCK["package_sha256"],
    }
    if any(fields.get(name) != value for name, value in expected.items()):
        raise ValueError("signed Tor Debian package identity differs from the pin")


def copy_pinned(source, destination: Path, expected_size: int) -> None:
    with destination.open("xb") as target:
        remaining = expected_size
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("pinned Tor package download ended early")
            target.write(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise ValueError("pinned Tor package download exceeded its recorded size")


def require_tor_version(stdout: str, returncode: int) -> None:
    first_line = stdout.splitlines()[0] if stdout else ""
    reported_version = first_line.removeprefix("Tor version ").split(" ", 1)[0].removesuffix(".")
    if returncode or not first_line.startswith("Tor version ") or reported_version != LOCK["tor_version"]:
        raise ValueError("verified Tor binary did not run at its pinned version")


def extract_tor_binary(deb: Path, scratch: Path, executable: Path) -> None:
    """Extract only the executable from the already authenticated package."""
    archive_path = scratch / "payload.tar"
    with archive_path.open("xb") as archive_output:
        archive = subprocess.run(
            ["dpkg-deb", "--fsys-tarfile", str(deb)],
            stdout=archive_output, stderr=subprocess.PIPE, text=True, check=False,
        )
    if archive.returncode:
        raise ValueError("verified Tor Debian package payload could not be read")
    with tarfile.open(archive_path, mode="r:") as payload:
        matches = [member for member in payload.getmembers()
                   if member.name in ("./usr/bin/tor", "usr/bin/tor")]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size == 0:
            raise ValueError("verified Tor Debian package has no unique regular Tor executable")
        source = payload.extractfile(matches[0])
        if source is None:
            raise ValueError("verified Tor Debian package executable could not be read")
        with source, executable.open("xb") as target:
            shutil.copyfileobj(source, target)
        if executable.stat().st_size != matches[0].size:
            raise ValueError("verified Tor executable length differs from package metadata")
    executable.chmod(0o755)


def stage(
    output: Path, package: Path | None, *, allow_v04913_local_hold_exception: bool = False
) -> dict[str, str | bool]:
    hold_exception_used = require_release_age(
        allow_v04913_local_hold_exception=allow_v04913_local_hold_exception
    )
    if platform.system() != "Linux" or platform.machine() not in ("aarch64", "arm64"):
        raise ValueError("pinned Tor Debian package requires Linux arm64")
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists; refusing to replace a local Tor installation")
    if not output.is_absolute() or not output.parent.is_dir():
        raise ValueError("--output must be absolute with an existing parent directory")
    with tempfile.TemporaryDirectory(prefix=".tor-prepare-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        verify_metadata(scratch)
        deb = scratch / "tor.deb"
        if package is None:
            with urlopen(LOCK["repository_url"] + LOCK["package_path"]) as source:
                copy_pinned(source, deb, LOCK["package_size"])
        else:
            if package.stat().st_size != LOCK["package_size"]:
                raise ValueError("local Tor package has the wrong size")
            shutil.copyfile(package, deb)
        require_hash(deb, LOCK["package_sha256"])
        staged = scratch / "staged"
        staged.mkdir(mode=0o755)
        bin_dir = staged / "bin"
        bin_dir.mkdir(mode=0o755)
        executable = bin_dir / "tor"
        extract_tor_binary(deb, scratch, executable)
        version = subprocess.run(
            [str(executable), "--version"], capture_output=True, text=True, check=False,
        )
        require_tor_version(version.stdout, version.returncode)
        staged.rename(output)
    return {
        "tor_executable": str(output / "bin" / "tor"),
        "package_sha256": LOCK["package_sha256"],
        "repository_signing_key_primary_fingerprint": LOCK["repository_signing_key_primary_fingerprint"],
        "tor_version": LOCK["tor_version"],
        "local_release_age_exception_used": hold_exception_used,
        "package_lock_sha256": file_sha256(LOCK_FILE),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--allow-v04913-local-hold-exception", action="store_true")
    args = parser.parse_args()
    print(json.dumps(stage(
        args.output, args.package,
        allow_v04913_local_hold_exception=args.allow_v04913_local_hold_exception,
    ), indent=2))


if __name__ == "__main__":
    main()
