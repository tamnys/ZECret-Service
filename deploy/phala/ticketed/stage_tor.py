#!/usr/bin/env python3
"""Stage only the signed Tor expert-bundle files used by the issuer sidecar."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
LOCK = json.loads((HERE / "tor-expert.lock.json").read_text(encoding="ascii"))
SELECTED = {
    "tor/tor": 0o555,
    "tor/libcrypto.so.3": 0o444,
    "tor/libevent-2.1.so.7": 0o444,
    "tor/libssl.so.3": 0o444,
    "data/geoip": 0o444,
    "data/geoip6": 0o444,
    "data/torrc-defaults": 0o444,
    "docs/libevent.txt": 0o444,
    "docs/openssl.txt": 0o444,
    "docs/tor.txt": 0o444,
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_hash(path, expected):
    if not path.is_file() or path.is_symlink() or sha256(path) != expected:
        raise ValueError(f"pinned input unavailable: {path.name}")


def verify_signature(archive, signature, key, scratch):
    inspect = subprocess.run(
        ["gpg", "--batch", "--no-default-keyring", "--show-keys", "--with-colons", str(key)],
        capture_output=True, text=True, check=False,
    )
    primary = []
    expecting = False
    for line in inspect.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            expecting = True
        elif fields[0] == "fpr" and expecting:
            primary.append(fields[9])
            expecting = False
    if inspect.returncode or primary != [LOCK["signing_key_primary_fingerprint"]]:
        raise ValueError("Tor signing key fingerprint differs from the pin")
    home = scratch / "gnupg"
    home.mkdir(mode=0o700)
    imported = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--import", str(key)],
        capture_output=True, check=False,
    )
    if imported.returncode:
        raise ValueError("Tor signing key import failed")
    verified = subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--no-auto-key-retrieve",
         "--status-fd", "1", "--verify", str(signature), str(archive)],
        capture_output=True, text=True, check=False,
    )
    signatures = [line.split() for line in verified.stdout.splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    if (verified.returncode or len(signatures) != 1
            or signatures[0][-1] != LOCK["signing_key_primary_fingerprint"]):
        raise ValueError("Tor expert-bundle signature rejected")


def stage(archive, signature, key, output, now=None):
    if set(LOCK) != {
        "schema", "release", "architecture", "published_utc", "minimum_age_days",
        "archive_url", "archive_sha256", "signature_url", "signature_sha256",
        "signing_key_url", "signing_key_sha256", "signing_key_primary_fingerprint",
    } or LOCK["schema"] != 1 or LOCK["architecture"] != "linux-x86_64":
        raise ValueError("Tor lock schema or target changed")
    published = datetime.fromisoformat(LOCK["published_utc"].replace("Z", "+00:00"))
    if (now or datetime.now(timezone.utc)) < published + timedelta(days=LOCK["minimum_age_days"]):
        raise ValueError("Tor expert bundle remains inside the release hold")
    for path, expected in ((archive, LOCK["archive_sha256"]),
                           (signature, LOCK["signature_sha256"]),
                           (key, LOCK["signing_key_sha256"])):
        require_hash(path, expected)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("fresh absolute Tor staging directory required")
    with tempfile.TemporaryDirectory(prefix=".tor-expert-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        verify_signature(archive, signature, key, scratch)
        staged = scratch / "stage"
        staged.mkdir()
        found = set()
        with tarfile.open(archive, mode="r:gz") as bundle:
            for member in bundle:
                name = PurePosixPath(member.name)
                if (name.is_absolute() or ".." in name.parts or
                        not (member.isfile() or member.isdir())):
                    raise ValueError("unsafe Tor expert-bundle member")
                if member.name not in SELECTED:
                    continue
                if not member.isfile() or member.name in found or member.size <= 0:
                    raise ValueError("Tor expert-bundle member differs from the pin")
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("Tor expert-bundle member unavailable")
                target = staged / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as destination:
                    copied = 0
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        destination.write(block)
                        copied += len(block)
                if copied != member.size:
                    raise ValueError("Tor expert-bundle member length changed")
                target.chmod(SELECTED[member.name])
                found.add(member.name)
        if found != set(SELECTED):
            raise ValueError("Tor expert bundle is missing required files")
        tor = staged / "tor/tor"
        with tor.open("rb") as binary:
            if binary.read(20)[:5] != b"\x7fELF\x02" or binary.seek(18) != 18 or binary.read(2) != b"\x3e\x00":
                raise ValueError("Tor executable is not Linux x86_64 ELF")
        receipt = {
            "schema": 1,
            "release": LOCK["release"],
            "archive_sha256": LOCK["archive_sha256"],
            "files_sha256": {name: sha256(staged / name) for name in sorted(SELECTED)},
        }
        (staged / "receipt.json").write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii"
        )
        staged.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.archive, args.signature, args.signing_key, args.output),
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
