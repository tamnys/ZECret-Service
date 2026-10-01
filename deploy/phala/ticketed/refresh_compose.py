#!/usr/bin/env python3
"""Prepare an image-only refresh of the approved ticketed Phala launch."""

import argparse
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREVIOUS = HERE.parent / "releases/2026-10-01/ticketed-app-compose.json"
PREVIOUS_SHA256 = "30104d0b60ee54988d8e45d36abc68249af52e5d113c22f7001d10d0841b84f5"
PREVIOUS_INNER_SHA256 = "54a7a1a4f2f968ef4f63c75e076fbe05468149ae38f40a86aeebd360c2098337"
PREVIOUS_IMAGE = (
    "ghcr.io/tamnys/zecret-service-preview@sha256:"
    "03040e2358b862a9c4b36296898f3574368205f85c7f806bb71a1299bcc7e94d"
)
IMAGE = re.compile(r"ghcr\.io/tamnys/zecret-service-preview@sha256:[0-9a-f]{64}\Z")
SECRETS = ("ZRPC_ISSUER_PRIVATE_DER_B64", "ZRPC_ONION_SECRET_KEY_B64")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def prepare(image_ref, output):
    if not IMAGE.fullmatch(image_ref) or image_ref == PREVIOUS_IMAGE:
        raise ValueError("new pinned ticket image required")
    if (not output.is_absolute() or not output.resolve().is_relative_to(ROOT)
            or output.exists() or output.is_symlink() or not output.parent.is_dir()):
        raise ValueError("fresh output directory on workspace volume required")
    previous_bytes = PREVIOUS.read_bytes()
    if digest(previous_bytes) != PREVIOUS_SHA256:
        raise ValueError("previous ticketed launch identity differs")
    outer = json.loads(previous_bytes)
    old_inner = outer["docker_compose_file"].encode("ascii")
    if (digest(old_inner) != PREVIOUS_INNER_SHA256
            or outer["allowed_envs"] != list(SECRETS)
            or outer["public_logs"] is not False
            or outer["public_sysinfo"] is not False):
        raise ValueError("previous ticketed launch configuration differs")
    inner = json.loads(old_inner)
    if (set(inner["services"]) != {"app", "quote", "issuer"}
            or any(inner["services"][name]["image"] != PREVIOUS_IMAGE
                   for name in ("app", "issuer"))):
        raise ValueError("previous ticketed service set differs")
    for name in ("app", "issuer"):
        inner["services"][name]["image"] = image_ref
    inner_bytes = canonical(inner)
    outer["docker_compose_file"] = inner_bytes.decode("ascii")
    outer_bytes = canonical(outer)
    output.mkdir()
    (output / "compose.json").write_bytes(inner_bytes)
    (output / "app-compose.json").write_bytes(outer_bytes)
    receipt = {
        "schema": 1,
        "previous_launch_sha256": PREVIOUS_SHA256,
        "previous_compose_sha256": PREVIOUS_INNER_SHA256,
        "new_launch_sha256": digest(outer_bytes),
        "new_compose_sha256": digest(inner_bytes),
        "previous_image": PREVIOUS_IMAGE,
        "new_image": image_ref,
        "secret_names": list(SECRETS),
    }
    (output / "receipt.json").write_bytes(canonical(receipt) + b"\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.image_ref, args.output), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
