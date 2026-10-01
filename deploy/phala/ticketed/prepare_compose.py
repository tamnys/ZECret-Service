#!/usr/bin/env python3
"""Prepare the ticket-required Phala CVM update without exposing issuer keys."""

import argparse
import hashlib
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREVIOUS = HERE.parent / "releases/2026-10-01/block-context-app-compose.json"
PREVIOUS_SHA256 = "e882001ca06686552edcc94f1e1f423b34866223ff0fcdc68087ec2e29de72a6"
PREVIOUS_INNER_SHA256 = "c82117629ad2a63e885c95e03f97ecbe701233adf21d73964918c875f02719a5"
PREVIOUS_IMAGE = (
    "ghcr.io/tamnys/zecret-service-preview@sha256:"
    "a73f032681a26f8b2cb960cd32f355c478612e49ae657b5ca656f2b105fb4d78"
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
        raise ValueError("previous Phala launch identity differs")
    outer = json.loads(previous_bytes)
    old_inner = outer["docker_compose_file"].encode("ascii")
    if digest(old_inner) != PREVIOUS_INNER_SHA256 or outer["allowed_envs"] != []:
        raise ValueError("previous Phala compose identity differs")
    inner = json.loads(old_inner)
    if set(inner["services"]) != {"app", "quote"} or inner["services"]["app"]["image"] != PREVIOUS_IMAGE:
        raise ValueError("previous Phala service set differs")
    app = inner["services"]["app"]
    app["image"] = image_ref
    app["command"] = ["ticketed-app"]
    app["volumes"].append({"source": "spent_tickets", "target": "/var/lib/zrpc-spent", "type": "volume"})
    issuer = {
        "image": image_ref,
        "platform": "linux/amd64",
        "command": ["issuer"],
        "user": "10003:0",
        "read_only": True,
        "restart": "no",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "logging": {"driver": "none"},
        "ulimits": {"core": 0},
        "tmpfs": [
            "/run:rw,nosuid,nodev,noexec,mode=1775",
            "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        ],
        "environment": [f"{name}=${{{name}}}" for name in SECRETS],
        "volumes": [{"source": "issuer_tickets", "target": "/var/lib/zrpc-issuer", "type": "volume"}],
    }
    inner["services"]["issuer"] = issuer
    inner["volumes"]["spent_tickets"] = {}
    inner["volumes"]["issuer_tickets"] = {}
    inner_bytes = canonical(inner)
    outer["docker_compose_file"] = inner_bytes.decode("ascii")
    outer["allowed_envs"] = list(SECRETS)
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
