#!/usr/bin/env python3
"""Update only the tracked Phala CVM to the checked block-context image."""

import argparse
import http.client
import json
import ssl
from datetime import datetime, timezone
from pathlib import Path

from update_existing import (
    APP, CVM, VM_UUID, WORKSPACE, Api, checked_token, decode_json, digest,
    durable_bytes, durable_new, validate_current,
)

OLD_LAUNCH = "76a8e40e01a5ce4b77a2582db1f6e5aed6eb0e6ae789f83ae8941c57149849fe"
OLD_COMPOSE = "08d28abce233b2701ad8156663dd5d2f569494a032951f7cc0f18b2572ac5212"
NEW_COMPOSE = "c82117629ad2a63e885c95e03f97ecbe701233adf21d73964918c875f02719a5"
OLD_IMAGE = "ghcr.io/tamnys/zecret-service-preview@sha256:446598032ba76a8ec4302392b0f634786908aead2b4a53ee8206cbaeff48bd48"
NEW_IMAGE = "ghcr.io/tamnys/zecret-service-preview@sha256:a73f032681a26f8b2cb960cd32f355c478612e49ae657b5ca656f2b105fb4d78"
CANDIDATE = Path(__file__).resolve().parent / "candidates/2026-10-01-block-context"
RELEASE = Path(__file__).resolve().parent / "releases/2026-10-01/app-compose.json"


def checked_candidate():
    source = RELEASE.read_bytes()
    if digest(source) != OLD_LAUNCH:
        raise ValueError("reviewed previous launch bytes differ")
    previous = decode_json(source)["docker_compose_file"].encode()
    desired = (CANDIDATE / "compose.json").read_bytes()
    receipt = decode_json((CANDIDATE / "receipt.json").read_bytes())
    if (digest(previous) != OLD_COMPOSE or digest(desired) != NEW_COMPOSE
            or receipt.get("old_launch_sha256") != OLD_LAUNCH
            or receipt.get("old_compose_sha256") != OLD_COMPOSE
            or receipt.get("new_compose_sha256") != NEW_COMPOSE
            or receipt.get("old_image") != OLD_IMAGE
            or receipt.get("new_image") != NEW_IMAGE
            or receipt.get("new_resources") is not False):
        raise ValueError("block-context candidate identity differs")
    old = decode_json(previous)
    new = decode_json(desired)
    if set(old["services"]) != {"app", "quote"} or set(new["services"]) != {"app", "quote"}:
        raise ValueError("service set differs")
    for name in ("app", "quote"):
        if old["services"][name].get("image") != OLD_IMAGE or new["services"][name].get("image") != NEW_IMAGE:
            raise ValueError("image reference differs")
        new["services"][name]["image"] = OLD_IMAGE
    if new != old:
        raise ValueError("candidate changes more than the two image references")
    return desired


def checked_state(path):
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.stat().st_mode & 0o077):
        raise ValueError("private original experiment directory required")
    original = decode_json((path / "original.json").read_bytes())
    binding = original.get("binding", {})
    if (binding.get("workspace_id") != WORKSPACE
            or binding.get("experiment_id") != "PHALA_PUBLIC_PREVIEW_20260930_ONE"
            or binding.get("total_ceiling_microusd") != 50_000_000
            or binding.get("deletion_deadline_unix_seconds") != 1_791_404_615
            or not (path / "ledger").is_dir()):
        raise ValueError("original experiment ledger binding differs")


def inspect(api, expected_compose):
    _, _, detail = api.request("GET", f"/api/v1/cvms/{CVM}")
    _, raw, launch = api.request("GET", f"/api/v1/cvms/{CVM}/compose_file")
    validate_current(detail, launch, expected_compose)
    return detail, raw, launch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("apply", "observe"))
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        desired = checked_candidate()
        checked_state(args.state_dir)
        api = Api(checked_token(args.token_file))
        expected = OLD_COMPOSE if args.operation == "apply" else NEW_COMPOSE
        detail, raw, launch = inspect(api, expected)
        if args.operation == "observe":
            observed = args.state_dir / "block-context-launch-readback.json"
            durable_bytes(observed, raw)
            print(json.dumps({"operation": "observe", "cvm_id": CVM,
                              "status": detail["status"],
                              "launch_sha256": digest(raw),
                              "inner_compose_sha256": NEW_COMPOSE,
                              "image": NEW_IMAGE, "private_accepted": False}))
            return 0
        if digest(raw) != OLD_LAUNCH:
            raise ValueError("existing full launch bytes differ")
        if (args.state_dir / "block-context-update-outcome.json").exists():
            raise ValueError("update outcome already recorded; do not repeat")
        durable_new(args.state_dir / "block-context-update-intent.json", {
            "operation": "update_existing_only", "cvm_id": CVM,
            "app_id": APP, "vm_uuid": VM_UUID,
            "old_launch_sha256": OLD_LAUNCH,
            "old_inner_compose_sha256": OLD_COMPOSE,
            "new_inner_compose_sha256": NEW_COMPOSE,
            "new_image": NEW_IMAGE,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        status, response_raw, response = api.request(
            "PATCH", f"/api/v1/cvms/{CVM}/docker-compose", desired)
        durable_new(args.state_dir / "block-context-update-outcome.json", {
            "http_status": status, "response_sha256": digest(response_raw),
            "provider_status": response.get("status"),
            "correlation_id": response.get("correlation_id"),
            "private_accepted": False,
        })
        if status != 202 or response.get("status") != "in_progress":
            raise ValueError("update outcome uncertain; inspect receipt and provider")
        print(json.dumps({"operation": "apply", "cvm_id": CVM,
                          "http_status": status, "provider_status": "in_progress",
                          "new_inner_compose_sha256": NEW_COMPOSE,
                          "private_accepted": False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            json.JSONDecodeError, ssl.SSLError, http.client.HTTPException) as error:
        print(json.dumps({"operation": args.operation, "status": "blocked",
                          "reason": str(error), "private_accepted": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
