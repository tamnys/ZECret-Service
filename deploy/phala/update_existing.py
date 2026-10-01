#!/usr/bin/env python3
"""Guarded, in-place update of the one tracked Phala preview CVM.

This operator tool never creates a CVM, changes its resources, or approves a
client release. The apply operation requires the original live Compose hash,
an exact checked candidate, and a durable intent before its sole PATCH call.
"""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import sys
from datetime import datetime, timezone


HOST = "cloud-api.phala.com"
WORKSPACE = "wks_1w8ro7eo"
CVM = "cvm_MeD4o0eQ"
APP = "5af400d6c4fd5312a9b9693fe0988d5bdc0ee726"
VM_UUID = "05decd53-6a57-4b1d-97f5-ecff44749040"
OLD_COMPOSE_SHA256 = "1e8f93e57803ea348cdf9fbbf9843d2851049ef9cec98d5c1237f71a4857058c"
OFFICIAL_SCRIPT_SHA256 = "982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8"
IMAGE = "ghcr.io/tamnys/zecret-service-preview@sha256:446598032ba76a8ec4302392b0f634786908aead2b4a53ee8206cbaeff48bd48"
APP_COMPOSE_SHA256 = "58d237b45dc5f577e258b2a7955d7695ee42f1399a098903afc89ad1b9688672"
INNER_COMPOSE_SHA256 = "08d28abce233b2701ad8156663dd5d2f569494a032951f7cc0f18b2572ac5212"
BODY_LIMIT = 1_048_576  # Operator-approved management response cap.
CANDIDATE = Path(__file__).resolve().parent / "candidates/2026-10-01"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def decode_json(data):
    def reject_constant(_value):
        raise ValueError("nonfinite JSON value")

    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def checked_candidate():
    receipt = decode_json((CANDIDATE / "receipt.json").read_bytes())
    app = (CANDIDATE / "app-compose.json").read_bytes()
    compose = (CANDIDATE / "compose.json").read_bytes()
    manifest = decode_json(app)
    inner = decode_json(compose)
    if (digest(app) != APP_COMPOSE_SHA256
            or digest(compose) != INNER_COMPOSE_SHA256
            or receipt["app_compose_file_sha256"] != APP_COMPOSE_SHA256
            or receipt["docker_compose_file_sha256"] != INNER_COMPOSE_SHA256
            or receipt["image_ref"] != IMAGE
            or receipt["private_accepted"] is not False
            or receipt["deployment_enabled"] is not False
            or manifest["docker_compose_file"].encode() != compose
            or manifest["public_logs"] is not False
            or manifest["public_sysinfo"] is not False
            or set(inner["services"]) != {"app", "quote"}
            or any(service["image"] != IMAGE
                   for service in inner["services"].values())):
        raise ValueError("checked launch candidate differs")
    return receipt, compose


def checked_token(path):
    if not path.is_absolute():
        raise ValueError("token path must be an absolute regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ValueError("token file permissions must exclude group and others")
        token = os.read(descriptor, 1025).strip()
    finally:
        os.close(descriptor)
    if not token.startswith(b"phak_") or len(token) > 1024:
        raise ValueError("Phala workspace token unavailable")
    return token.decode("ascii")


class Api:
    def __init__(self, token):
        self.token = token
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3

    def request(self, method, path, body=None):
        connection = http.client.HTTPSConnection(HOST, context=self.context,
                                                timeout=20)
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "X-API-Key": self.token,
            "X-Phala-Version": "2026-06-23",
            "X-Phala-Workspace": WORKSPACE,
        }
        if body is not None:
            headers["Content-Type"] = "text/yaml"
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(BODY_LIMIT + 1)
            if len(data) > BODY_LIMIT:
                raise ValueError("management response exceeds approved 1 MiB cap")
            if response.status not in (200, 202):
                raise ValueError(f"Phala management HTTP {response.status}")
            parsed = decode_json(data) if data else {}
            if not isinstance(parsed, dict):
                raise ValueError("Phala management response is not an object")
            return response.status, data, parsed
        finally:
            connection.close()


def validate_current(detail, compose, expected_compose_sha256):
    if (detail.get("id") != CVM or detail.get("app_id") != APP
            or detail.get("vm_uuid") != VM_UUID
            or detail.get("status") != "running"):
        raise ValueError("existing CVM identity or status differs")
    script = compose.get("pre_launch_script")
    if (compose.get("public_logs") is not False
            or compose.get("public_sysinfo") is not False
            or not isinstance(script, str)
            or digest(script.encode()) != OFFICIAL_SCRIPT_SHA256
            or not isinstance(compose.get("docker_compose_file"), str)
            or digest(compose["docker_compose_file"].encode())
            != expected_compose_sha256):
        raise ValueError("existing CVM launch configuration differs")


def durable_new(path, data):
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    durable_bytes(path, encoded)


def durable_bytes(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("apply", "observe"))
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt, desired = checked_candidate()
        token = checked_token(args.token_file)
        if (not args.state_dir.is_absolute() or args.state_dir.is_symlink()
                or not args.state_dir.is_dir()
                or args.state_dir.stat().st_mode & 0o077):
            raise ValueError("private existing state directory required")
        original = decode_json((args.state_dir / "original.json").read_bytes())
        binding = original.get("binding", {})
        if (binding.get("workspace_id") != WORKSPACE
                or binding.get("experiment_id")
                != "PHALA_PUBLIC_PREVIEW_20260930_ONE"
                or binding.get("total_ceiling_microusd") != 50_000_000
                or binding.get("deletion_deadline_unix_seconds") != 1_791_404_615
                or not (args.state_dir / "ledger").is_dir()):
            raise ValueError("original experiment ledger binding differs")
        api = Api(token)
        _, _, detail = api.request("GET", f"/api/v1/cvms/{CVM}")
        _, raw, compose = api.request("GET", f"/api/v1/cvms/{CVM}/compose_file")
        expected = (OLD_COMPOSE_SHA256 if args.operation == "apply"
                    else INNER_COMPOSE_SHA256)
        validate_current(detail, compose, expected)
        if args.operation == "observe":
            # Save full provider launch bytes privately for later independent
            # workload review. Never print scripts, credentials or the token.
            observation = args.state_dir / "trusted-update-readback.json"
            durable_bytes(observation, raw)
            print(json.dumps({"operation": "observe", "cvm_id": CVM,
                              "compose_sha256": digest(raw),
                              "inner_compose_sha256": expected,
                              "private_accepted": False}))
            return 0
        intent = args.state_dir / "trusted-update-intent.json"
        durable_new(intent, {
            "cvm_id": CVM,
            "app_id": APP,
            "vm_uuid": VM_UUID,
            "old_inner_compose_sha256": OLD_COMPOSE_SHA256,
            "new_inner_compose_sha256": receipt["docker_compose_file_sha256"],
            "candidate_app_compose_sha256": receipt["app_compose_file_sha256"],
            "preflight_readback_sha256": digest(raw),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "operation": "update_existing_only",
        })
        status, response_raw, response = api.request(
            "PATCH", f"/api/v1/cvms/{CVM}/docker-compose", desired)
        if response.get("status") == "precondition_required":
            raise ValueError("KMS update requires unimplemented on-chain step")
        durable_new(args.state_dir / "trusted-update-outcome.json", {
            "http_status": status,
            "response_sha256": digest(response_raw),
            "provider_status": response.get("status"),
            "correlation_id": response.get("correlation_id"),
            "private_accepted": False,
        })
        if status != 202 or response.get("status") != "in_progress":
            raise ValueError("update outcome uncertain; inspect the recorded intent and provider state")
        print(json.dumps({"operation": "apply", "cvm_id": CVM,
                          "http_status": status,
                          "provider_status": response.get("status"),
                          "private_accepted": False}))
        return 0
    except (OSError, UnicodeError, KeyError, TypeError, ValueError,
            json.JSONDecodeError, ssl.SSLError,
            http.client.HTTPException) as error:
        print(json.dumps({"operation": args.operation, "status": "blocked",
                          "reason": str(error), "private_accepted": False}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
