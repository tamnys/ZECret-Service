#!/usr/bin/env python3
"""Guarded in-place update of the tracked Phala CVM to ticket-required mode."""

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
updater_spec = importlib.util.spec_from_file_location("phala_updater", HERE.parent / "update_existing.py")
updater = importlib.util.module_from_spec(updater_spec)
updater_spec.loader.exec_module(updater)
sys.modules["update_existing"] = updater
budget_spec = importlib.util.spec_from_file_location("phala_budget", HERE.parent / "update_block_context.py")
budget = importlib.util.module_from_spec(budget_spec)
budget_spec.loader.exec_module(budget)
compose_spec = importlib.util.spec_from_file_location("ticket_compose", HERE / "prepare_compose.py")
ticket_compose = importlib.util.module_from_spec(compose_spec)
compose_spec.loader.exec_module(ticket_compose)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_file(path):
    if not path.is_absolute():
        raise ValueError("absolute private file required")
    item = path.lstat()
    if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) & 0o077):
        raise ValueError("owner-private regular file required")
    return path.read_bytes()


class JsonApi(updater.Api):
    def request_json(self, method, path, document):
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        connection = http.client.HTTPSConnection(updater.HOST, context=self.context)
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
            "X-API-Key": self.token,
            "X-Phala-Version": "2026-06-23",
            "X-Phala-Workspace": updater.WORKSPACE,
        }
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(updater.BODY_LIMIT + 1)
            if len(raw) > updater.BODY_LIMIT:
                raise ValueError("Phala management response exceeds reviewed limit")
            if response.status not in (200, 202):
                raise ValueError(f"Phala management HTTP {response.status}")
            return response.status, raw, updater.decode_json(raw) if raw else {}
        finally:
            connection.close()


def checked_candidate(directory):
    if (not directory.is_absolute() or directory.is_symlink()
            or not directory.resolve().is_relative_to(ROOT)):
        raise ValueError("candidate must stay on the workspace volume")
    receipt = updater.decode_json((directory / "receipt.json").read_bytes())
    outer_bytes = (directory / "app-compose.json").read_bytes()
    inner_bytes = (directory / "compose.json").read_bytes()
    with tempfile.TemporaryDirectory(prefix=".ticket-compose-check-", dir=directory.parent) as temporary:
        checked = Path(temporary) / "expected"
        expected = ticket_compose.prepare(receipt.get("new_image"), checked)
        if (receipt != expected or outer_bytes != (checked / "app-compose.json").read_bytes()
                or inner_bytes != (checked / "compose.json").read_bytes()):
            raise ValueError("ticketed candidate differs from reviewed construction")
    outer = updater.decode_json(outer_bytes)
    inner = updater.decode_json(inner_bytes)
    if (receipt.get("schema") != 1
            or receipt.get("previous_launch_sha256") != ticket_compose.PREVIOUS_SHA256
            or receipt.get("new_launch_sha256") != digest(outer_bytes)
            or receipt.get("new_compose_sha256") != digest(inner_bytes)
            or receipt.get("secret_names") != list(ticket_compose.SECRETS)
            or outer.get("docker_compose_file", "").encode("ascii") != inner_bytes
            or outer.get("allowed_envs") != list(ticket_compose.SECRETS)
            or outer.get("public_logs") is not False
            or outer.get("public_sysinfo") is not False
            or set(inner.get("services", {})) != {"app", "quote", "issuer"}
            or inner["services"]["app"].get("command") != ["ticketed-app"]
            or inner["services"]["issuer"].get("command") != ["issuer"]
            or inner["services"]["quote"].get("image") != ticket_compose.PREVIOUS_IMAGE
            or any(inner["services"][name].get("image") != receipt.get("new_image")
                   for name in ("app", "issuer"))):
        raise ValueError("ticketed candidate differs from reviewed construction")
    return receipt, outer


def checked_secret_state(args, detail):
    pubkey = private_file(args.kms_pubkey_file).decode("ascii").strip().removeprefix("0x")
    current = ((detail.get("kms_info") or {}).get("encrypted_env_pubkey")
               or detail.get("encrypted_env_pubkey"))
    if (detail.get("kms_type") != "phala" or not isinstance(current, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", pubkey)
            or pubkey.lower() != current.removeprefix("0x").lower()):
        raise ValueError("Phala KMS encryption key changed")
    sealed = private_file(args.sealed_env_file).decode("ascii").strip()
    if (not re.fullmatch(r"[0-9a-f]+", sealed) or len(sealed) <= (32 + 12 + 16) * 2
            or digest(sealed.encode()) != args.sealed_env_sha256):
        raise ValueError("sealed issuer environment differs")
    return sealed


def current(api, expected_inner):
    _, _, detail = api.request("GET", f"/api/v1/cvms/{updater.CVM}")
    _, raw, launch = api.request("GET", f"/api/v1/cvms/{updater.CVM}/compose_file")
    updater.validate_current(detail, launch, expected_inner)
    return detail, raw, launch


def run(args):
    budget.checked_state(args.state_dir)
    receipt, candidate = checked_candidate(args.candidate_dir)
    api = JsonApi(updater.checked_token(args.token_file))
    expected_inner = (ticket_compose.PREVIOUS_INNER_SHA256 if args.operation != "observe"
                      else receipt["new_compose_sha256"])
    detail, raw, _ = current(api, expected_inner)
    if args.operation == "observe":
        if digest(raw) != receipt["new_launch_sha256"]:
            raise ValueError("ticketed launch readback differs")
        updater.durable_bytes(args.state_dir / "ticketed-launch-readback.json", raw)
        print(json.dumps({"operation": "observe", "status": detail["status"],
                          "cvm_id": updater.CVM, "launch_sha256": digest(raw)}))
        return
    if digest(raw) != ticket_compose.PREVIOUS_SHA256:
        raise ValueError("current Phala launch differs from approved predecessor")
    sealed = checked_secret_state(args, detail)
    if args.operation == "inspect":
        print(json.dumps({"operation": "inspect", "cvm_id": updater.CVM,
                          "status": detail["status"],
                          "current_launch_sha256": digest(raw),
                          "candidate_launch_sha256": receipt["new_launch_sha256"],
                          "sealed_env_sha256": args.sealed_env_sha256}))
        return
    intent = args.state_dir / "ticketed-update-intent.json"
    outcome = args.state_dir / "ticketed-update-outcome.json"
    if intent.exists() or outcome.exists():
        raise ValueError("ticketed update was already attempted; inspect provider state")
    updater.durable_new(intent, {"operation": "ticketed_in_place_update",
                                "cvm_id": updater.CVM, "app_id": updater.APP,
                                "old_launch_sha256": digest(raw),
                                "new_launch_sha256": receipt["new_launch_sha256"],
                                "new_image": receipt["new_image"],
                                "sealed_env_sha256": args.sealed_env_sha256,
                                "created_at": datetime.now(timezone.utc).isoformat()})
    status, _, provision = api.request_json(
        "POST", f"/api/v1/cvms/{updater.CVM}/compose_file/provision",
        {**candidate, "update_env_vars": True})
    if (status != 200 or provision.get("compose_hash") != receipt["new_launch_sha256"]
            or provision.get("app_id") != updater.APP):
        raise ValueError("Phala provisioned a different ticketed launch")
    updater.durable_new(args.state_dir / "ticketed-provision.json",
                        {"status": status, "compose_hash": provision["compose_hash"],
                         "app_id": provision["app_id"]})
    status, response_raw, response = api.request_json(
        "PATCH", f"/api/v1/cvms/{updater.CVM}/compose_file",
        {"compose_hash": receipt["new_launch_sha256"], "encrypted_env": sealed,
         "env_keys": list(ticket_compose.SECRETS), "update_env_vars": True})
    updater.durable_new(outcome, {"http_status": status,
                                 "response_sha256": digest(response_raw),
                                 "provider_status": response.get("status"),
                                 "correlation_id": response.get("correlation_id")})
    if status != 202:
        raise ValueError("Phala ticketed update outcome is uncertain")
    print(json.dumps({"operation": "apply", "http_status": status,
                      "cvm_id": updater.CVM,
                      "new_launch_sha256": receipt["new_launch_sha256"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inspect", "apply", "observe"))
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--kms-pubkey-file", type=Path)
    parser.add_argument("--sealed-env-file", type=Path)
    parser.add_argument("--sealed-env-sha256")
    args = parser.parse_args()
    if args.operation != "observe" and not all((args.kms_pubkey_file, args.sealed_env_file,
                                                  args.sealed_env_sha256)):
        parser.error("issuer key inputs are required before inspection or apply")
    try:
        run(args)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            json.JSONDecodeError, ssl.SSLError, http.client.HTTPException) as error:
        print(json.dumps({"operation": args.operation, "status": "blocked",
                          "reason": str(error)}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
