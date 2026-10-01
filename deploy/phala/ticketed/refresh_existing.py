#!/usr/bin/env python3
"""Guard an in-place image refresh of the existing ticketed Phala CVM."""

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import ssl
import http.client
import tempfile


HERE = Path(__file__).resolve().parent
ticket_spec = importlib.util.spec_from_file_location("ticket_update", HERE / "update_existing.py")
ticket_update = importlib.util.module_from_spec(ticket_spec)
ticket_spec.loader.exec_module(ticket_update)
refresh_spec = importlib.util.spec_from_file_location("refresh_compose", HERE / "refresh_compose.py")
refresh_compose = importlib.util.module_from_spec(refresh_spec)
refresh_spec.loader.exec_module(refresh_compose)
updater = ticket_update.updater


def checked_candidate(directory):
    if (not directory.is_absolute() or directory.is_symlink()
            or not directory.resolve().is_relative_to(refresh_compose.ROOT)):
        raise ValueError("candidate must stay on the workspace volume")
    receipt = updater.decode_json((directory / "receipt.json").read_bytes())
    outer_bytes = (directory / "app-compose.json").read_bytes()
    inner_bytes = (directory / "compose.json").read_bytes()
    with tempfile.TemporaryDirectory(prefix=".ticket-refresh-check-", dir=directory.parent) as temporary:
        expected_dir = Path(temporary) / "expected"
        expected = refresh_compose.prepare(receipt.get("new_image"), expected_dir)
        if (receipt != expected or outer_bytes != (expected_dir / "app-compose.json").read_bytes()
                or inner_bytes != (expected_dir / "compose.json").read_bytes()):
            raise ValueError("ticketed refresh differs from reviewed construction")
    return receipt, updater.decode_json(outer_bytes)


def run(args):
    ticket_update.budget.checked_state(args.state_dir)
    receipt, candidate = checked_candidate(args.candidate_dir)
    api = ticket_update.JsonApi(updater.checked_token(args.token_file))
    expected_inner = (receipt["new_compose_sha256"] if args.operation == "observe"
                      else refresh_compose.PREVIOUS_INNER_SHA256)
    detail, raw, _ = ticket_update.current(api, expected_inner)
    if args.operation == "observe":
        if ticket_update.digest(raw) != receipt["new_launch_sha256"]:
            raise ValueError("refreshed launch readback differs")
        updater.durable_bytes(args.state_dir / "blockcount-launch-readback.json", raw)
        print(json.dumps({"operation": "observe", "status": detail["status"],
                          "cvm_id": updater.CVM, "launch_sha256": ticket_update.digest(raw)}))
        return
    if ticket_update.digest(raw) != refresh_compose.PREVIOUS_SHA256:
        raise ValueError("current Phala launch differs from approved ticketed release")
    sealed = ticket_update.checked_secret_state(args, detail)
    if args.operation == "inspect":
        print(json.dumps({"operation": "inspect", "cvm_id": updater.CVM,
                          "status": detail["status"],
                          "current_launch_sha256": ticket_update.digest(raw),
                          "candidate_launch_sha256": receipt["new_launch_sha256"],
                          "sealed_env_sha256": args.sealed_env_sha256}))
        return
    intent = args.state_dir / "blockcount-update-intent.json"
    outcome = args.state_dir / "blockcount-update-outcome.json"
    if intent.exists() or outcome.exists():
        raise ValueError("ticketed refresh was already attempted; inspect provider state")
    updater.durable_new(intent, {"operation": "ticketed_image_refresh",
                                "cvm_id": updater.CVM, "app_id": updater.APP,
                                "old_launch_sha256": ticket_update.digest(raw),
                                "new_launch_sha256": receipt["new_launch_sha256"],
                                "new_image": receipt["new_image"],
                                "sealed_env_sha256": args.sealed_env_sha256,
                                "created_at": datetime.now(timezone.utc).isoformat()})
    status, _, provision = api.request_json(
        "POST", f"/api/v1/cvms/{updater.CVM}/compose_file/provision",
        {**candidate, "update_env_vars": True})
    if (status != 200 or provision.get("compose_hash") != receipt["new_launch_sha256"]
            or provision.get("app_id") != updater.APP):
        raise ValueError("Phala provisioned a different refreshed launch")
    updater.durable_new(args.state_dir / "blockcount-provision.json",
                        {"status": status, "compose_hash": provision["compose_hash"],
                         "app_id": provision["app_id"]})
    status, response_raw, response = api.request_json(
        "PATCH", f"/api/v1/cvms/{updater.CVM}/compose_file",
        {"compose_hash": receipt["new_launch_sha256"], "encrypted_env": sealed,
         "env_keys": list(refresh_compose.SECRETS), "update_env_vars": True})
    if response is None:
        response = {}
    if not isinstance(response, dict):
        raise ValueError("Phala ticketed refresh returned an unexpected response")
    updater.durable_new(outcome, {"http_status": status,
                                 "response_sha256": ticket_update.digest(response_raw),
                                 "provider_status": response.get("status"),
                                 "correlation_id": response.get("correlation_id")})
    if status != 202:
        raise ValueError("Phala ticketed refresh outcome is uncertain")
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
