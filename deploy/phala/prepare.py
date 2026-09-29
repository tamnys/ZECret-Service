#!/usr/bin/env python3
"""Offline, unapproved packaging inputs for a stock Phala public testnet preview."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
STOCK_LOCK = HERE / "stock-candidate.lock.json"
ZEBRA_LOCK = ROOT / "deploy/gcp/zebra-release.lock.json"
STOCK_LOCK_SHA256 = "76361686948794ad56b571c7ef640110d47c79d68618c960148c414286d01510"
IMAGE_REF = re.compile(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_json(path):
    def reject_nonfinite(_value):
        raise ValueError("nonfinite JSON")

    return json.loads(regular_bytes(path), object_pairs_hook=unique_object,
                      parse_constant=reject_nonfinite)


def regular_bytes(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular non-symlink input required")
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UTC timestamp required")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def locks():
    stock = read_json(STOCK_LOCK)
    zebra_bytes = regular_bytes(ZEBRA_LOCK)
    zebra = read_json(ZEBRA_LOCK)
    if (digest(regular_bytes(STOCK_LOCK)) != STOCK_LOCK_SHA256
            or stock.get("schema_version") != 1
            or stock.get("status") != "observed-stock-candidate-unapproved"
            or stock.get("os_image_sha256") !=
            "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
            or stock.get("kms_catalog_id") != "kms_opjg1KBD"
            or stock.get("zebra_release_lock_sha256") != digest(zebra_bytes)
            or stock.get("private_accepted") is not False
            or stock.get("deployment_enabled") is not False
            or zebra.get("status") != "reviewed-metadata-only-unapproved"
            or zebra.get("tag") != "v6.4.2"
            or zebra.get("minimum_age_days") != 7
            or zebra.get("asset", {}).get("sha256") !=
            "505cab2c616dac1a5bc1c414716206a775f38f41ca6f70a60729df40c29e7b8b"):
        raise ValueError("stock or Zebra identity differs from reviewed candidate")
    return stock, zebra, digest(zebra_bytes)


def eligibility(zebra, now=None):
    now = now or datetime.now(timezone.utc)
    eligible_at = utc(zebra["asset"]["created_at"]) + timedelta(
        days=zebra["minimum_age_days"])
    return now >= eligible_at, eligible_at


def inside_workspace(path):
    path = Path(path)
    if not path.is_absolute() or not path.resolve().is_relative_to(ROOT):
        raise ValueError("input and output must stay on the workspace volume")
    return path


def fresh_output(path):
    path = inside_workspace(path)
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("fresh output directory required")
    return path


def checked_elf(path, expected_sha256, expected_size=None):
    path = inside_workspace(path)
    data = regular_bytes(path)
    if (not SHA256.fullmatch(expected_sha256) or digest(data) != expected_sha256
            or (expected_size is not None and len(data) != expected_size)
            or len(data) < 20 or data[:6] != b"\x7fELF\x02\x01"
            or data[16:18] not in (b"\x02\x00", b"\x03\x00")
            or data[18:20] != b"\x3e\x00"):
        raise ValueError("x86_64 ELF differs from supplied reviewed identity")
    return data


def image_context(args):
    stock, zebra, lock_digest = locks()
    eligible, eligible_at = eligibility(zebra)
    if not eligible:
        raise ValueError(f"Zebra release hold ends {eligible_at.isoformat()}")
    if not IMAGE_REF.fullmatch(args.base_image):
        raise ValueError("immutable base image reference required")
    if datetime.now(timezone.utc) < utc(args.base_image_created_at) + timedelta(days=7):
        raise ValueError("base image is inside the seven-day hold")
    stage = inside_workspace(args.zebra_stage)
    receipt = read_json(stage / "receipt.json")
    if (receipt.get("status") != "staged-diagnostic-unapproved"
            or receipt.get("release_lock_sha256") != lock_digest
            or receipt.get("asset_sha256") != zebra["asset"]["sha256"]
            or receipt.get("zebrad_elf_sha256") != zebra["zebrad_elf_sha256"]
            or receipt.get("zebrad_elf_size") != zebra["zebrad_elf_size"]
            or type(receipt.get("verified_attestation_count")) is not int
            or receipt["verified_attestation_count"] < 1
            or zebra["zebrad_elf_sha256"] is None
            or zebra["zebrad_elf_size"] is None):
        raise ValueError("Zebra staging receipt is missing or unreviewed")
    binaries = {
        "zebrad": checked_elf(stage / "zebrad", zebra["zebrad_elf_sha256"],
                              zebra["zebrad_elf_size"]),
        "zrpc-node-wrapper": checked_elf(args.node_wrapper,
                                         args.node_wrapper_sha256),
        "zrpc-quote-proxy": checked_elf(args.quote_proxy,
                                        args.quote_proxy_sha256),
    }
    template = regular_bytes(HERE / "image/Dockerfile.in").decode("ascii")
    prefix = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
    if not template.startswith(prefix):
        raise ValueError("image recipe changed")
    dockerfile = ("FROM " + args.base_image + "\n" + template[len(prefix):]).encode()
    output = fresh_output(args.output)
    output.mkdir()
    (output / "bin").mkdir()
    (output / "state").mkdir()
    for name, data in binaries.items():
        destination = output / "bin" / name
        destination.write_bytes(data)
        destination.chmod(0o555)
    for name in ("supervisor.py", "zebra.toml"):
        (output / name).write_bytes(regular_bytes(HERE / "image" / name))
    (output / "state/.keep").write_bytes(b"")
    (output / "Dockerfile").write_bytes(dockerfile)
    result = {
        "schema_version": 1,
        "status": "local-image-context-unapproved",
        "base_image": args.base_image,
        "base_image_created_at": args.base_image_created_at,
        "stock_os_image_sha256": stock["os_image_sha256"],
        "stock_candidate_lock_sha256": STOCK_LOCK_SHA256,
        "zebra_release_lock_sha256": lock_digest,
        "zebra_asset_sha256": zebra["asset"]["sha256"],
        "binaries_sha256": {name: digest(data) for name, data in binaries.items()},
        "dockerfile_sha256": digest(dockerfile),
        "private_accepted": False,
        "deployment_enabled": False,
    }
    (output / "image-inputs.json").write_bytes(canonical(result))
    return result


def runtime_config(path):
    value = read_json(inside_workspace(path))
    required = {"quote_startup_timeout_secs", "node_startup_timeout_secs",
                "node_poll_interval_ms", "max_connections", "max_quotes",
                "quote_spacing_ms"}
    if (not isinstance(value, dict) or set(value) != required
            or any(type(value[name]) is not int or value[name] <= 0 for name in required)):
        raise ValueError("explicit positive runtime limits required")
    return value


def launch_documents(args):
    stock, zebra, lock_digest = locks()
    eligible, eligible_at = eligibility(zebra)
    if not eligible:
        raise ValueError(f"Zebra release hold ends {eligible_at.isoformat()}")
    if not IMAGE_REF.fullmatch(args.image):
        raise ValueError("immutable application image reference required")
    inputs_path = inside_workspace(args.image_inputs)
    inputs_bytes = regular_bytes(inputs_path)
    inputs = read_json(inputs_path)
    if (inputs.get("status") != "local-image-context-unapproved"
            or inputs.get("zebra_release_lock_sha256") != lock_digest
            or inputs.get("zebra_asset_sha256") != zebra["asset"]["sha256"]
            or inputs.get("stock_os_image_sha256") != stock["os_image_sha256"]
            or inputs.get("stock_candidate_lock_sha256") != STOCK_LOCK_SHA256
            or inputs.get("private_accepted") is not False
            or inputs.get("deployment_enabled") is not False):
        raise ValueError("image context receipt differs from reviewed inputs")
    limits = runtime_config(args.runtime)
    base = {
        "image": args.image, "platform": "linux/amd64", "read_only": True,
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "logging": {"driver": "none"}, "restart": "no",
        "volumes": [{"type": "volume", "source": "runtime_tmpfs", "target": "/run"}],
    }
    quote = {
        **base, "user": "10002:0", "command": ["quote"],
        "network_mode": "none",
        "environment": {
            "QUOTE_STARTUP_TIMEOUT_SECS": str(limits["quote_startup_timeout_secs"]),
        },
        "volumes": base["volumes"] + [{
            "type": "bind", "source": "/run/dstack.sock", "target": "/run/dstack.sock",
            "read_only": True, "bind": {"create_host_path": False},
        }],
        "healthcheck": {
            "test": ["CMD", "python3", "/opt/zrpc/supervisor.py", "quote-health"],
        },
    }
    app = {
        **base, "user": "10001:0", "command": ["app"],
        "environment": {
            "NODE_STARTUP_TIMEOUT_SECS": str(limits["node_startup_timeout_secs"]),
            "NODE_POLL_INTERVAL_MS": str(limits["node_poll_interval_ms"]),
            "MAX_CONNECTIONS": str(limits["max_connections"]),
            "MAX_QUOTES": str(limits["max_quotes"]),
            "QUOTE_SPACING_MS": str(limits["quote_spacing_ms"]),
        },
        "ports": ["8443:8443"],
        "volumes": base["volumes"] + [{
            "type": "volume", "source": "zebra_public_testnet",
            "target": "/var/lib/zebra",
        }],
        "depends_on": {"quote": {"condition": "service_healthy"}},
    }
    compose = {
        "services": {"quote": quote, "app": app},
        "volumes": {
            "runtime_tmpfs": {"driver": "local", "driver_opts": {
                "type": "tmpfs", "device": "tmpfs", "o": "uid=0,gid=0,mode=1775",
            }},
            "zebra_public_testnet": {},
        },
    }
    compose_bytes = canonical(compose)
    app_compose = {
        "manifest_version": 2,
        "name": "zrpc-public-testnet-preview",
        "runner": "docker-compose",
        "docker_compose_file": compose_bytes.decode("ascii"),
        "storage_fs": "ext4",
        "swap_size": 0,
        "key_provider": "kms",
        "kms_enabled": True,
        "tproxy_enabled": True,
        "public_logs": False,
        "public_sysinfo": False,
        "allowed_envs": [],
    }
    app_bytes = canonical(app_compose)
    output = fresh_output(args.output)
    output.mkdir()
    (output / "compose.json").write_bytes(compose_bytes)
    (output / "app-compose.json").write_bytes(app_bytes)
    result = {
        "schema_version": 1,
        "status": "local-launch-document-unapproved",
        "stock_os_image_sha256": stock["os_image_sha256"],
        "stock_candidate_lock_sha256": STOCK_LOCK_SHA256,
        "kms_catalog_id": stock["kms_catalog_id"],
        "zebra_release_lock_sha256": lock_digest,
        "image_ref": args.image,
        "image_inputs_sha256": digest(inputs_bytes),
        "docker_compose_file_sha256": digest(compose_bytes),
        "app_compose_file_sha256": digest(app_bytes),
        "tls_passthrough_port": 8443,
        "private_accepted": False,
        "deployment_enabled": False,
        "cloud_calls": False,
    }
    (output / "receipt.json").write_bytes(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    image = commands.add_parser("image-context")
    image.add_argument("--zebra-stage", required=True, type=Path)
    image.add_argument("--node-wrapper", required=True, type=Path)
    image.add_argument("--node-wrapper-sha256", required=True)
    image.add_argument("--quote-proxy", required=True, type=Path)
    image.add_argument("--quote-proxy-sha256", required=True)
    image.add_argument("--base-image", required=True)
    image.add_argument("--base-image-created-at", required=True)
    image.add_argument("--output", required=True, type=Path)
    launch = commands.add_parser("launch-documents")
    launch.add_argument("--image", required=True)
    launch.add_argument("--image-inputs", required=True, type=Path)
    launch.add_argument("--runtime", required=True, type=Path)
    launch.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        stock, zebra, _ = locks()
        if args.command == "status":
            eligible, eligible_at = eligibility(zebra)
            result = {
                "status": "age-eligible-artifacts-still-unapproved" if eligible
                else "held-artifacts-unapproved",
                "stock_os_image_sha256": stock["os_image_sha256"],
                "stock_candidate_lock_sha256": STOCK_LOCK_SHA256,
                "kms_catalog_id": stock["kms_catalog_id"],
                "zebra_asset_sha256": zebra["asset"]["sha256"],
                "zebra_eligible_at_utc": eligible_at.isoformat().replace("+00:00", "Z"),
                "zebra_elf_identity_pinned": zebra["zebrad_elf_sha256"] is not None,
                "private_accepted": False,
                "deployment_enabled": False,
                "cloud_calls": False,
            }
        elif args.command == "image-context":
            result = image_context(args)
        else:
            result = launch_documents(args)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "private_accepted": False, "deployment_enabled": False,
                          "cloud_calls": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
