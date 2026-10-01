#!/usr/bin/env python3
"""Prepare local, unapproved split-service inputs for a corrected Phala guest.

The output is source input only. It does not build, admit or deploy an image.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT / ".codex-tmp"
SOURCE = Path(__file__).with_name("prepare-image-source.py")
spec = importlib.util.spec_from_file_location("phala_guest_source", SOURCE)
guest_source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest_source)

RUNTIME_KEYS = {
    "node_startup_timeout_secs": "NODE_STARTUP_TIMEOUT_SECS",
    "node_poll_interval_ms": "NODE_POLL_INTERVAL_MS",
    "max_connections": "MAX_CONNECTIONS",
    "max_quotes": "MAX_QUOTES",
    "quote_spacing_ms": "QUOTE_SPACING_MS",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def positive_int(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("positive decimal integer required")
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("positive decimal integer required") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("positive decimal integer required")
    return number


def workspace_input(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("system configuration must be an absolute, non-symlink workspace file")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(ROOT):
        raise ValueError("system configuration must stay inside the workspace")
    return path


def system_bytes(path: Path) -> bytes:
    path = workspace_input(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("system configuration must be a regular file")
        payload = source.read(32 * 1024 + 1)
    if len(payload) > 32 * 1024:
        raise ValueError("system configuration exceeds pinned dstack copy bound")
    if guest_source.sys_config_digest(path) != hashlib.sha256(payload).digest():
        raise ValueError("system configuration changed while being prepared")
    return payload


def output_path(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute output path without parent traversal required")
    if SCRATCH.is_symlink():
        raise ValueError("workspace scratch directory cannot be a symlink")
    SCRATCH.mkdir(mode=0o700, exist_ok=True)
    if (not SCRATCH.is_dir() or not path.parent.is_dir()
            or not path.parent.resolve(strict=True).is_relative_to(SCRATCH.resolve(strict=True))
            or path.exists() or path.is_symlink()):
        raise ValueError("fresh output directory under workspace .codex-tmp required")
    return path


def split_compose(image: str, runtime: dict[str, int]) -> bytes:
    if set(runtime) != set(RUNTIME_KEYS) or any(
        type(value) is not int or value <= 0 for value in runtime.values()
    ):
        raise ValueError("all split runtime values must be explicit positive integers")
    environment = {env: str(runtime[arg]) for arg, env in RUNTIME_KEYS.items()}
    node = copy.deepcopy(guest_source.SPLIT_COMMON)
    node.update({
        "image": image,
        "command": ["node"],
        "environment": {"NODE_POLL_INTERVAL_MS": environment["NODE_POLL_INTERVAL_MS"]},
        "healthcheck": {"test": ["CMD", "python3", "/opt/zrpc/supervisor.py", "node-health"]},
        "ports": ["8443:8443"],
        "volumes": copy.deepcopy(guest_source.SPLIT_NODE_VOLUMES),
    })
    wrapper = copy.deepcopy(guest_source.SPLIT_COMMON)
    wrapper.update({
        "image": image,
        "command": ["wrapper"],
        "depends_on": {"node": {"condition": "service_healthy"}},
        "environment": environment,
        "network_mode": "service:node",
        "volumes": copy.deepcopy(guest_source.SPLIT_WRAPPER_VOLUMES),
    })
    payload = canonical({"services": {"node": node, "wrapper": wrapper}})
    guest_source.validate_compose_file(payload.decode("ascii"))
    return payload


def launch_bytes(name: str, kms_identity: str, compose: bytes) -> bytes:
    if not isinstance(name, str) or not name or not isinstance(kms_identity, str) or not kms_identity:
        raise ValueError("explicit launch name and KMS identity required")
    profile = {
        "manifest_version": 2,
        "name": name,
        "runner": "docker-compose",
        "docker_compose_file": compose.decode("ascii"),
        "storage_fs": "ext4",
        "storage_encrypted": True,
        "swap_size": 0,
        "key_provider": "kms",
        "key_provider_id": kms_identity,
        "kms_enabled": True,
        "tproxy_enabled": True,
        "public_logs": False,
        "public_sysinfo": False,
        "public_tcbinfo": False,
        "allowed_envs": [],
        "port_policy": {"restrict_mode": True,
                        "ports": [{"port": 8443, "pp": False}]},
    }
    return canonical(profile) + b"\n"


def write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


def prepare(image: str, name: str, kms_identity: str, runtime: dict[str, int],
            sys_config: Path, output: Path) -> dict[str, object]:
    sys_payload = system_bytes(sys_config)
    compose = split_compose(image, runtime)
    launch = launch_bytes(name, kms_identity, compose)
    output = output_path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    write_exclusive(output / "docker-compose.json", compose + b"\n")
    write_exclusive(output / "app-compose.json", launch)
    write_exclusive(output / "sys-config.json", sys_payload)
    launch_digest, sys_digest = guest_source.bound_digests(
        output / "app-compose.json", output / "sys-config.json")
    manifest = {
        "schema_version": 1,
        "status": "local_source_only_unapproved",
        "application_image": image,
        "application_image_reviewed": False,
        "docker_compose_sha256": hashlib.sha256(compose + b"\n").hexdigest(),
        "launch_config_sha256": launch_digest.hex(),
        "sys_config_sha256": sys_digest.hex(),
        "guest_image_built": False,
        "phala_admission_verified": False,
        "private_accepted": False,
        "cloud_resources_created_by_this_tool": 0,
    }
    write_exclusive(output / "bundle-manifest.json", canonical(manifest) + b"\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", required=True,
                        help="application image pinned by sha256 digest; provenance is reviewed separately")
    parser.add_argument("--name", required=True)
    parser.add_argument("--key-provider-id", required=True)
    parser.add_argument("--sys-config", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    for argument in RUNTIME_KEYS:
        parser.add_argument("--" + argument.replace("_", "-"), required=True,
                            type=positive_int)
    args = parser.parse_args()
    runtime = {key: getattr(args, key) for key in RUNTIME_KEYS}
    try:
        prepare(args.image_ref, args.name, args.key_provider_id, runtime,
                args.sys_config, args.output_dir)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print("Local launch bundle only; image build, Phala admission and private acceptance remain blocked.")


if __name__ == "__main__":
    main()
