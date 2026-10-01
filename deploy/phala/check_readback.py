#!/usr/bin/env python3
"""Compare a caller-supplied Phala compose readback with prepared launch bytes.

This offline diagnostic does not authenticate its stdin or approve a release.
Provider responses may contain startup scripts and configuration secrets, so
only fixed field names, lengths, and digests appear in its output.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys


# The operator approved a 1 MiB cap for each Phala management API response.
MAX_INPUT_BYTES = 1_048_576
FIELDS = (
    "manifest_version", "runner", "docker_compose_file", "storage_fs",
    "kms_enabled", "tproxy_enabled", "gateway_enabled", "no_instance_id",
    "public_logs", "public_sysinfo", "public_tcbinfo", "pre_launch_script",
    "allowed_envs",
)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse_object(data):
    if not data or len(data) > MAX_INPUT_BYTES:
        raise ValueError("input length outside approved bound")

    def reject_constant(_value):
        raise ValueError("nonfinite JSON value")

    value = json.loads(data, object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def read_candidate(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate must be a regular non-symlink file")
    with path.open("rb") as source:
        data = source.read(MAX_INPUT_BYTES + 1)
    return data, parse_object(data)


def value_digest(value):
    if not isinstance(value, str):
        return None
    encoded = value.encode("utf-8")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def compare(candidate_bytes, candidate, readback_bytes, readback):
    status = {}
    for field in FIELDS:
        if field not in candidate:
            status[field] = "added" if field in readback else "absent"
        elif field not in readback:
            status[field] = "missing"
        else:
            status[field] = "match" if candidate[field] == readback[field] else "changed"
    unknown = (set(candidate) | set(readback)) - set(FIELDS)
    return {
        "mode": "offline_compose_readback_comparison",
        "readback_provenance": "caller_supplied_unverified",
        "exact_manifest_match": candidate_bytes == readback_bytes,
        "semantic_manifest_match": candidate == readback,
        "private_accepted": False,
        "provider_mutations_performed": False,
        "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
        "readback_sha256": hashlib.sha256(readback_bytes).hexdigest(),
        "field_status": status,
        "other_field_count": len(unknown),
        "candidate_docker_compose": value_digest(candidate.get("docker_compose_file")),
        "readback_docker_compose": value_digest(readback.get("docker_compose_file")),
        "readback_pre_launch_script": value_digest(readback.get("pre_launch_script")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    args = parser.parse_args()
    try:
        candidate_bytes, candidate = read_candidate(args.candidate)
        readback_bytes = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        readback = parse_object(readback_bytes)
        result = compare(candidate_bytes, candidate, readback_bytes, readback)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        print(json.dumps({"mode": "offline_compose_readback_comparison",
                          "error": "invalid or oversized input",
                          "private_accepted": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["exact_manifest_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
