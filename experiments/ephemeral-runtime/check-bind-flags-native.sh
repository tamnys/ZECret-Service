#!/usr/bin/env bash
# Native Linux syntax/effect probe for the corrected guest's VFS bind flags.
# The filesystem is synthetic tmpfs; this does not test Phala TDX or KMS.
set -euo pipefail

if [[ "${1:-}" == "--inside" ]]; then
    base="$2"
    data="$base/data"
    target="$base/target"
    cleanup() {
        if mountpoint -q "$target"; then umount "$target"; fi
        if mountpoint -q "$data"; then umount "$data"; fi
    }
    trap cleanup EXIT
    mount -t tmpfs -o mode=0700 tmpfs "$data"
    mkdir -m 0700 "$data/zebra-public-testnet"
    mount -o remount,rw,noexec,nodev,nosuid,nosymfollow "$data"
    mount --bind "$data/zebra-public-testnet" "$target"
    mount -o remount,bind,rw,noexec,nodev,nosuid,nosymfollow "$target"
    ln -s /etc/passwd "$target/poisoned-link"
    python3 -I - "$data" "$target" <<'PY'
import os
from pathlib import Path
import sys

for point in map(Path, sys.argv[1:]):
    rows = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
            if line.split()[4] == str(point)]
    if len(rows) != 1:
        raise SystemExit(f"expected one native mount at {point}")
    options = set(rows[0][5].split(","))
    if not {"rw", "noexec", "nodev", "nosuid", "nosymfollow"} <= options:
        raise SystemExit(f"missing native VFS flags at {point}")
try:
    os.stat(Path(sys.argv[2]) / "poisoned-link")
except OSError:
    pass
else:
    raise SystemExit("native bind followed a poisoned symlink")
print("Native bind flags and nosymfollow effect verified; synthetic filesystem")
PY
    exit 0
fi

test "$#" -eq 0
workspace="${GITHUB_WORKSPACE:?}/source/.codex-tmp"
mkdir -p "$workspace"
base=$(mktemp -d "$workspace/bind-flags.XXXXXX")
mkdir "$base/data" "$base/target"
trap 'rmdir "$base/data" "$base/target" "$base"' EXIT
sudo -n unshare --mount --propagation private bash "$0" --inside "$base"
