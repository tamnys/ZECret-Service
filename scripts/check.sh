#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
python3 scripts/check-verifier-features.py
cargo test --locked --workspace
cargo build --locked -p zrpc-cli --bins --examples
cargo build --locked -p zrpc-server --bins
python3 scripts/cli-check.py
python3 scripts/public-inspection-check.py
python3 scripts/wrapper-check.py
python3 experiments/ephemeral-runtime/test-launch-profile.py
python3 experiments/ephemeral-runtime/test-rootfs-source.py
mkdir -p .codex-tmp
rustc --edition=2021 --test experiments/ephemeral-runtime/runtime-guard.rs -o .codex-tmp/runtime-guard-tests
.codex-tmp/runtime-guard-tests
rustc --edition=2021 experiments/ephemeral-runtime/runtime-guard.rs -o .codex-tmp/runtime-guard
if [[ "${1:-}" == "--browser" ]]; then
  node scripts/browser-check.cjs
fi
