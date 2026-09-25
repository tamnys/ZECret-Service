#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
python3 scripts/check-verifier-features.py
cargo test --locked --workspace
cargo build --locked -p zrpc-cli --bins --examples
python3 scripts/cli-check.py
if [[ "${1:-}" == "--browser" ]]; then
  node scripts/browser-check.cjs
fi
