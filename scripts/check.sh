#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
python3 scripts/check-verifier-features.py
python3 scripts/test_reproduce_release.py
cargo test --locked --workspace
cargo build --locked -p zrpc-cli --bins --examples
cargo build --locked -p zrpc-server --bins
cargo build --locked -p zrpc-lifecycle --bins
"${CARGO_TARGET_DIR:-target}/debug/zrpc-gcp-lifecycle" --help >/dev/null
python3 scripts/cli-check.py
python3 scripts/public-inspection-check.py
python3 scripts/public-inspection-check.py --platform gcp-tdx
python3 scripts/wrapper-check.py
python3 tools/gcp-guest/test_prepare.py
python3 tools/gcp-guest/test_export_rust_inputs.py
python3 tools/gcp-guest/test_audit_initrd.py
python3 tools/gcp-guest/test_gcp_import_archive.py
python3 tools/gcp-guest/test_inspect_import_toolchain.py
python3 tools/gcp-guest/test_verify_mkosi_source.py
python3 tools/gcp-guest/test_verify_mkosi_tree.py
python3 tools/gcp-guest/test_verify_mkosi_payload.py
python3 tools/gcp-guest/test_verify_package_closure.py
python3 tools/gcp-guest/test_fetch_guest_closure.py
python3 tools/gcp-guest/test_verify_builder_packages.py
python3 tools/gcp-guest/test_verify_builder_closure.py
python3 tools/gcp-guest/test_stage_builder_toolchain.py
python3 tools/gcp-guest/test_inspect_raw_gpt.py
python3 tools/gcp-guest/test_inspect_raw_esp.py
python3 tools/gcp-guest/test_inspect_raw_verity.py
python3 experiments/ephemeral-runtime/test-launch-profile.py
python3 experiments/ephemeral-runtime/test-rootfs-source.py
python3 experiments/ephemeral-runtime/test-packaging-source.py
mkdir -p .codex-tmp
rustc --edition=2021 --test experiments/ephemeral-runtime/runtime-guard.rs -o .codex-tmp/runtime-guard-tests
.codex-tmp/runtime-guard-tests
rustc --edition=2021 experiments/ephemeral-runtime/runtime-guard.rs -o .codex-tmp/runtime-guard
if [[ "${1:-}" == "--browser" ]]; then
  node scripts/browser-check.cjs
fi
