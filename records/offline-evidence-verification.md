# Offline evidence integration record

Date: 2026-09-25. This extends the completed M0 foundation with local Intel hardware-evidence inspection. It does not complete M1 or authorize a private query, cloud deployment or spending.

## Implementation

`zrpc inspect-quote --quote FILE --collateral FILE` verifies exact binary quote bytes and supplied signed collateral at the current system clock. The integration pins `dcap-qvl` 0.6.3 with its Ring and maintained X.509 backends, Intel's production root, and no fetch or dangerous TCB-override feature. `serde_json` is pinned to 1.0.149 to satisfy the verifier's declared requirement. All resolved package versions and registry checksums are committed in `Cargo.lock`.

The report separates hardware authenticity from strict security policy. Workload identity, freshness and live-key binding remain unchecked; `private_accepted`, `query_sent` and `network_used` remain false. The report cannot construct the genuine channel capability. There is no runtime historical-time or root override, and upstream error strings and unique platform identifiers are not emitted.

The genuine historical quote and collateral come from upstream commit `e61f4fba357e96d68fc7d7be71635049841824fb`, with license, source paths and hashes preserved in `tests/fixtures/dcap/`. The original quote contains 70 trailing zero bytes. The exact derivative contains the 4936 bytes consumed and reproduced by the maintained decoder/encoder; a test proves that relationship. Production inspection rejects padding. Historical validity is exercised only inside unit tests; the public CLI rejects this expired evidence using today's clock.

## Verification

Execution used the managed untrusted browser container on `aarch64-unknown-linux-gnu`, Rust/Cargo 1.94.1. No claim of an x86 guest boot or TDX hardware execution follows from local verification of an Intel signature chain.

- `cargo fmt --all -- --check`: passed.
- `python3 scripts/check-verifier-features.py`: passed; pins/checksums/fixture hashes and native dependency graph checked. Fetch and override features are absent. This is a source/build guard, not syscall-level network instrumentation.
- `cargo test --locked --workspace`: **39 unit tests and 5 compile-fail tests passed**. The six new verifier tests cover authentic historical hardware evidence, expired/not-yet-valid collateral, modified report data and signed collateral, malformed/truncated/appended/provider-asserted evidence, fixture derivation, and strict policy rejection. Mutated policy-unit claims are explicitly not re-signed quotes.
- `cargo build --locked -p zrpc-cli --bins --examples`: passed.
- `python3 scripts/cli-check.py`: passed, including expired current-clock inspection and rejection of a historical-time override. Existing private-before-input refusal and lifecycle checks passed.
- `node scripts/browser-check.cjs`: passed after the shared JSON dependency update; desktop/mobile screenshots inspected. The UI still uses the simulation core and same-origin loopback APIs.
- User-docs boundary scanner and `git diff --check`: passed.
- Independent exact-source review of the offline verifier and CLI reported no findings.

Build identifiers (local debug artifacts, not signed release provenance):

```text
ab8ec63ba95aa5d2affef6df8116cec88e66aaae8f5d976885c22be1b70f19b9  target/debug/zrpc
fa2e8f2b573c52f191cbbe16f6deae7600d443cd2b07d7546ddfb79f15d02c79  Cargo.lock
```

## Remaining boundaries

The RPC path, dashboard evidence and provider cleanup remain simulated. There is no live Tor/TLS transport, workload-event verification, selected production image/KMS tuple, cloud adapter or external deletion job. Gates A–E remain unresolved. No provider resources were created or charged by this work.

Source investigation found the default dstack v0.5.11 persistent Docker/containerd/sysbox runtime layout incompatible with the design's public-chain-data-only persistence rule; details and limits are in `gate-d-source-analysis.md`. The operator selected further investigation of a measured early-boot ephemeral-runtime configuration. That choice is not deployment authorization or approval of an untested configuration.

## Next local command

```sh
cd /Users/j/Code/phala-zcash-rpc
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --command cargo run --locked -p zrpc-cli -- inspect-quote --quote tests/fixtures/dcap/tdx_quote.exact.bin --collateral tests/fixtures/dcap/tdx_quote_collateral.json
```

Expected result: a single JSON report rejecting expired collateral, `private_accepted: false`, and exit status 1. This performs no cloud action.
