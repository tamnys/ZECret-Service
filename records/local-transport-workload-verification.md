# Local transport and workload follow-through

Scope: continue authorized local M0 work after the read-only account inspection, without deployment, paid resources, account changes or external messages. Private-mode authority remains unavailable.

## Implemented boundaries

`zrpc inspect-workload` first uses the existing Intel production-root verifier and strict TDX policy. Its crate-private callback receives immutable authenticated claims only after those checks pass. The workload inspector replays every runtime event with maintained dstack code, compares authenticated MRTD/RTMR0/RTMR1/RTMR2 with explicit local expectations, and compares exact raw app-compose bytes and unique boot fields. The local policy has no defaults and grants no approval provenance. No launch geometry or release measurements were inferred.

The dstack historical fixture has no matching authenticated collateral tuple here. Its replay test establishes compatibility only. Fabricated report fields in policy unit tests never enter an accepted hardware path. Freshness and live-key ownership remain unchecked, and all private/query/network acceptance fields remain false.

`zrpc-transport` now has a standalone SOCKS bootstrap API using `tokio-socks=0.5.3`. It connects only to a numeric loopback SOCKS endpoint and gives the hostname to SOCKS for remote resolution. It requires the caller to supply a secret session-isolation label within RFC1929's length constraint. Tor's `<torS0X>0` username identifies that isolation use. A small read guard rejects a proxy selecting unauthenticated negotiation before CONNECT; the maintained library handles the remaining protocol. There is no direct fallback, retry, environment proxy selection or invented timeout. [Tor SOCKS extensions](https://spec.torproject.org/socks-extensions.html).

The returned channel exposes no application write, raw socket or RPC authority. A successful SOCKS negotiation is not proof of a Tor process or anonymity. The CLI and UI do not invoke this transport yet; native TLS, challenge freshness and attested live-key binding remain unimplemented.

The separate [checked-hook experiment](ephemeral-runtime-candidate.md) closes the reproduced extraction failure in a source candidate. It does not establish the immutable runtime barrier or approve the stock Phala image.

## Dependency review

- `cc-eventlog=0.5.9` uses Git commit `282eeb27d22d8f091ad0fa5a90e638f85cf68751`; no registry package was presumed. Its maintained digest/replay implementation uses native endianness, so the inspector rejects non-little-endian targets.
- `ez-hash=1.1.0` checksum: `42b3b3adc5fbbc9e21416d5b721b1bccb501a87d7b32ac89f2c7cea229d40772`.
- `tokio-socks=0.5.3` checksum: `a7e2948f60dbe26b35f2c7fb74ac2854c1fddded0fe9d7548fcc674a246f7615`, default features disabled, Tokio backend only.
- The 14 newly resolved registry packages matched primary registry checksums, were not yanked and were older than the workspace's seven-day release hold on 2026-09-25. The committed lock retains the exact graph. No existing dependency version was updated.
- Three new build scripts were reviewed before compilation: BLAKE3 compiles bundled C/assembly, fs-err probes compiler-version support, and thiserror compiles a local metadata probe in its output directory. The new thiserror derive macro parses an AST and emits tokens; the reviewed source has no process, network or filesystem I/O. The managed build exception was scoped to these reviewed locked inputs.
- No declared new MSRV exceeds 1.85; this does not establish an actual Rust 1.85 build. Verification uses the pinned managed Rust 1.94.1 toolchain on ARM Linux.

The dependency guard now checks the complete native verifier dependency graph, exact dstack/registry pins and both fixture families. It finds no known network client in that graph; this is a source/dependency check, not a syscall-level network proof.

## Verification results

All execution used the managed untrusted browser container on ARM Linux with Rust 1.94.1. No Phala or live Tor connection was used.

- `cargo test --locked --workspace`: **54 unit tests and 7 compile-fail tests passed**, with no failures or ignored tests. New network tests use loopback fake proxies and a direct-connection trap. New workload tests distinguish synthetic policy comparisons from authentic quote verification.
- `cargo build --locked -p zrpc-cli --bins --examples` and `python3 scripts/cli-check.py`: passed. The new command rejects expired hardware evidence before workload appraisal and rejects malformed policies and historical-time overrides. Existing private-input refusal, simulation, budget and deployment checks still pass.
- `python3 scripts/check-verifier-features.py`, formatting, user-doc boundary check and `git diff --check`: passed.
- `python3 experiments/ephemeral-runtime/check-loader.py`: all 14 controlled cases passed, including the explicit successful-exit boundary. Deriving the candidate from the pinned source and `bash -n` also passed.

The UI and public site were not changed; their prior browser results remain recorded in `m0-verification.md`. This pass does not prove a genuine Tor circuit, DNS behavior by syscall tracing, native TLS, fresh/live hardware attestation, exact-image boot behavior, node resource fit, or external deletion. No positive authenticated quote/event-log/collateral tuple exists for this workload yet.

## Remaining deployment gates

The account's catalog identity and archive mapping are recorded in [the read-only preflight](phala-account-preflight.md). Genuine Gates A–E still require independent approved launch/workload measurements and fresh authenticated evidence; same-channel TLS-key ownership; exact-image administrative-access and runtime-storage evidence; actual KMS trust/upgrade policy; and a final all-in quote plus external deletion/deadline proof. No source-only result here resolves those live properties. The operator's $50 ceiling and explicit spending approval remain mandatory.
