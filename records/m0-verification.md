# M0 implementation and verification record

Date: 2026-09-25. Repository: `/Users/j/Code/phala-zcash-rpc`. The entire supplied design is preserved as `records/input-design.md`; the user's request defines M0 scope and spending authorization. The document's later milestones did not authorize deployment.

## Outcome against the M0 contract

Implemented a local Rust workspace with strict protocol parsing, disabled release policy, unconstructible genuine verified channels, separated simulation state machine, in-process RPC fixture wrapper, CLI and bundled TypeScript loopback UI. Added a static public documentation preview and precise offline cost/lifecycle tools. No GitHub repository was published, no provider credentials were requested, no cloud API was called, and no resources or costs were created by this task.

Private mode refuses before CLI stdin is read; deferred-body tests prove the private request builder is not invoked. A provider `verified: true` assertion and mock evidence cannot yield a verified session. Simulation reports `private_accepted: false`, `query_sent: false` and distinct local `fixture_dispatched` state. Every displayed evidence match is explicitly simulated.

## Tests performed

All execution used the managed untrusted browser container, Rust/Cargo 1.94.1, Node 22.22.2 and pnpm 10.34.5.

- TypeScript 5.9.3 compiled successfully from exact dependency/lock pins using frozen, script-free installation.
- `cargo fmt --all -- --check`: passed.
- `cargo test --locked --workspace`: **33 unit tests and 5 compile-fail tests passed**.
- `cargo build --locked -p zrpc-cli --bins --examples`: passed.
- `python3 scripts/cli-check.py`: passed. Exercises all fixture requests, private refusal, single-document JSON reports, simulated attestation/Tor failures, marker-safe errors, exact cost baseline, disabled deployment, deadline deletion intent and simulated cleanup.
- `node scripts/browser-check.cjs`: passed in the managed browser profile. All five UI methods and six required negative scenarios exercised; capability bootstrap removes fragment; browser requests remain same-origin loopback; no web storage/service workers; static public site has no script/input/form/iframe or external request. Both interfaces checked at 1440×1100 and 390×844 (representative desktop/mobile QA viewports, not product limits).
- Local API unit tests: forged Host/Origin, null Origin, missing capability, reused bootstrap, duplicate Host, unsupported GET, WebSocket upgrade and excessive body rejected; native-core response parity and no-store headers checked.
- Lifecycle tests: exact $40.84416; fees/accrued/existing-resource costs; delayed-start existing billing; quote/control omissions; overflow; changed sizing/lifetime; $45/deadline delete decision; stopped storage; partial creation; idempotence; deletion failures and residual inventory; real manifest cannot use fake deletion.
- User-docs boundary scanner passed on user-facing Markdown.
- Desktop/mobile screenshots inspected under `.codex-tmp/playwright/`; transient browser servers were terminated by the harness.

Review corrected the transaction fixture identifier, delayed-start cost undercount, positional-array parsing and multi-document CLI errors before closeout.

## Simulation and deferred work

All node data, attestation scenarios and cleanup operations are synthetic. There is no live TLS endpoint, Tor dialer, quote-verification implementation, dstack SDK adapter, Zebra node, provider adapter, external scheduler or actual deletion confirmation. No such implementation or approval is implied by the typed interfaces. No benchmark or cloud privacy result is claimed.

The server request/response limits are enforced for fixtures; two executing queries, four queued queries and 15-second backend timeout are design constants only, awaiting the live backend. Raw fixture transaction/header strings are intentionally not consensus-valid Zcash bytes. Bit-for-bit reproducibility, release signing, real chain identity validation, network/DNS leak instrumentation and live retention behavior are unproven.

All Gates A–E remain unresolved: exact locally validated platform/workload; fresh live TLS-key ownership; measured absence of administrative access; KMS/rootfs/disk implications; authenticated resources/fees/funding quote plus memory fit and tested external deletion/deadline controls. See `records/feasibility-research.md` for dated official sources. The published-rate baseline is confirmed, not an actual checkout quote. M0 local fake cleanup cannot satisfy deployment prerequisites.

## Artifact hashes from this build

```text
b7f3e71708a9c43a5e61c3c1a951c2d4beabbc5518d930d46bab00d74ad9ee19  target/debug/zrpc
cf2af6d7bf9163cc94ccb0db37a6d50dd7b40c55cb23fff9f363683cc0556cd8  Cargo.lock
9747995ee6c20d5990a84006b6353d66070f7a2bb23b92133c1c81e02a1e5693  ui/local/pnpm-lock.yaml
4015a34c7e95ccf49d0b7ee164a065aed5c63635755a2855e48c07cb741531c7  ui/local/dist/app.js
```

These identify the observed local debug build and inputs; they are not signed release provenance.

## Next operator command

```sh
cd /Users/j/Code/phala-zcash-rpc
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --command cargo run --locked -p zrpc-cli -- doctor
```

This reports the local foundation and blocked live gates. It performs no cloud action. A separate explicit deployment action is required only after the documented live prerequisites are satisfied.
