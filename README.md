# ZRPC — local foundation and offline evidence inspection

A Rust scaffold for a Phala Intel TDX Zcash testnet RPC experiment. **Private mode is unavailable and every private verification attempt fails closed.** The dashboard and CLI RPC path remain local simulations. Separate offline and public endpoint diagnostics inspect Intel hardware evidence. The public diagnostic uses explicit loopback SOCKS and TLS; no cloud deployment or live Zebra node is included.

The native CLI and its bundled loopback dashboard share the same client core. Synthetic evidence cannot create a verified channel. The public documentation preview is static and has no private-query path.

## Run

Use Rust **1.94.1** and the committed `Cargo.lock`. Linux is the supported development target. From the repository:

```sh
cargo build --locked -p zrpc-cli
./target/debug/zrpc doctor
./target/debug/zrpc query --simulate --method getblockcount
./target/debug/zrpc query --simulate --scenario wrong-key
./target/debug/zrpc demo
```

`demo` binds `127.0.0.1` on an ephemeral port and deliberately opens the local browser using `xdg-open`. On a terminal without a browser opener, `demo --no-open` displays a one-time link directly on the controlling terminal; do not share or record it. It is never written to application stdout/stderr logs. A Linux container's loopback is inside the container: use its browser profile for UI checks, rather than exposing the dashboard on a LAN interface.

Under `/Users/j/Code`, open the managed shell first and execute all builds/tests there:

```sh
cd /Users/j/Code/phala-zcash-rpc
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --shell
cargo build --locked -p zrpc-cli
./target/debug/zrpc doctor
bash scripts/check.sh --browser
```

Private mode is the default. `zrpc query --stdin` refuses before reading standard input. Fixture requests use `--simulate --stdin`; transaction selections need not enter command arguments or shell history. Each query or verify invocation emits one JSON report; rejection returns a nonzero exit code. No environment variable enables genuine acceptance or a direct fallback.

## Offline evidence inspection

```sh
./target/debug/zrpc inspect-quote --quote quote.bin --collateral collateral.json
```

This uses pinned `dcap-qvl` 0.6.3, Intel's production root, supplied signed collateral and the system clock without fetching anything. Hardware cryptography and strict security appraisal are separate results. It never approves private mode, workload identity, freshness or the live TLS key. See [offline evidence](docs/offline-evidence.md) for supported inputs and policy.

For a compatible operator-selected endpoint, [public endpoint inspection](docs/public-inspection.md) adds a nonce-only SOCKS/TLS exchange and compares authenticated quote REPORTDATA with that connection's proposed exporter binding. Diagnostic matches do not authorize private queries or establish release approval.

The [local public wrapper](docs/public-wrapper.md) provides the corresponding attestation-only TLS listener with a fresh process-local key and an explicit dstack Unix socket. It binds only loopback through its CLI and exposes no RPC route or private acceptance.

## Local UI and public preview

The native release embeds `ui/local/index.html`, its stylesheet and committed compiled TypeScript. The dashboard exchanges a one-time fragment capability for an in-memory session capability. API access also requires exact Host and Origin. It does not persist query history or load remote assets.

To rebuild the UI using the pinned TypeScript **5.9.3** compiler and pnpm **10.34.5**:

```sh
cd ui/local
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build
cd ../..
cargo build --locked -p zrpc-cli
```

`ui/public/` is a fixture-only documentation site suitable for later static hosting. It is not published by this repository's tooling. No login, payment, customer-key input or browser-to-cloud RPC exists.

## Protocol and state boundaries

The strict fixture protocol supports `getblockchaininfo`, `getblockcount`, `getblockhash`, `getblockheader` and `getrawtransaction`. It rejects notifications, batches, unknown/duplicate fields, write methods, wallet methods, arbitrary upstream URLs, and malformed or oversized input. Header/transaction verbosity is an explicit boolean in this fixture model; live compatibility must be established against the selected Zebra release.

Requests are bounded at 16 KiB and encoded responses at 16 MiB, from design §9. The internal loopback-node library implements the two-executing/four-queued/15-second backend policy and testnet checks. It is not exposed through a private-query listener. Synthetic raw data is deliberately not valid Zcash wire data.

`PrivateSession<UnverifiedChannel>` exposes no query method. `VerifiedChannel` cannot be constructed or deserialized in M0. The fixture client is a separate type and has no conversion to it. `verified: true` provider assertions never authorize a query.

## Cost and lifecycle tools

```sh
./target/debug/zrpc plan --input deploy/plan.fixture.json
./target/debug/zrpc watchdog --manifest deploy/manifest.fixture.json --now 1790956800 --accrued-microusd 0
./target/debug/zrpc teardown --simulate --manifest deploy/manifest.fixture.json
```

These commands perform local arithmetic or in-memory simulation. They never call a provider or schedule a real job. Rates use integer microUSD; timestamps use Unix UTC seconds. The fixture reproduces **$40.84416** for 168 hours and 80 GB. Fixture availability, fees and cleanup references are synthetic assumptions, not a checkout quote.

The operator's total experiment budget is **$50**, including all deployment, testing and deletion costs. Planning refuses more than $50 projected usage and requires external deadline/watchdog/deletion evidence references. The watchdog requests deletion at $45 conservative cumulative cost or an absolute deadline no later than 168 hours; modeled detection/deletion costs and fees must fit the remaining $5. **Stopping does not stop disk billing.** Account funding does not authorize spending: obtain explicit operator approval before any billable action. A real deployment also requires authenticated pricing and tested external deletion and deadline jobs. `zrpc deploy` always refuses.

On Unix, `zrpc lifecycle observe` reads Phala inventory, tracked CVM details and usage for an existing initialized ledger. Run `zrpc lifecycle --help` for its required file paths, page sizes, time budget and response/retention bounds. Supply the API key through an owner-private regular file and trust anchors through explicit DER certificate files. The command uses ordinary authenticated HTTPS to the fixed Phala API; it has no private RPC or browser path.

The original ledger determines the workspace, tracked resources and usage start date. Every usage request uses the same cutoff captured from the system clock, including observations after the original deadline. Completed scans are not atomic snapshots. Usage rows remain unjoined and uncharged because their relation to CVM identifiers is unresolved. The report is not persisted and does not modify costs or deletion history. A CVM 404 does not prove storage deletion or billing finality. This command cannot create or delete resources, install jobs, initialize/reset a ledger, or approve deployment.

## Project map

- `crates/{protocol,verifier,transport,client,server}`: typed boundaries and in-process fixtures.
- `crates/cli`: native CLI, loopback authorization and bundled UI server.
- `crates/lifecycle`: cost planning, durable local history, read-only provider observations and simulated cleanup.
- `tests/fixtures`: synthetic node data plus separately labeled historical upstream hardware evidence in `dcap/`.
- `docs/implementation-plan.md`, `docs/gates-and-tests.md`: implementation contract and acceptance checklist.
- `docs/phala-feasibility.md`, `docs/operator-runbook.md`: compatibility gates and operator workflow.
- `records/`: internal research and verification evidence.

Dependencies have exact direct pins and checksum-bearing lockfiles. Native builds use the committed UI bundle; build outputs can be checksummed with `sha256sum target/debug/zrpc`. Bit-for-bit reproducible release binaries, signed releases and independently reviewed attestation integration are future release work. This scaffold is not an audited private service.
