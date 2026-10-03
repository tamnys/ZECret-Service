# ZECret service

ZECret service is an experimental privacy-focused way to read Zcash blockchain data. It is designed to combine **trusted execution environments (TEEs)**, which protect queries while the server processes them, with **Nym or Tor**, which help protect the client's identity on the network.

The goal is simple: look up a block or transaction without giving a remote server an easy way to connect that lookup to you.

**Current status:** the native client packages an approved Phala-trusting release for live Zcash testnet queries. The stricter provider-independent private profile remains unavailable. The public website shows fixed examples and does not connect to the service. Query commands start a selected local Tor executable; Nym is an intended alternative, not an available client option in this version.

## How it works

The intended private-query flow is:

```text
Your device → Tor (or future Nym support) → [ TEE: service wrapper → Zcash node ]
```

TLS encrypts the connection from your device to the service inside the TEE.

1. **Connect through a privacy network.** The client routes traffic through a local privacy-network client so the service does not receive a direct connection from your IP address.
2. **Check the server before sharing the query.** The server returns hardware-backed evidence called an *attestation*. Your client checks the hardware and software against an approved release, checks that the evidence is fresh, and checks that it belongs to the same encrypted connection.
3. **Send the query over that verified connection.** Only after those checks pass can the client send a supported read-only request. The server wrapper forwards it to a local Zcash node and returns the response.

If a check fails, the client stops. It does not silently switch to a direct connection or send the query to an unverified server. The CLI and local dashboard use the same Rust client core.

## Privacy at the server: TEEs

A TEE isolates a workload from the machine hosting it. ZECret service currently targets Phala dstack Intel TDX, with Google Cloud C3 TDX retained as a separate backend. TDX protects the virtual machine's private memory from access by the host operating system and hypervisor. See [Intel's TDX overview](https://www.intel.com/content/www/us/en/support/articles/000097227/processors/intel-xeon-processors.html).

Attestation lets the client check what it is connecting to before trusting it with a query. The client makes that decision locally; a provider's claim that a server is “verified” is not enough.

This protection still depends on the hardware, the approved software, and your device. Attestation does not prove that software has no bugs, that it never retains data, or that a blockchain response is correct.

The explicit `phala-trusted` profile also trusts Phala's guest administration, KMS, and persistent runtime controls. It can protect a query from ordinary network observers while requiring a reviewed workload, live TDX quote, fresh TLS-key binding, and Tor. It does **not** claim confidentiality from Phala administrators or prove that persistent state was erased. The client packages approved releases; a local policy file or a provider response cannot add one.

## Privacy on the network: Nym or Tor

Network privacy complements the TEE by making it harder to link a request to the person sending it.

| Option | What it provides | Availability here |
| --- | --- | --- |
| **Tor** | Routes connections through relays to hide the client's IP address from the destination. | Endpoint inspection uses an explicitly configured local SOCKS proxy. The approved Phala-trusting query profile starts a local Tor child with a private Unix socket. |
| **Nym mixnet** | Mixes traffic with other users' traffic and adds cover traffic and timing delays to make connections harder to correlate. This adds latency. | Intended alternative; not yet selectable in this version. |

Learn more about [Tor's protections](https://support.torproject.org/about-tor/introduction/protections/) and [how Nym's mixnet works](https://nym.com/nym_litepaper.pdf).

The transport sends destination hostnames through the proxy for remote DNS resolution, uses a fresh stream-isolation credential for each session, and has no direct fallback. For endpoint inspection, run and configure Tor yourself. For private commands, supply the absolute path to the local Tor executable. The client trusts that installation and your device; a successful SOCKS connection alone does not prove Tor's identity or network behavior. See the [endpoint inspection guide](docs/public-inspection.md) for diagnostic configuration.

Neither network routing nor a TEE guarantees complete anonymity. They address different parts of the privacy problem, and both depend on the client and service being configured correctly.

## Try it locally

Use Linux, Rust **1.94.1**, and the committed `Cargo.lock`. From the repository root:

```sh
cargo build --locked -p zrpc-cli
./target/debug/zrpc doctor
./target/debug/zrpc query --simulate --method getblockcount
./target/debug/zrpc query --simulate --scenario wrong-key
./target/debug/zrpc demo
```

The command-line tool is named `zrpc`. These examples check the local setup, return synthetic blockchain data, demonstrate a rejected verification, and open the local dashboard. They do not create cloud resources or query a live node.

The dashboard listens only on `127.0.0.1` and loads no remote assets. If a browser cannot open automatically, use `demo --no-open` to display a one-time access link in your terminal. Keep that link private. When running in a container, open the dashboard from a browser in that container.

The stricter private profile is the default when `--simulate` and `--privacy-profile` are omitted; it refuses before reading a query body because it has no approved release in this build. Select `phala-trusted` explicitly for live testnet queries.

## Live Phala testnet queries

Install Tor on Linux and build the native client and its separately locked ticket verifier from this source tree. The client includes the [current attestation collateral](deploy/phala/releases/2026-10-01/blockcount-collateral.json), [approved app-compose bytes](deploy/phala/releases/2026-10-01/blockcount-app-compose.json), [release selection policy](deploy/phala/releases/2026-10-01/blockcount-selection-policy.json), and [issuer public key](deploy/phala/ticketed/issuer-public.der). From the repository root, set the local paths and verify the service:

```sh
cargo build --locked -p zrpc-cli
cargo build --locked --manifest-path tools/payment-crypto/Cargo.toml
ZRPC_TOR="$(command -v tor)"
test -x "$ZRPC_TOR"
ZRPC_COLLATERAL="$PWD/deploy/phala/releases/2026-10-01/blockcount-collateral.json"
ZRPC_HELPER="$PWD/tools/payment-crypto/target/debug/zrpc-payment-crypto"
ZRPC_ISSUER=il3hrcrare4fzp3ka6oe4ewl6433isnfzxdvnqe7cfyefhylkadyyead.onion
ZRPC_TICKET_STORE="$HOME/.local/share/zrpc-tickets"
mkdir -p "$HOME/.local/share"

./target/debug/zrpc verify --privacy-profile phala-trusted --platform phala-dstack \
  --endpoint-host 5af400d6c4fd5312a9b9693fe0988d5bdc0ee726-8443s.dstack-pha-prod9.phala.network \
  --endpoint-port 443 --tor-executable "$ZRPC_TOR" --collateral "$ZRPC_COLLATERAL" \
  --app-compose deploy/phala/releases/2026-10-01/blockcount-app-compose.json \
  --release-policy deploy/phala/releases/2026-10-01/blockcount-selection-policy.json
```

Request up to 100 free tickets per batch through the issuer's Tor onion service. The CLI creates an owner-private ticket store outside the repository and verifies each returned ticket against the bundled public key. No account or ZEC payment is needed.

```sh
./target/debug/zrpc payments get --credits 100 \
  --ticket-store "$ZRPC_TICKET_STORE" \
  --issuer-public-der deploy/phala/ticketed/issuer-public.der \
  --issuer-name "$ZRPC_ISSUER" --crypto-helper "$ZRPC_HELPER" \
  --issuer-onion "$ZRPC_ISSUER" --issuer-port 80 --tor-executable "$ZRPC_TOR"
./target/debug/zrpc payments balance --ticket-store "$ZRPC_TICKET_STORE"
```

The live CLI requires a ticket for every query and marks it spent only after a successful response. If a response is uncertain, it keeps that ticket out of the available balance to prevent reuse. Run a read-only query with the same verified release:

```sh
./target/debug/zrpc query --privacy-profile phala-trusted --method getblockchaininfo \
  --platform phala-dstack \
  --endpoint-host 5af400d6c4fd5312a9b9693fe0988d5bdc0ee726-8443s.dstack-pha-prod9.phala.network \
  --endpoint-port 443 --tor-executable "$ZRPC_TOR" --collateral "$ZRPC_COLLATERAL" \
  --app-compose deploy/phala/releases/2026-10-01/blockcount-app-compose.json \
  --release-policy deploy/phala/releases/2026-10-01/blockcount-selection-policy.json \
  --ticket-store "$ZRPC_TICKET_STORE" \
  --issuer-public-der deploy/phala/ticketed/issuer-public.der \
  --issuer-name "$ZRPC_ISSUER" --crypto-helper "$ZRPC_HELPER"
```

Use the same query command with `--method getblockcount` to read the current testnet height. The client checks the Phala-managed release, fresh hardware evidence, and the live TLS connection before sending the query. The website never handles tickets or queries. The bundled collateral is time-limited; an expired bundle fails closed and must be refreshed through a reviewed client release.

## What you can query

The protocol accepts these read-only methods:

| Method | Purpose |
| --- | --- |
| `getblockchaininfo` | Read blockchain status. |
| `getblockcount` | Read the current block height. |
| `getblockhash` | Find a block's hash by height. |
| `getblockheader` | Read a block header. |
| `getrawtransaction` | Read a transaction by its ID. |
| `getaddressbalance` | Read one validated testnet transparent address balance in the Phala-trusting profile. |

The JSON-RPC interface rejects wallet operations, transaction submission, batch requests, and arbitrary upstream URLs. A separate [local wallet reader](docs/wallet-read.md) exposes pinned read-only lightwallet methods through an authenticated loopback bridge when a wallet-capable Phala release is approved. The local demo returns fixtures; the approved Phala-trusting profile uses the live testnet service.

Chain status and confirmed address balances include
`chain_context: {"height": ..., "hash": ...}`. This identifies the node state
used for that result; it does not prove global chain freshness or private-mode
approval. Chain-status diagnostics such as synchronization estimates are not
block-state guarantees. The preview reports status and balance contexts
separately because the chain can advance between those requests.

To require an exact block, add `expected_block` to a covered JSON request passed
to `query --stdin`. Both height and hash must match; otherwise the query fails
without retrying or selecting another block. For example, this **synthetic**
request matches the local fixture:

```json
{"jsonrpc":"2.0","id":1,"method":"getblockcount","expected_block":{"height":42,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
```

This is an exact-match condition on current state, not a historical balance
query. Address balances exclude mempool changes and omit the lifetime `received`
field. An oversized UTXO response fails instead of producing a partial balance.
Block and transaction lookup methods do not carry this context and reject
`expected_block`. Upgrade the wrapper and native client together: covered
responses without context are rejected by the new client.

## Inspect attestation evidence

To inspect a saved hardware quote and its supporting verification data without making a network request:

```sh
./target/debug/zrpc inspect-quote --quote quote.bin --collateral collateral.json
```

The [offline evidence guide](docs/offline-evidence.md) explains the required files and how to read the results. To inspect a compatible remote endpoint through Tor, follow the [public endpoint inspection guide](docs/public-inspection.md).

These tools inspect evidence. Passing an inspection does not approve a server release or enable private queries.

## Develop or operate the service

The Rust workspace separates request validation, attestation verification, transport, client logic, server wrappers, and resource lifecycle tools. The native CLI bundles the local dashboard; `ui/public/` contains the public website.

- [Local server wrapper](docs/public-wrapper.md): run an attestation-only listener.
- [Google Cloud TDX](docs/gcp-tdx.md): native client commands, guest inputs, and operator lifecycle tooling.
- [Operator guide](docs/operator-runbook.md): deployment prerequisites and experiment cost controls.
- [Watchdog guide](docs/watchdog.md): track resources and prepare cleanup jobs.
- [Reproducible builds](docs/release-verification.md): reproduce the native Linux binary.
- [Security model](SECURITY.md): trust assumptions and reporting guidance.

To rebuild the dashboard, use the repository's pinned pnpm **10.34.5** and TypeScript **5.9.3**:

```sh
cd ui/local
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build
cd ../..
cargo build --locked -p zrpc-cli
```

Run `bash scripts/check.sh --browser` in the managed Linux browser environment to check the CLI and dashboard.

Deployment is not enabled: `zrpc deploy` always refuses. Cost-planning and simulation commands do not create resources, but some lifecycle commands can delete explicitly selected cloud resources. Follow the operator guide before using them. This is an experimental project, not an audited private service.
