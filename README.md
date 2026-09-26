# ZECret service

ZECret service is an experimental privacy-focused way to read Zcash blockchain data. It is designed to combine **trusted execution environments (TEEs)**, which protect queries while the server processes them, with **Nym or Tor**, which help protect the client's identity on the network.

The goal is simple: look up a block or transaction without giving a remote server an easy way to connect that lookup to you.

**Current status:** this repository provides a local demo, attestation tools, and the foundations of a Zcash testnet service. Private queries are disabled because the client does not yet include an approved server release. The current transport uses Tor; Nym is an intended alternative, not an available client option in this version. No hosted endpoint or live Zcash node is included.

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

A TEE isolates a workload from the machine hosting it. ZECret service targets Google Cloud C3 Intel TDX with a custom measured guest, and retains a separate Phala dstack backend. TDX protects the virtual machine's private memory from access by the host operating system and hypervisor. See [Intel's TDX overview](https://www.intel.com/content/www/us/en/support/articles/000097227/processors/intel-xeon-processors.html).

Attestation lets the client check what it is connecting to before trusting it with a query. The client makes that decision locally; a provider's claim that a server is “verified” is not enough.

This protection still depends on the hardware, the approved software, and your device. Attestation does not prove that software has no bugs, that it never retains data, or that a blockchain response is correct.

## Privacy on the network: Nym or Tor

Network privacy complements the TEE by making it harder to link a request to the person sending it.

| Option | What it provides | Availability here |
| --- | --- | --- |
| **Tor** | Routes connections through relays to hide the client's IP address from the destination. | Implemented through an explicitly configured local SOCKS proxy. Available for endpoint inspection; private queries remain disabled. |
| **Nym mixnet** | Mixes traffic with other users' traffic and adds cover traffic and timing delays to make connections harder to correlate. This adds latency. | Intended alternative; not yet selectable in this version. |

Learn more about [Tor's protections](https://support.torproject.org/about-tor/introduction/protections/) and [how Nym's mixnet works](https://nym.com/nym_litepaper.pdf).

The Tor transport sends destination hostnames through the proxy for remote DNS resolution, uses a fresh stream-isolation credential for each session, and has no direct fallback. You must run and configure Tor yourself: a successful SOCKS connection alone does not prove that the local proxy is Tor. See the [endpoint inspection guide](docs/public-inspection.md) for configuration.

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

Private mode is the default when `--simulate` is omitted. In this build it refuses before reading a query from standard input. Use synthetic data for demonstrations.

## What you can query

The protocol accepts these read-only methods:

| Method | Purpose |
| --- | --- |
| `getblockchaininfo` | Read blockchain status. |
| `getblockcount` | Read the current block height. |
| `getblockhash` | Find a block's hash by height. |
| `getblockheader` | Read a block header. |
| `getrawtransaction` | Read a transaction by its ID. |

Wallet operations, transaction submission, batch requests, and arbitrary upstream URLs are rejected. The local demo returns fixtures; compatibility with a live Zebra release must be established before running a service.

## Inspect attestation evidence

To inspect a saved hardware quote and its supporting verification data without making a network request:

```sh
./target/debug/zrpc inspect-quote --quote quote.bin --collateral collateral.json
```

The [offline evidence guide](docs/offline-evidence.md) explains the required files and how to read the results. To inspect a compatible remote endpoint through Tor, follow the [public endpoint inspection guide](docs/public-inspection.md).

These tools inspect evidence. Passing an inspection does not approve a server release or enable private queries.

## Develop or operate the service

The Rust workspace separates request validation, attestation verification, transport, client logic, server wrappers, and resource lifecycle tools. The native CLI bundles the local dashboard; `ui/public/` contains a static demo site.

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
