# Private Zcash RPC on Phala Cloud
## Proof-of-concept design and implementation handoff

**Status:** Proposed implementation baseline, not a deployed or audited system  
**Prepared:** September 25, 2026  
**Audience:** Codex and the developer operating the experiment  
**Deployment:** One Intel TDX confidential VM on Phala Cloud; Zcash testnet only  
**Evaluation envelope:** One deployment lasting at most 168 hours; approximately $60 maximum infrastructure budget  
**Source convention:** `[S#]` references identify public upstream documentation listed at the end. Requirements without a source reference are design decisions for this project, not claims about existing products.

## 1. Objective and scope

Build an RPC proof of concept in which a customer-controlled client checks the remote execution environment and its connection key before sending customer-specific queries. The approved service processes queries inside a confidential VM. The customer reaches it through Tor, rather than exposing their source IP directly to Phala's network edge.

Provide three interfaces with deliberately different trust properties:

1. A native command-line client for actual use and automation.
2. A browser dashboard served locally by that same client for a visual, interactive privacy demonstration.
3. A public informational website with documentation and a clearly labeled example/demo mode. This website does not handle private queries, credentials, payments, or user wallet information in v1.

Keep all customer wallet seeds, spending keys, viewing keys, and transaction construction outside the service. Do not create user accounts. Do not collect real payments in this milestone.

The one-week constraint is a hosting window, not a promise to complete engineering in one week. Implement and test locally before starting its clock.

### Definition of a useful result

An approved native client and local dashboard can query a live Zebra testnet node through Tor and attestation-bound encryption. Changing the approved application/configuration or substituting the connection key makes the client refuse the query. The demo shows these failures as clearly as it shows successful queries.

A working endpoint, a Phala dashboard screenshot, or a server-reported `verified: true` is not sufficient.

## 2. Decisions fixed for this milestone

| Area | Decision |
|---|---|
| Hardware and provider | Phala Cloud, Intel TDX production-image path. |
| Backend | Zebra testnet inside the same protected VM as the RPC wrapper. |
| Client | Rust CLI with a shared verification/transport library. Linux first. |
| Visual interface | Locally served web UI bundled into the CLI release. |
| Public site | Static project documentation and synthetic/example demonstration only. |
| Repository | Public GitHub repository; no repository or cloud resources are created by this document. |
| Transport | Tor required for private mode; explicit direct benchmark mode uses synthetic data only. |
| RPC scope | Strictly allowlisted, bounded, read-only JSON-RPC. |
| Accounts/payment | None in v1. No user-specific API keys. |
| Customer keys | Never accepted by any API or form. |
| Persistence | Public chain state only; no application-level customer query history. |
| Channel keys | Generated in the approved environment; ephemeral and not persisted by the application. |
| Release acceptance | Explicit client-side approved release policy, not trust on first use. |
| Deployment machinery | Docker Compose and a small external deployment/teardown tool; no Kubernetes. |
| Nym | Reserved transport extension; not a v1 dependency. |
| Host budget | Published-rate baseline about $40.84 for 168 hours; actual checkout validation required. |

These decisions may be changed through a written architecture decision record (ADR), not silently while implementing.

## 3. What the privacy claim does and does not mean

### Intended, conditional claims

**Protected execution:** A client accepts only the approved TDX platform/software/configuration policy and a connection key bound to that environment. Queries are decrypted only inside the approved processing boundary.

**No direct source-IP disclosure to the RPC host:** Private-mode application connections traverse the configured local Tor client. Phala's ingress receives a Tor exit connection, not a direct connection from the customer's network.

**Application-level retention policy:** The approved application does not persist RPC request bodies, transaction selections, responses, customer identifiers, or query-to-payment mappings. It is not a claim that providers erase encrypted network traffic.

**Local customer secrets:** The service has no interface for customer spending/viewing keys. Reading a transaction does not require these keys.

### Explicit limitations

The hardware vendor, relevant firmware, approved guest software, verifier implementation, release distribution, and customer device remain trusted. Remote attestation is evidence of execution identity under these assumptions; it is not an independent proof of correct code or the absence of every runtime exploit.

A TEE does not hide outer network addresses, connection timing, packet sizes, or all storage/memory access patterns. Tor does not guarantee resistance to an observer watching both ends. Client compromise, physical attacks outside the platform's documented model, denial of service, and full access-pattern privacy are not solved by v1. `[S3, S8]`

The host may retain encrypted traffic and public chain data. The local client/browser may retain user-requested outputs on the customer's own device. Avoid the statements “no data exists anywhere,” “100% anonymous,” “trustless,” and “cryptographic proof of deletion.”

Attestation is not proof of current blockchain consensus or of the completeness of a server response. Report chain readiness separately from attestation acceptance.

## 4. Product and user journeys

### 4.1 Developer journey

A developer installs a reviewed client release, supplies an approved release-policy file and endpoint, and runs a query. The CLI verifies the service before sending RPC parameters. Machine-readable output exposes verification status separately from the RPC result.

Proposed commands, to be implemented rather than assumed to exist:

```sh
zrpc doctor
zrpc verify --endpoint ENDPOINT --policy policy.json
zrpc query --method getblockcount
zrpc query --stdin
zrpc demo
```

Private mode is the default. A development escape hatch must be explicit, for example `--transport direct --allow-development-network`, visibly marked in every output, and absent from the default demo path. Direct mode still requires genuine attestation unless a separate local-only mock test binary is being used.

For customer-specific arguments, prefer standard input or interactive prompts so that transaction selections do not unnecessarily enter shell history or process arguments. Do not automatically write query history.

### 4.2 Visual demonstration journey

`zrpc demo` starts a loopback web server and opens its bundled interface. The browser talks only to that local process. The process uses the same verifier and transport code as the CLI.

The UI offers chain status and transaction/block examples, displays results, and separately shows:

- Transport: Tor configured and active for this request, direct development mode, or failed.
- Hardware evidence: accepted, rejected, or not checked.
- Application/configuration policy: matched or rejected.
- Connection-key binding: checked or failed.
- Chain readiness: ready, syncing, stale/uncertain, or unavailable.
- Release identity and policy version.
- Client-observed round-trip latency; server-reported processing latency labeled separately.
- The retention policy of the approved release, explicitly labeled as a policy backed by the reviewed build rather than a deletion proof.

Do not combine these into an unexplained green “private” badge. Display actual failure reasons without exporting sensitive diagnostics.

Provide demonstrations of an unknown release, incorrect key, invalid nonce, altered event log, unavailable Tor, and unavailable node. Show that the query was not sent when verification fails.

### 4.3 Public website journey

Host a static project site with installation instructions, architecture, privacy limitations, approved release downloads, and an example dashboard using public fixtures. Label examples as examples, not live verified private sessions.

The public site must not contain a custom transaction-ID input connected directly to the service. It must not request wallet secrets, account creation, or payments. It must not connect to the local client in the background; local functionality is opened deliberately from the installed client.

GitHub Pages is suitable for noncommercial project documentation in a public repository. It records visitor IP addresses and is not intended for commercial SaaS/checkout hosting. State this distinction in the site's privacy notice. `[S10, S11]`

A website can be visited through Tor Browser, but configuring the CLI's Tor connection does not anonymize unrelated browser traffic. Do not make the public website a mandatory step in each private query session.

### 4.4 Future payment journey, excluded from v1

Plan an accountless prepaid model: the local client creates blinded access tickets; a shielded payment authorizes issuance; later requests redeem unlinked one-use tickets. A future local dashboard can present purchase choices, a payment QR code, and remaining local tickets without introducing email/password accounts.

The public project site may describe the plan, but must not imply it exists. Any payment preview must be nonfunctional and labeled. Payment confirmation, blind issuance, duplicate claims, ticket replay, rollback, and recovery require a separate implementation design before funds are accepted. `[S16]`

## 5. Architecture and boundaries

```text
Public documentation website
    - examples and installation only
    - outside private query path

Customer device
    CLI ─┐
         ├─ shared Rust verification + RPC client
    local browser UI ─ local loopback server ┘
                        │
                   local Tor client
                        │
                 Tor network / exit
                        │
              Phala TLS-passthrough gateway
                        │ encrypted TLS stream
               TDX confidential VM
              ┌──────────────────────────┐
              │ RPC wrapper / TLS server │
              │ attestation integration  │
              │ strict method allowlist  │
              │            │             │
              │ internal Zebra testnet   │
              │ public blockchain state  │
              └──────────────────────────┘
```

Use the provider's passthrough hostname mechanism, discovered for the selected deployment. Do not hard-code a gateway-region hostname from a documentation example. In passthrough mode the service, not the gateway, terminates TLS. `[S2]`

No new domain purchase is required for the native-client path. A service certificate can be authenticated by the attestation-aware client rather than relying on browser compatibility. Never solve certificate problems by disabling verification for customer RPC traffic.

Zebra's P2P synchronization is separate from customer transport. It may communicate outward normally from the CVM; its network identity is not a customer identity. Do not expose underlying Zebra RPC publicly or proxy user-specific queries to an external node.

## 6. Mandatory feasibility gates

Before claiming a private deployment, implement a synthetic echo service and answer these questions for exact pinned versions.

### Gate A: locally verifiable platform and workload identity

Select a compatible production dstack image and verifier. Verify the Intel chain and collateral locally, appraise acceptable security status/advisories, reconstruct the authenticated launch measurements, and compare against an independently supplied release policy. Phala documents local quote verification; dstack documents additional workload verification. `[S4, S5]`

A raw hash in an unverified JSON event log is not evidence. A genuine hardware quote alone does not establish the expected application. The server cannot supply its own trusted allowlist.

### Gate B: connection-key ownership and freshness

Prove that the key terminating the customer connection is controlled by the accepted workload. Bind a fresh client challenge and the active channel key to attestation, and verify actual key possession through the TLS connection. Use supported, reviewed mechanisms; do not design new encryption primitives.

Do not expose a generic endpoint that attests any caller-supplied public key. The approved code must bind its own active key. Do not obtain evidence from one endpoint and send queries to another without repeating/binding verification.

### Gate C: no administrative plaintext access

Confirm that the approved production image and configuration do not provide SSH, a debug console, an operator exec API, mutable startup scripts, or another guest-level route to request memory. Map each assertion to the measured components that enforce it; inventing an `admin_disabled` attestation flag is not acceptable.

Development images must use a different policy and never be accepted in private mode. Phala documents production/development remote-access differences, but the selected deployment still needs testing. `[S6]`

### Gate D: KMS and disk trust

Use Cloud KMS provisionally to avoid adding contracts to v1, but do not equate it with provider-independent key governance. It allows Phala-managed authorization changes. `[S7]`

Document the exact effect of that control on boot, rootfs verification, volume keys, container images, and application integrity. Generate channel keys inside the workload and do not persist them. Permit only public node state on persistent writable mounts; no executable/configuration loading from them. Independently approved release measurements must still reject changed code regardless of cloud authorization.

If KMS control permits an approved-looking deployment to disclose current query plaintext, or persistent disk contents can replace trusted executable/configuration state, the intended claim fails. Report this as a blocker. Do not quietly add “trust Phala” to the guarantee or buy a different service without approval.

### Gate E: resources and actual price

Validate current availability, disk limits, all rate components, and the quoted projected cost before creating the VM. The documented size is an example, not a reservation. Verify that Zebra testnet fits and remains responsive in 8 GB without swapping request memory onto persistent storage.

If a gate fails, preserve the CLI/UI and synthetic demonstration, label the unresolved property accurately, and stop claiming end-to-end privacy. Do not replace an unsolved security gate with a green mock indicator.

## 7. Attestation and session design requirements

Prefer an existing remote-attestation TLS integration that meets this section. If bootstrap attestation is outside the TLS handshake, implement an explicit two-state channel: **unverified/public bootstrap only** and **verified/RPC permitted**. It must be impossible for the latter API to be called with the former channel type.

Before transmission of any private RPC body:

1. Load the independently trusted policy distributed with the reviewed release. Runtime downloads may supply public evidence, never silently update trust.
2. Establish transport through the local Tor client, resolving endpoint hostnames remotely.
3. Create a fresh 32-byte client nonce with a cryptographic random generator.
4. Obtain evidence binding that nonce, the active endpoint public key, and a domain-separated protocol context. Specify an unambiguous byte encoding in a reviewed ADR and test vectors before implementing it.
5. Validate the quote's vendor chain, relevant revocation/collateral expiration, debug/security attributes, and an explicit TCB/advisory policy.
6. Verify the selected dstack OS/boot and application launch/configuration evidence, including event-log replay and digest-pinned images. Check any required KMS/configuration identity.
7. Verify that the evidence's key is the key proven by the actual TLS connection. Confirm nonce equality and evidence freshness. An unbound server-supplied timestamp is not freshness evidence.
8. Transition to a verified channel and only then send RPC parameters.

Disable TLS 0-RTT and session resumption initially. Reverify on every newly established TLS connection; for the small POC, keep verified connections short-lived with a maximum five-minute policy lifetime. Reconnection never inherits verification merely because a DNS name is unchanged. Do not claim that fresh attestation proves a process has no runtime vulnerability.

The `dcap-qvl` library verifies quotes and supports offline collateral. Its default collateral fetch path can contact Phala's PCCS. Override or contain such network access: ship/cache signed collateral with expiration checks, obtain collateral through the privacy transport, or receive it as untrusted signed data from the server. Never let a hidden verifier HTTP client bypass Tor. `[S9]`

Keep hardware authenticity, application matching, security-policy appraisal, and key binding as separate fields in machine-readable verification output. Unknown or unacceptable status fails closed. Test policies and mocks must not be enabled by a production environment variable.

## 8. Network privacy

### Tor v1

Use a maintained locally installed Tor client via a loopback SOCKS endpoint. Require hostname-based SOCKS resolution; do not resolve the RPC endpoint with the system resolver first. Use the selected Tor implementation's supported stream-isolation mechanism. Tor's specification covers hostname forwarding and isolation parameters. `[S12]`

All private-mode application network operations, including attestation and collateral retrieval, must use the approved transport or already validated local data. Disable automatic redirects to arbitrary hosts and OS proxy-variable surprises.

The CLI can verify that it used its configured Tor transport; it cannot cryptographically prove that an arbitrary user-provided SOCKS server is Tor. Document reliance on the locally installed Tor process. Do not silently label any SOCKS proxy “anonymous.”

No browser request should go directly from the local dashboard to Phala. No external fonts, scripts, analytics, telemetry, error-reporting services, explorer lookups, or wallet-identifying “help” links should run automatically.

Default private mode fails when Tor is unavailable. Display a non-private development mode distinctly rather than falling back. A .onion service is a possible later routing simplification, not a v1 requirement.

### Nym extension

Keep transport dialing behind a small interface independent of verification and RPC serialization. Reserve adapters for Nym's native mixnet and dVPN modes, but do not install or depend on them in v1.

Nym's Zcash guidance distinguishes fast dVPN synchronization from mixnet broadcast. Its browser transport options differ from native options. Treat current SDK maturity, bandwidth credentials, rate limits, and end-to-end latency as separate evaluation tasks before adoption. `[S13, S14]`

Nym is complementary to protected server execution, not a substitute for it. Nor does a TEE implement a mixnet.

## 9. RPC contract and backend handling

Start with the following method list and verify exact request/response behavior against the pinned Zebra release. These methods are documented upstream, but this wrapper deliberately supports only a subset. `[S15]`

| Method | v1 restriction |
|---|---|
| `getblockchaininfo` | No parameters; report network/readiness distinctly. |
| `getblockcount` | No parameters. |
| `getblockhash` | One bounded nonnegative block height. |
| `getblockheader` | One valid block hash and supported explicit verbosity. |
| `getrawtransaction` | One valid transaction ID and supported explicit verbosity; not an address-history API. |
| `getblock` | Optional after the others; block-hash lookup with verbosity 0 or 1 only after size testing. |

The wrapper uses `POST /rpc`; never put transaction selections in URLs. Reject notifications, batch requests, unknown methods, excess parameters, non-testnet configuration, and excessive bodies. Initial limits: 16 KiB request bodies, 16 MiB decoded responses, two concurrent executing queries, a bounded queue of four, and a 15-second backend timeout. These are configurable release-policy values to validate, not Zebra limits.

No `sendrawtransaction`, address-history/balance endpoints, wallet RPC, administrative RPC, or arbitrary upstream URL forwarding. Add methods by reviewed policy change, not by exposing the entire node.

Zebra RPC is reachable only on the VM's private container network. Enable internal cookie authentication when compatible with the chosen release and protect the cookie from external exposure. Containers do not need each other's entire writable state.

Generate fresh upstream request IDs. Never forward cookies, account names, browser user agents, identifying headers, or customer-supplied tracing IDs. Do not echo raw backend errors containing query parameters into operational logs.

Use Zebra health facilities as inputs to readiness. Testnet has different activity patterns; do not falsely mark a quiet chain compromised or mark an unsynced node current. Report observed tip/age, synchronization state, and actual policy. `[S17]`

Response correctness tests compare returned transaction IDs and block identities to protocol-aware parsing and test fixtures. This is not a new consensus-proof protocol.

## 10. Browser dashboard security

Serve the UI and local API on `127.0.0.1` only, with an ephemeral port. Do not listen on `0.0.0.0`, a LAN address, or an implicitly dual-stack public interface.

Bundle assets with the native release so the public website cannot replace code before it processes sensitive input. This shifts software-delivery trust to the reviewed release; it does not eliminate supply-chain or browser compromise.

Require a cryptographically random, per-launch local capability for every API call. A one-time bootstrap capability can be conveyed in the opened URL fragment and immediately removed from browser history by the UI. Never place capabilities in query strings, logs, referrers, or persistent browser storage.

Validate the exact Host and Origin. Reject cross-origin browser calls, wildcard CORS, DNS-rebinding hostnames, unauthenticated WebSocket upgrades, and state-changing GETs. CORS alone is not authorization. Use a restrictive content-security policy, no remote asset loading, no framing, and no service worker. Test forged Origin and Host values as well as missing credentials.

Treat RPC results as text, not HTML. No `innerHTML` of remote data, markdown execution, automatic external URLs, or remote-provided JavaScript. Use `Cache-Control: no-store` for API responses and do not persist query history in localStorage/IndexedDB.

The local API may provide query and status operations but must not expose a general-purpose TCP proxy, shell command, arbitrary file access, runtime trust-policy replacement, or direct-network switch to a remote webpage.

## 11. Server-side handling, hardening, and abuse limits

Use a minimal digest-pinned image, non-root application user, dropped Linux capabilities, read-only executable filesystem, constrained temporary filesystems, and the minimum dstack API access needed for attestation. Do not mount the host Docker control socket into the wrapper.

Keep channel keys and transient RPC data in memory. Disable swap where possible and core dumps. Never persist TLS key logs or debug tracing. Do not import TLS private keys from an operator workstation for the approved path.

Persistent writable mounts may contain public chain state only. Persistent state is not automatically trustworthy executable input and does not prove freshness. Recovering node state and rotating a channel key must be independent operations.

Do not enable application HTTP access logs or serialize request objects in exceptions. Bound and sanitize error messages. Configure container logging so raw stdout/stderr cannot become a request-history store. Audit Zebra's logging and error behavior rather than assuming that the wrapper is the only component that might print a query.

v1 permits free, short-lived access for the controlled demonstration. Bound connections, requests, quote-generation concurrency, and response work globally without retaining per-user IP histories. Do not promise this is an internet-scale anti-abuse system. Quote generation itself needs rate limiting; exhausting the VM with fresh nonces must not lead to a verification bypass.

Collect only coarse operational counters needed to run the demo. Do not publish per-request timestamps, IDs, or method-level timelines that enable correlation. Aggregate counters must not be described as anonymous without considering the one-to-two-user audience.

## 12. Persistence and retention specification

| Data | Location and retention |
|---|---|
| Public blockchain database | CVM persistent disk; removed at experiment teardown. |
| Approved code/configuration | Public repository and pinned release artifacts. |
| Channel key/session state | Protected process memory; new key after restart; no application persistence. |
| RPC request/response | Temporary protected processing and customer device; no server application history. |
| Raw request logs, IP tables, browser identifiers | Not collected by approved application. |
| Provider connection records | Outside application control; may exist, hence Tor and explicit claim limits. |
| Public-site visitor records | Outside private query path; GitHub documents IP collection. |
| Verification collateral | Signed public data cached with validity checks. |
| Deployment cost/resource manifest | Operator-controlled tooling; no customer data. |
| Test diagnostics | Synthetic data only; intentional export of real local query output is customer-controlled. |
| Payment/entitlement state | Absent in v1. |

### Testnet payment POC amendment (separate from v1)

The separately approved CLI-first payment POC uses prepaid, unlinkable request tickets with simulated settlement. It adds no real ZEC settlement, account, subscription, production credential, or website checkout. The client and operator-controlled issuer exchange private files, without a public minting endpoint. An explicit operator-authorized quantity permits one idempotent batch of blinded Privacy Pass type-2 signatures. The issuer sees purchase references and blinded requests but never the finalized tickets. Tickets share one reviewed testnet issuer key and challenge; they contain no purchase identifier, customer key, personalized expiry, or account metadata.

The native client keeps purchase and blinding state in its own private store, then selects a finalized ticket only after the existing release, Tor, hardware, workload, freshness, and TLS-binding checks pass. A verified RPC request carries the ticket in the `Authorization: PrivateToken` header on that same connection. The protected server validates the ticket and allowed request locally, atomically records its issuer-scoped spent marker, and only then forwards to the loopback Zebra adapter. A node error or lost response after admission may consume the credit. The issuer is not contacted during redemption. A ticket-required profile and the existing free demonstration profile are explicit; failure to load the payment configuration or spent state must not select free access.

The only permitted persistent payment records are specified in `config/retention-policy.md`. In particular, the protected redeemer retains marker pairs only, with no query history or purchase linkage. This amendment requires reviewed measured inputs before a paid listener is enabled and does not itself approve a private deployment. Ordinary restart recovery is in scope; malicious disk rollback and restoration of old backups remain a production requirement.

The test suite should insert synthetic markers and search permitted diagnostic outputs for leakage. An absence-of-marker test is useful evidence, not a proof that malicious infrastructure retains nothing.

## 13. Budget and lifecycle

Published planning inputs checked September 25, 2026: `tdx.large`, 4 vCPU/8 GB, $0.232/hour in the detailed pricing example; disk $0.000139/GB/hour. New-account per-VM disk limit is 80 GB. Actual inventory/checkout governs. `[S1]`

| Item | Calculation | Planned cost |
|---|---|---:|
| Compute | 168 × $0.232 | $38.976 |
| 80 GB disk | 168 × 80 × $0.000139 | $1.86816 |
| Baseline | Compute + disk | **$40.84416** |
| Budget remaining | $60 − baseline | **$19.15584** |

No paid domain, second VM, Nym subscription, mainnet funds, GPU, or purchased monitoring product. Public docs and local UI should not require extra hosting charges. Do not assume promotional credits; credits do not justify expanding scope.

Zebra recommends 16 GB RAM but documents a 4 GB minimum and about 10 GB of testnet state. The 8 GB selection is a budget compromise to benchmark, not a production sizing recommendation. `[S18]`

### Preflight requirements

A local `plan` command fetches/accepts an actual quote, checks the chosen size and storage, computes the remaining experiment cost including existing resources, and refuses a plan above $50 projected infrastructure usage before the $60 overall ceiling. Confirm tax/payment fees, network allowances, minimum account funding, and any preauthorization. Usage cost is not always the same as the cash needed to open/fund an account.

A true provider-enforced hard cap is preferable if available; verify it rather than assuming that prepaid balance or disabled auto-recharge guarantees no overage. A polling script and alert are not an absolute billing guarantee.

Do not auto-upgrade instance size or extend runtime. If memory is insufficient, first reduce bounded concurrency and nonessential features. A larger machine or shorter hosted evaluation requires a revised costed plan, not an external unprotected backend.

### Lifetime controls

Persist a deployment manifest immediately after resource creation, including CVM ID, start time, absolute UTC deletion deadline, resource IDs, rates, and budget. The 168-hour clock includes synchronization and testing, not only customer demonstration time.

Arrange teardown from outside the CVM before accepting deployment as complete. Use a bounded periodic watchdog plus an absolute deadline job on operator-controlled infrastructure/CI. It must delete the VM/storage at 168 hours or when conservative cumulative cost reaches $45, whichever occurs first. If deployment fails partway, cleanup all created resources. Do not leave API credentials in the guest.

Delete, do not merely stop: disk billing continues while a CVM exists. Confirm deletion and inspect residual resources and charges. `[S1]` GitHub scheduled jobs can be delayed; use an independent reminder/manual check as a backstop and do not label a cron-based watcher a guaranteed spending cap.

## 14. Performance evaluation

Measure with one and two simultaneous native clients after the testnet node is synchronized. Use a mix of chain status, recent transaction lookup, and a bounded older lookup; do not report repeated cached block-height calls as the whole benchmark.

Report separate distributions for verification/connection setup, server-reported processing, and client-observed round-trip latency. Include reconnects, cold/warm state, errors, and payload sizes. Do not put production query identifiers into benchmark logs.

Proposed goals, not promised results:

- Warm bounded queries: p95 under one second over a direct development benchmark path with synthetic public fixtures.
- Tor mode: measure the actual p50/p95 and failures; a warm p95 under five seconds is an initial demonstration goal, not a fixed Tor guarantee.
- UI remains responsive while waiting and never displays a false success or silently changes transports.
- Both clients can operate without memory exhaustion or unbounded queues.

If the Tor goal is missed, report network/setup versus server costs before changing the security design. Do not weaken verification to improve a latency graph.

## 15. Repository layout and implementation constraints

```text
README.md
SECURITY.md
Cargo.toml
Cargo.lock
rust-toolchain.toml
crates/
  protocol/          # typed, bounded requests and evidence/result models
  verifier/          # platform/workload policy and channel binding
  transport/         # Tor and explicit development transports
  client/            # shared client state machine
  cli/               # CLI and local dashboard server
  server/            # attested RPC wrapper
ui/
  local/             # bundled visual dashboard
  public/            # static docs and fixture-only preview
config/
  zebra.testnet.toml
  release-policy.example.json
  retention-policy.md
deploy/
  compose.dev.yaml
  compose.phala.yaml
  Dockerfile
  plan-and-deploy.*
  teardown.*
  watchdog.*
docs/
  design.md
  threat-model.md
  phala-feasibility.md
  release-verification.md
  operator-runbook.md
  demo-script.md
  adr/
tests/
  fixtures/
  negative-attestation/
  network-leaks/
  local-ui-security/
  integration/
.github/workflows/
```

Names are provisional; do not publish a repository or spend money without authenticated operator intent. Prefer maintained Rust TLS/HTTP/serialization libraries. Use the current compatible dstack verifier/SDK and pin releases or commits; never leave a production dependency on a moving branch.

Use a small TypeScript frontend with locally bundled assets; avoid a separate server-side-rendering platform for the demo. A public repo is not the same as an audited release. Provide checksums and reproducible build instructions, and document any remaining non-reproducible dependency.

Public CI must never receive customer queries, seeds, cloud credentials in logs, or private keys as artifacts. Restrict deployment credentials to approved workflows, pin third-party actions, and do not expose privileged deployment secrets to forked pull requests. Keep cloud writes disabled in default CI.

## 16. Implementation milestones and acceptance tests

### M0 — Local foundation, no cloud spending

Create typed interfaces, CLI shell, local UI, mock node fixtures, policy representation, and negative tests. Mock evidence must be plainly marked and unaccepted by the real private-mode path. Add cost planning and cleanup tooling before deployment tooling is enabled.

Acceptance: CLI/UI work with fixtures; prohibited fields/methods fail; local UI rejects cross-origin/unauthorized requests; no cloud resources exist.

### M1 — Synthetic attested service on Phala

Complete Gates A–E with an echo/status-only protected service. Record exact image and verifier versions, quote appraisal, launch/configuration policy, active-key binding, KMS implications, and no-admin evidence.

Acceptance: valid deployment accepted; wrong key, stale/mismatched nonce, changed image/configuration, altered event log, expired/unacceptable collateral, and debug image rejected. No RPC body can be serialized onto an unverified connection.

### M2 — Tor and no-bypass enforcement

Connect using the local Tor client. Route bootstrap, verification collateral, and RPC through the expected transport. Add connection/DNS instrumentation in local tests.

Acceptance: disconnect Tor and requests fail; no direct fallback or plaintext debug retry; no system-DNS lookup of the service endpoint; no hidden PCCS or telemetry connection bypass; redirects to unapproved destinations rejected.

### M3 — Zebra testnet and real query path

Replace mock node with internal Zebra. Populate testnet state normally, verify runtime configuration, enforce method limits, and expose readiness separately.

Acceptance: chain status and a selected real testnet transaction work; underlying node RPC is not publicly reachable; unknown/write methods fail; malformed input, oversized output, backend failures, and restarts are bounded and do not disclose query history.

### M4 — Visual demo and public documentation

Finish bundled dashboard, fixture-only public preview, README, release policy, and privacy wording. Demonstrate live verification success and deliberate failure side by side.

Acceptance: CLI and dashboard use the same core; dashboard's outbound requests are loopback-only; no external assets/analytics; preview never represents synthetic results as live verification; no login or real payment form exists.

### M5 — Evaluation and teardown

Run the two-client benchmark, retention-marker tests, UI attack tests, and operator recovery checks. Export only synthetic/redacted reports and public configuration. Tear down on deadline/cost policy.

Acceptance: final report states exactly which privacy properties passed, measured performance, unresolved risks, actual accrued/remaining charges, and confirmation that all billable resources were deleted. If an automated teardown test has never succeeded, the deployment is not complete.

## 17. Deferred work

Nym adapter and broadcast experiments; full light-wallet gRPC compatibility; shielded receive/send integration with local keys; anonymous paid credentials; stronger access-pattern defenses; high availability; mainnet capacity; browser-extension or packaged desktop distribution; independently reviewed release governance; and production abuse controls.

Do not implement these in v1 merely because the repository has an extension point.

## 18. Instructions to Codex

Start with M0 and a concise implementation plan. Read upstream references to resolve exact API/version details. Do not turn design placeholders into invented SDK calls or hardware measurements.

Keep a checklist of feasibility gates and negative tests. Prefer completing a narrow, genuine verification path over a broad mocked dashboard. When a gate cannot be established, describe the precise missing evidence and stop the affected privacy claim; continue unrelated local work.

Before deployment, present the exact quote, projected 168-hour cost, teardown controls, and required operator credentials. Do not create external resources merely because a deployment file exists. The user's $60 ceiling is not permission to add unbudgeted services or increase runtime.

Every final implementation report must distinguish implemented, tested, simulated, and deferred behavior. Do not call the product audited, anonymous against every adversary, or a proof of no retention.

## 19. Sources checked September 25, 2026

[S1] Phala detailed CPU pricing and billing lifecycle: https://cloud.phala.com/about/pricing  
[S2] Phala TLS passthrough: https://docs.phala.com/phala-cloud/networking/tls-passthrough  
[S3] dstack security model (moving upstream branch; pin actual implementation): https://raw.githubusercontent.com/Dstack-TEE/dstack/next/docs/security/security-model.md  
[S4] Phala attestation verification guide: https://docs.phala.com/phala-cloud/attestation/verification-guide  
[S5] dstack verification: https://raw.githubusercontent.com/Dstack-TEE/dstack/next/docs/verification.md  
[S6] Phala production/development debugging modes: https://docs.phala.com/phala-cloud/troubleshooting/debug-your-application  
[S7] Phala Cloud versus Onchain KMS: https://docs.phala.com/phala-cloud/key-management/cloud-vs-onchain-kms  
[S8] Tor threat-model limitations: https://support.torproject.org/about-tor/security/attacks-on-onion-routing/  
[S9] dcap-qvl verifier and collateral behavior: https://github.com/Phala-Network/dcap-qvl  
[S10] GitHub Pages availability and visitor-IP collection: https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages  
[S11] GitHub Pages usage limits: https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits  
[S12] Tor SOCKS and stream isolation: https://spec.torproject.org/socks-extensions.html  
[S13] Nym/Zcash implementation guidance: https://zcash-sdk.nym.com/guidance/  
[S14] Nym browser/native transport differences: https://zcash-sdk.nym.com/platforms/  
[S15] Zebra RPC methods: https://zebra.zfnd.org/internal/zebra_rpc/methods/trait.RpcServer.html  
[S16] RSA blind signatures, RFC 9474: https://www.rfc-editor.org/rfc/rfc9474.html  
[S17] Zebra health/readiness: https://zebra.zfnd.org/user/health.html  
[S18] Zebra system requirements: https://zebra.zfnd.org/user/requirements.html
