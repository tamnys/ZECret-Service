# Public session attestation exchange — 2026-09-25

This is local implementation and test evidence. No genuine private session,
approved release, deployed endpoint, hardware quote generation, or cloud
operation was performed. It extends the earlier TLS bootstrap record; the
experiment now sends a public nonce and receives explicitly unverified evidence.

## Implemented boundary

`crates/protocol/src/attestation.rs` specifies a nonce-only `POST /attestation`
body and five required response fields: nonce, quote, event log, report data and
VM configuration. Direct Serde parsing rejects duplicate/unknown fields and
positional arrays. Public policy reuses the design's 16 KiB/16 MiB body limits.
No selector, caller key, caller exporter, or provider `verified` assertion is part
of the request or public response contract.

The native `PendingChallenge` consumes its original TLS connection and nonce.
It records the maintained RFC 8446 exporter output, original nonce and original
connection lifetime privately before Hyper takes ownership of the TLS stream.
HTTP can send only this public request. It cannot resolve another host, redirect,
retry, extract the socket, or transmit an RPC body. Wrong nonce, malformed JSON,
compression, explicit closure, oversized/truncated data and connection expiry
fail. The retained `UnverifiedPublicEvidence` offers only borrowed public data;
it has no `VerifiedChannel` conversion or private-query operation.

The experimental server library holds Hyper I/O and exporter access to the same
Rustls session. It accepts one nonce attempt per connection and computes its own
64-byte exporter using the fixed ADR 0002 label and raw 32-byte context. It does
not expose the internal quote source or allow caller-selected report data. An
explicit local Unix socket receives only the pinned dstack `/GetQuote` operation.
The server reuses maintained `dstack-sdk-types::dstack::GetQuoteResponse` 0.1.2;
the HTTP adapter uses maintained Hyper framing and bounded body collection.

The [pinned Rust SDK implementation](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/sdk/rust/src/dstack_client.rs)
defines `/GetQuote` with a hex `report_data` JSON field. The
[maintained response type](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/sdk/rust/types/src/dstack.rs)
provides the four string fields. The full SDK client was not added: its Unix
response collection lacks this adapter's body bound and its package also brings
unneeded signer/HTTP dependencies. There is no HTTP URL or environment fallback
in this adapter. The guest's echoed report-data string is only a consistency
check; it is not authenticated hardware `REPORTDATA`.

Admission is shared across service clones. Connection count, concurrent quotes,
and minimum global quote spacing must be explicitly supplied by a future reviewed
release configuration; no production values were guessed. Inputs above Tokio's
documented semaphore capacity are rejected. Failed quote attempts cannot retry a
different nonce on the same connection. The server's active exchange is bounded
by the design's 300-second lifetime; cancellation drops the guest HTTP driver and
releases admission. It returns fixed errors, no-store JSON, and no `/rpc` route.

The service currently consumes an already-negotiated TLS stream. It checks TLS
1.3, a full handshake and HTTP/1.1 ALPN. It does not supply a listener, admission
before handshakes, in-workload ephemeral key generation, or an approved server
configuration. Its lifetime begins when the accepted stream enters the service;
the native client separately preserves the stricter original handshake lifetime.

## Validation

Managed `cargo test --locked --workspace` passed 109 unit tests and 15 compile-fail
documentation tests. New tests exercise actual loopback TLS and a Unix-socket
guest-agent fixture, including the real native public client talking to the real
server adapter. The quote string is explicitly synthetic in this integration
test; real TLS transport does not turn it into genuine attestation.

CLI builds and CLI refusal/fixture/cost/offline-inspection checks also passed,
as did formatting, verifier/dependency guards and the changed ADR's documentation
boundary check. One example-build attempt reported permission denied while
creating a generated object file. The directory remained owned/writable and the
object was absent; an identical managed build rerun passed without permission
changes or artifact deletion. No UI source or layout changed in this pass, and
browser visual checks were not repeated.

Server tests compare client/server exporter bytes for the same nonce and session,
prove caller report-data rejection before quote generation, enforce one challenge,
exercise global quote concurrency/rate policy across connections, reject oversized
and malformed guest replies, sanitize failures, and cancel a pending quote at the
connection deadline. Existing transport signature, ALPN, reconnect and downgrade
tests still pass. Type tests deny raw writes and approval conversion before and
after public evidence receipt.

An independent local source review covered the same-session exporter ownership,
nonce-only input, bounded Unix-only quote operation and unavailable private
authority. It found no reproducible violation in that scope. It does not replace
an independent cryptographic protocol review, cross-implementation known-answer
vector, actual TDX test, or release-policy approval.

## Dependency changes

The dstack type crate is pinned to immutable commit
`282eeb27d22d8f091ad0fa5a90e638f85cf68751`, matching the selected OS source. The
lock added eight non-yanked registry packages; official index checksums matched
the committed lock. Their publication dates all pass the workspace's seven-day
hold at this record date:

| Packages | Exact version | Published |
| --- | --- | --- |
| bon, bon-macros | 3.10.1 | 2026-09-07 |
| darling, darling_core, darling_macro | 0.24.1 | 2026-08-20 |
| prettyplease | 0.3.0 | 2026-07-18 |
| ident_case | 1.0.1 | 2019-03-18 |
| strsim | 0.11.1 | 2024-04-02 |

The new maximum declared dependency MSRV is 1.88; the workspace now requires
1.89 for the lifecycle store's standard-library file locking. Checks ran on the
managed pinned Rust 1.94.1 toolchain, not an additional 1.89 toolchain.

The [Prettyplease build script](https://github.com/dtolnay/prettyplease/blob/49e50897b580a5b7591ead6ef73f3fe09e76d896/build.rs)
reads named Cargo version/link variables and emits metadata. The inspected
[Bon macros](https://github.com/elastio/bon/blob/fdefce26d3233dedce83e1eff6daa659687e96a3/bon-macros/src/lib.rs)
and [Darling macros](https://github.com/TedDriggs/darling/blob/6b68cbe74cf5a7684c406f09558afc854022f824/macro/src/lib.rs)
generate tokens. Their reviewed source paths contained no filesystem, subprocess,
network or dynamic loading operations. This was a scoped executable-hook review,
not a full dependency audit. Compilation used the managed reviewed build gate.
The verifier feature guard still forbids collateral-fetch/override features and
known network clients in the native verifier graph.

## Remaining requirements

Authenticated quote/workload appraisal and comparison against the privately held
exporter remain unavailable as a private acceptance path. The CLI does not yet
invoke this public transport. Ephemeral server key generation, pre-handshake
resource limits, exact-image boot/runtime tests, no-administration evidence,
KMS/disk policy, genuine Tor instrumentation, provider quoting, external jobs and
real deletion/billing reconciliation remain necessary. Simulation never closes
those gates or authorizes spending.
