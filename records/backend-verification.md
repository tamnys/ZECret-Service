# Internal node adapter verification — 2026-09-25

This is implementation evidence, not a deployment or privacy acceptance record.
The adapter has no public listener, CLI query wiring, attestation authority, or
ability to construct `VerifiedChannel`. Tests use a loopback fake node; no Zebra
process or blockchain synchronization has been run.

`crates/server/src/node.rs` implements the design §9 allowlist over maintained
Hyper HTTP/1. It takes an explicit numeric IPv4 loopback address and in-memory
cookie, opens no DNS/proxy path, probes `getblockchaininfo` on the same connection,
and requires `chain: "test"` before sending query selections. Original caller IDs
are replaced with process-local numeric IDs. Only the result is returned with the
original caller ID; node errors are mapped to fixed messages.

Clones share the design's two executing/four queued admission limits. Its
15-second deadline includes queueing, network identification and body collection;
cancellation aborts the connection driver. The 16 KiB request and 16 MiB response
bounds come from the design, including streamed chunked responses and the final
returned envelope. Redirects, compressed responses, malformed/duplicate/unknown
envelope fields and response-ID mismatches are rejected. Browser headers,
cookies, tracing data and arbitrary methods cannot be forwarded through this API.

Wire compatibility was checked against official Zebra release v6.4.2 source,
commit `e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291`, published 2026-09-25:

- [RPC declarations and results](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-rpc/src/methods.rs):
  `getblockhash` takes `i32`; the adapter rejects unsigned heights outside that
  range. `getrawtransaction` takes numeric verbosity; public booleans become 0/1.
  `getblockheader` retains boolean verbosity. BIP70 testnet name is `test`.
- [Node cookie implementation](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-rpc/src/server/cookie.rs):
  the adapter accepts user/password cookie bytes and marks the resulting
  Authorization header sensitive. Debug output contains no cookie or endpoint.

This source review does not approve the new release for dependency installation
or deployment. No Zebra binary/image pin has been selected; the managed release
hold and image verification remain necessary before actual node execution.

Enabling Hyper's client feature added only `want 0.3.1` and `try-lock 0.2.5`
besides already locked HTTP dependencies. Their official registry records are
non-yanked, published 2023-06-14 and 2023-12-07 respectively, and their archives
contain no `build.rs`. Checksums match the committed lock:
`bfa7760aed19e106de2c7c0b581b509f2f25d3dacaf737cb82ac61bc6d760b0e`
and `e421abadd41a4225275504ea4d6566923418b7f05506fbc9c0fe86ba7396114b`.
No dependency or lock update outside the managed container was performed.

Validation: `cargo test --locked -p zrpc-server` passed all 12 tests (8 adapter
tests plus 4 existing wrapper tests). Tests cover all five methods and verbosity
forms, network rejection before selection forwarding, malformed envelopes,
returned hash/txid field mismatches, redirect/compression/error sanitization,
chunked oversize responses, invalid requests before dialing, deadline socket
closure, shared admission and cancellation, and redacted configuration.

Remaining: result checks currently validate shapes and returned identifier fields.
They do not recompute Zcash block-header hashes or transaction IDs with a
protocol-aware maintained implementation. Actual Zebra readiness/sync behavior,
Compose network namespace and RPC isolation, RAM-only cookie handling, and live
attested TLS query integration remain unimplemented. This adapter alone cannot
support a private-mode claim.
