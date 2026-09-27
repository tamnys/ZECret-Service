# GCP TDX TLS-exporter and retained-session review

Reviewed 2026-09-27 against commit `5a91381` for the client/server channel path. The later base commit `f5d8eba` did not change the reviewed Rust paths. This is a scoped source review with local tests, not production TDX acceptance or an audit of Rustls, OpenSSL, or Intel QVL internals.

## Source findings

- The bootstrap client requires a full TLS 1.3 handshake and `http/1.1` ALPN, disables resumption and early data, and exposes no caller write API before verification ([`crates/transport/src/tls.rs`](../crates/transport/src/tls.rs), lines 93–137, 143–225). The server generates an ephemeral key, disables tickets, session storage, early data, and key logging, and starts the 300-second deadline when it accepts the socket ([`crates/server/src/bootstrap.rs`](../crates/server/src/bootstrap.rs), lines 39–74, 130–156).
- The client creates one OS-random 32-byte nonce and sends only `POST /attestation`. It computes 64 bytes with Rustls `export_keying_material` using `ATTESTATION_EXPORTER_LABEL` and the raw nonce as context on that original TLS stream before giving it to Hyper ([`crates/transport/src/tls.rs`](../crates/transport/src/tls.rs), lines 165–193; [`crates/transport/src/tls/attestation.rs`](../crates/transport/src/tls/attestation.rs), lines 175–265; [`crates/protocol/src/attestation.rs`](../crates/protocol/src/attestation.rs), lines 8–14). The server computes the same exporter from its active Rustls session and passes it to its local quote source; the request cannot supply report data ([`crates/server/src/attestation.rs`](../crates/server/src/attestation.rs), lines 447–501).
- The client checks the echoed nonce, but treats it only as correlation. The offline verifier calls the maintained QVL with the production Intel root and strict TCB policy before exposing authenticated claims to the workload comparison ([`crates/transport/src/tls/attestation.rs`](../crates/transport/src/tls/attestation.rs), lines 179–208; [`crates/verifier/src/offline.rs`](../crates/verifier/src/offline.rs), lines 138–228). GCP inspection compares signed `REPORTDATA` with the retained exporter, plus quote measurements and CCEL replay ([`crates/verifier/src/gcp.rs`](../crates/verifier/src/gcp.rs), lines 250–300, 318–365). This review checked the call and data flow, not the cryptographic implementations themselves.
- Only the HTTP sender that received the quote can become `VerifiedRpcSession`. It has no socket replacement or serialization path. Promotion requires a selected client-packaged release, live session, collateral expiration, and GCP provenance; diagnostic policy alone cannot promote it ([`crates/transport/src/tls/attestation/gcp.rs`](../crates/transport/src/tls/attestation/gcp.rs), lines 29–64; [`crates/transport/src/tls/attestation.rs`](../crates/transport/src/tls/attestation.rs), lines 94–173, 418–460). `query_from_body` checks readiness before invoking its body closure and again before sending. The TLS I/O adapter checks both connection and collateral deadlines on every read, write, and flush ([`crates/transport/src/tls/attestation.rs`](../crates/transport/src/tls/attestation.rs), lines 110–165, 463–552). The CLI and local dashboard defer reading private stdin/HTTP body until `connect_verified` succeeds ([`crates/cli/src/main.rs`](../crates/cli/src/main.rs), lines 180–220; [`crates/cli/src/lib.rs`](../crates/cli/src/lib.rs), lines 221–265).
- The server refuses `/rpc` before its one attestation exchange and checks this before reading the RPC body. It dispatches only the typed method allowlist after that point. It does not claim to verify the client's release decision ([`crates/server/src/attestation.rs`](../crates/server/src/attestation.rs), lines 414–461, 531–575). Listener shutdown aborts owned connection tasks ([`crates/server/src/bootstrap.rs`](../crates/server/src/bootstrap.rs), lines 130–156, 267–302).

No reproducible bypass of nonce correlation, same-connection binding, pre-verification private-body withholding, or the enforced lifetime was found in this scoped review. In the current release, GCP private-session promotion is unreachable: the embedded release catalog is empty ([`crates/verifier/src/approved.rs`](../crates/verifier/src/approved.rs), line 29), and `private_acceptance_ready` requires firmware and artifact provenance statuses that the current inspector always sets to `not_checked` ([`crates/verifier/src/gcp.rs`](../crates/verifier/src/gcp.rs), lines 219–228, 285–299). This fail-closed state must remain until those checks are independently implemented and reviewed.

## Local checks

In the managed untrusted browser-profile container at `5a91381`:

```text
cargo test --locked -p zrpc-transport -p zrpc-server -p zrpc-client
  passed: client 9; server library 57; server binaries 7;
          transport 40 (one separate interoperability test ignored); doc tests 16
python3 experiments/tls-exporter/check.py
  passed: Rustls/OpenSSL TLS 1.3 exporter and nonce-context agreement
```

The tests cover changed nonce and label, a different connection, malformed/replayed evidence, forbidden RPC before attestation, TLS configuration, expiration before body read and before TLS write, and listener shutdown. The OpenSSL harness uses a pinned public test certificate and loopback fixture. All quote, node, and Tor fixtures in these checks are synthetic; they do not show a live Tor process, real GCP hardware, a production artifact, or an approved private query.

## Release boundary

This checkpoint does not close the production security gate. The exact signed guest artifact, firmware reference, boot-input and rootfs provenance, administrative isolation, real TDX quote and collateral, Tor deployment, and live retained-session behavior still require independent evidence. A future change that makes GCP provenance `verified` or populates the packaged release catalog must receive a new review and hardware tests before private mode is enabled.
