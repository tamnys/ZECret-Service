# ADR 0002: public TLS bootstrap and connection-owned challenges

Date: 2026-09-25  
Status: TLS bootstrap accepted; exporter attestation protocol proposed

## Decision

Layer Rustls TLS 1.3 over the existing opaque SOCKS connection. Carry the same
hostname from SOCKS CONNECT into TLS SNI. The implementation has no resolver,
redirect, proxy-environment lookup, reconnection, or direct-network fallback.
Require `http/1.1` ALPN, disable resumption and early data, and install `NoKeyLog`
explicitly. Inherited `SSLKEYLOGFILE` cannot enable key logging.

The bootstrap certificate is untrusted. Rustls parses it and verifies the
server's TLS CertificateVerify signature and Finished message. Certificate
chain, DNS identity, attestation, and workload policy are not accepted at this
stage. The custom certificate verifier stays private to this restricted
transport; it must never be reused by an HTTP client that can send private data.

`PublicBootstrapTls` retains the TLS connection without exposing the stream,
configuration, or a write API. Consuming it generates one 32-byte challenge
using `getrandom` and produces `PendingChallenge`, which owns that same session.
Neither type constructs `VerifiedChannel`. Neither serializes or transmits an
application request. A challenge does not prove that a quote includes it.

The design's five-minute connection lifetime is measured with a monotonic clock
from handshake completion. A new challenge cannot extend it. Expiration requires
a new SOCKS/TLS connection and challenge. Dropping or cancelling any stage closes
its owned socket; no acceptance state survives reconnection.

## Proposed exporter binding

The candidate uses the maintained TLS 1.3 exporter from
[RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5).
It is not the named `tls-exporter` channel binding in RFC 9266: that binding uses
a different label, empty context, and 32-byte output.

The candidate inputs are:

| Field | Exact bytes or value |
| --- | --- |
| Label | ASCII `EXPORTER-zrpc-attestation-v1` |
| Label hex | `4558504f525445522d7a7270632d6174746573746174696f6e2d7631` |
| Context | Exactly the native client's 32 challenge bytes, without encoding or prefix |
| Output length | 64 bytes, matching TDX `REPORTDATA` |
| Maintained operation | `export_keying_material([0u8; 64], label, Some(&nonce))` |

For the encoding vector, the nonce and context are both
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.
This vector defines encoding only. Exporter output depends on the negotiated TLS
secrets and cannot be specified from this nonce alone. Exporter calls currently
exist only in tests; production does not use this proposal as quote policy.

Any future public attestation endpoint accepts the nonce only. The approved
server computes the exporter from its own active TLS connection and requests a
quote for those exact 64 bytes. It cannot accept caller-selected report data or
keys. The native client must authenticate the quote and workload, compare its
authenticated `REPORTDATA` with its own same-session exporter, enforce challenge
and connection lifetime, and consume this one pending challenge before private
serialization becomes possible. TLS termination and this quoting operation must
belong to the approved workload. A remote frontend that supplies arbitrary
exporter bytes to the guest would not establish that property.

At dstack 0.5.9 commit
[`282eeb27d22d8f091ad0fa5a90e638f85cf68751`](https://github.com/Dstack-TEE/dstack/tree/282eeb27d22d8f091ad0fa5a90e638f85cf68751),
Rust `DstackClient::get_quote(Vec<u8>)` supports raw report data of up to 64 bytes
through `GetQuote`; the guest pads shorter input. The proposed adapter would
always supply exactly 64 bytes over an explicit guest Unix socket. The stock
RA-TLS certificate report-data binding has no client challenge, so a cached
certificate alone cannot establish this proposal's per-connection freshness.
No dstack SDK or quote request is integrated into this transport.

## Maintained implementations

Use Rustls `0.23.45` with only `ring` and `std`, and Tokio Rustls `0.26.5` with
only `ring`; default features remain disabled. TLS versions are also restricted
explicitly in the client configuration. Random challenges use `getrandom 0.3.4`.

- [Rustls certificate and signature verifier interface](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/verify.rs)
- [Rustls maintained TLS 1.3 signature verification](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/webpki/verify.rs)
- [Rustls exporter API](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/conn.rs)
- [Tokio Rustls existing-stream connector](https://github.com/rustls/tokio-rustls/blob/f8832d28ce5688f101368e34fc6b49899a8d4293/src/client.rs)
- [dstack Rust quote client](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/sdk/rust/src/dstack_client.rs)
- [dstack guest quote operation](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/guest-agent/src/rpc_service.rs)
- [dstack RA-TLS report-data encoding](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/dstack-attest/src/attestation.rs)

## Consequences

This API provides a public bootstrap foundation only. It does not prove Tor
process identity, an approved execution environment, quote freshness, live-key
attestation binding, or private-query eligibility. Public fixture tests establish
TLS behavior; their certificates and keys are test data, never release identity.
Cloud execution, administration, KMS/disk, independent release policy, and
deletion/cost requirements remain prerequisites for any genuine private mode.
