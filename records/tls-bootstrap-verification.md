# Public TLS bootstrap verification — 2026-09-25

This record covers a local transport foundation. The CLI still refuses private
queries before reading their body. No genuine quote, approved deployment policy,
server-side quoting endpoint, or private-query authorization was created.

The SOCKS/TLS transport uses Rustls 0.23.45 and Tokio Rustls 0.26.5 over an
already-connected socket. The restricted verifier parses the certificate and
checks the actual TLS 1.3 CertificateVerify signature through Rustls/Ring. It does
not assert certificate-chain, DNS, hardware, or workload identity. Tests also
exercise the full Rustls handshake, including Finished. Opaque ownership prevents
callers from writing application data, extracting the socket, or constructing
`VerifiedChannel`. The original SOCKS hostname is reused as SNI; there is no
resolver, redirect, reconnect, environment proxy, or direct fallback operation.

TLS 1.3 and HTTP/1.1 ALPN are required. Resumption, early data and secret extraction
are disabled; `NoKeyLog` is installed explicitly. One 32-byte OS-random challenge
consumes its original TLS object. The design's 300-second connection lifetime is
checked with a monotonic clock and cannot be extended by preparing a challenge.
No nonce or exporter currently goes on the wire.

Validation: `cargo test --locked --workspace` passed 81 unit tests and 12
compile-fail documentation tests. The transport accounts for 17 unit tests and
8 compile-fail tests. Its local SOCKS/TLS tests cover signature alteration, missing
or wrong ALPN, session/nonce-dependent exporter output, connection lifetime and
zero client application bytes. A dropped TLS socket produces `ConnectionReset`
on this Linux environment; the test requires an empty collected plaintext buffer
before accepting EOF, UnexpectedEof or ConnectionReset. Other errors fail. No
production behavior was changed to accommodate that terminal socket condition.

Exporter tests use Rustls on both ends of a real local TLS session. They establish
agreement for the same session/label/context, and different output after changing
the nonce or session. They are not an independent known-answer vector, Intel
attestation test, or proof of a server quoting its own live key. The proposed
wire encoding is in ADR 0002 and remains unavailable as an acceptance policy.

## Dependency and fixture provenance

Exact versions and checksums are committed in `Cargo.lock` and checked by
`scripts/check-verifier-features.py`:

| Package | Version | Registry SHA-256 | Publication date |
| --- | --- | --- | --- |
| rustls | 0.23.45 | `0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634` | 2026-09-14 |
| tokio-rustls | 0.26.5 | `b0c85f2c3ef0b1cd58b36682f4b17aaa995f0e5db534d85692b4903abce21f67` | 2026-09-04 |
| rustls-webpki | 0.103.15 | `f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2` | 2026-08-21 |

The official registry index and immutable upstream sources were reviewed:
[Rustls](https://github.com/rustls/rustls/tree/2976d90fd1c2db6b518700dd101b714069cfcb17),
[Tokio Rustls](https://github.com/rustls/tokio-rustls/tree/f8832d28ce5688f101368e34fc6b49899a8d4293),
[WebPKI](https://github.com/rustls/webpki/tree/c14836d8de33c0ad0ac7dcb28fe9aade20831a4d).
The selected Rustls build script is empty with these features; Tokio Rustls and
WebPKI contain no build script. The native build uses the previously reviewed Ring
backend; AWS-LC is absent. Default TLS features are disabled. The guard enforces
the reviewed Ring-only feature sets and keeps the offline verifier's dependency
graph free of its known network clients and collateral-fetch/override features.

The certificate and **public upstream test private key** come from the pinned
Rustls repository's `test-ca/ecdsa-p256/` directory. Their exact URLs, SHA-256
digests and Apache license are in `tests/fixtures/tls/provenance.json`. They are
included only in tests; no production server key or identity is configured.

Remaining work includes exact server-side same-session quoting through an
explicit dstack Unix socket, bounded public attestation exchange, authenticated
quote/report-data comparison, approved release-policy provenance, Tor process
and isolation evidence, and instrumentation of the final private transport. All
Phala feasibility gates continue to constrain genuine private-mode activation.
