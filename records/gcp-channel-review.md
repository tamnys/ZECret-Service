# GCP TDX TLS-exporter construction review

Date: 2026-09-26. This is a source-level protocol review and local-test plan,
not hardware acceptance or approval to populate the release catalog.

## Reviewed construction

The client and server call maintained Rustls `export_keying_material` on their
own *completed, full TLS 1.3 handshake* with the same application label,
the exact 32-byte challenge as context, and 64-byte output. The server places
that output in the local TSM ConfigFS quote request. The client retains the
original HTTP/TLS sender and compares its own output only to authenticated
TDX `REPORTDATA` after the offline DCAP/TCB gate succeeds. The same owned
sender is the only path to `POST /rpc` after packaged-release matching. A
quote response's echoed nonce or report-data text grants no authority.

This is an application-specific exporter binding, not RFC 9266's named
`tls-exporter` channel binding. [RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)
defines the TLS 1.3 exporter and requires the ordinary exporter master secret
except when an application explicitly selects the early exporter. Both
ends use Rustls's ordinary exporter API, with early data and resumption
disabled. [RFC 5705 §4](https://www.rfc-editor.org/rfc/rfc5705.html#section-4)
allows labels beginning `EXPERIMENTAL` for private use without registration.
The original `EXPORTER-zrpc-attestation-v1` candidate was unregistered; this
checkpoint changes the shared label to `EXPERIMENTAL-zrpc-attestation-v1`.
No approved release used the old bytes. The raw nonce, label and 64-byte length
remain the only exporter inputs; no new cryptographic primitive is introduced.

The exporter context is public, which is appropriate here: connection secrecy
comes from the TLS handshake, while the fresh nonce prevents a cached quote on
the same connection from answering another challenge. A separate TLS connection
has a different exporter even with the same nonce. A relay that terminates TLS
cannot quote its own exporter under the approved guest measurement; a transparent
relay leaves the guest owning the actual TLS connection. These properties
depend on the quote being genuine, the approved image keeping its key and quote
operation private, and the client's release policy matching that image.

## Source checks

- `PublicBootstrapTls` exposes no caller write or stream extraction API.
  `PendingChallenge` owns one OS-generated nonce and can send only the public
  nonce request. The existing-stream Hyper client has no connector or retry.
- Client and server reject TLS versions other than 1.3, non-full handshakes,
  wrong ALPN, resumption and 0-RTT. The server generates ephemeral in-process
  keys; both sides install `NoKeyLog`.
- Both sides use the same constant from `zrpc-protocol`, with raw challenge
  bytes as context. The authenticated quote comparison and connection-lifetime
  checks precede client session promotion. `VerifiedRpcSession` is opaque,
  single-use and connection-owned.
- The guest's quote broker accepts only the wrapper UID on local Unix sockets
  and has fixed ConfigFS paths. Effective broker and guest isolation still
  require the exact image on real TDX.

## Evidence and remaining release gate

The existing Rustls test checks same-session agreement and rejects a changed
challenge, label and connection. The server's local TLS test checks that its
quote request received the same export as the client. GCP rejection tests
observe no private body when the quote or nonce is wrong. The exact new label
bytes have a fixed encoding assertion.

The combined `bash scripts/check.sh --browser` suite passed in the managed
untrusted browser container on 2026-09-26, including these transport,
dashboard, and guest-source checks. The documentation-boundary scanner and
`git diff --check` also passed. These are local tests, not hardware evidence.

The tests use Rustls at both ends. A maintained second implementation known
answer for the 32-byte-context exporter, plus an independent protocol review
of the final release artifact and its boot/key-ownership assumptions, remains
a release gate. No local result can substitute for a genuine quote from the
exact production image or for the empty client approval catalog.
