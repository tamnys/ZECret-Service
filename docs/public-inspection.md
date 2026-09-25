# Public endpoint inspection

`inspect-endpoint` sends a public nonce through an explicitly configured local
SOCKS service and inspects the returned attestation locally. It accepts no RPC
query and closes the connection after inspection. It cannot enable private mode.

From the managed development shell, after building the CLI:

```sh
./target/debug/zrpc inspect-endpoint \
  --endpoint-host "$ZRPC_ENDPOINT_HOST" \
  --endpoint-port "$ZRPC_ENDPOINT_PORT" \
  --socks "$ZRPC_SOCKS_ADDRESS" \
  --collateral collateral.json \
  --app-compose app-compose.json \
  --policy workload-policy.json
```

Set the endpoint variables to the hostname and port of an operator-selected
compatible diagnostic endpoint. No endpoint is deployed by this repository.
`ZRPC_SOCKS_ADDRESS` must be an explicit numeric IPv4 loopback address and nonzero
port for your Tor SOCKS listener. Endpoint IP addresses and URLs are rejected;
the hostname is sent to SOCKS for remote resolution. There is no direct fallback
or environment-proxy discovery. Each invocation generates a fresh stream-isolation
credential. The command cannot establish that the local SOCKS process is Tor;
the output reports `tor_process_identity_verified: false`.

Use the collateral, exact raw app-compose bytes and independently obtained local
policy described in [offline evidence inspection](offline-evidence.md). There are
no default measurements, collateral downloads or historical-clock overrides.
Arguments and policy are validated before dialing. Provider-returned verification
flags, echoed report-data strings and VM configuration never establish authority.

The endpoint must implement this repository's nonce-only `POST /attestation`
protocol over a full TLS 1.3 handshake with `http/1.1` ALPN. Its quote must bind the
same connection's proposed TLS exporter encoding from
[ADR 0002](adr/0002-public-tls-bootstrap.md). An ordinary Phala dashboard,
gateway, or dstack API URL is not a compatible substitute. TLS certificate
signatures prove handshake-key possession; certificate identity is deliberately
untrusted until independently appraised evidence establishes ownership.

The report separates hardware authenticity, strict security appraisal, workload
comparison, authenticated REPORTDATA equality and local session checks. Exit
status zero means these diagnostic comparisons passed. It does **not** mean an
approved release or private channel exists: release-policy provenance, approved
workload ownership, freshness and live-key binding remain `not_checked`.
`private_accepted` and `query_sent` remain false, and deployment remains disabled.
Failures return a nonzero exit status without printing raw evidence or session
secrets.

The operation includes connection setup and inspection within the design's
five-minute connection budget. The local OS and clock remain trusted. The local
dashboard continues to use its fixture client; it exposes no endpoint inspection
or browser-to-cloud query path.
