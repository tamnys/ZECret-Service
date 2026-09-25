# Local public attestation wrapper

`zrpc-wrapper` serves the public nonce-only attestation protocol on an explicit
numeric loopback address. It has no RPC route, private-query authorization or
deployment operation. Its status always reports `private_accepted: false`.

Build and inspect its required arguments inside the supported Linux environment:

```sh
cargo build --locked -p zrpc-server --bin zrpc-wrapper
./target/debug/zrpc-wrapper --help
```

Every setting must be supplied. Select a loopback IP and port (port `0` asks the
OS for an available port), an absolute dstack Unix-socket path, positive global
connection and quote limits, and positive quote spacing in milliseconds. Limits
must come from the intended environment's reviewed resource configuration;
there are no production defaults.

```sh
./target/debug/zrpc-wrapper \
  --listen "$WRAPPER_LOOPBACK_ADDRESS" \
  --dstack-socket "$DSTACK_UNIX_SOCKET" \
  --max-connections "$WRAPPER_CONNECTION_LIMIT" \
  --max-quotes "$WRAPPER_QUOTE_LIMIT" \
  --quote-spacing-ms "$WRAPPER_QUOTE_SPACING_MS"
```

The process emits its actual listening address as JSON. `SIGINT` or `SIGTERM`
closes the listener, accepted sockets and pending quote work. A Linux container's
loopback is inside that container; this command does not publish a host or cloud
port. Starting it does not create a VM or consume Phala credits.

Each startup generates a fresh P-256 TLS identity in process memory using
rcgen and Ring. No key import, export, file or key-log option is available. TLS
uses version 1.3 and HTTP/1.1 ALPN with resumption and early data disabled. The
self-signed certificate is bootstrap metadata, not a trusted endpoint identity;
do not install it into a trust store. Certificate dates do not establish quote
freshness or a deployment deadline.

Connection admission happens before TLS negotiation. Each accepted connection
has the design's total 300-second lifetime, including handshake, HTTP and quote
work. `POST /attestation` accepts one 32-byte nonce per TLS connection. The
wrapper requests dstack `/GetQuote` over the explicit Unix socket with the
proposed session exporter binding. It does not interpret the guest's returned
quote as independently verified. A missing socket produces a sanitized refusal.
Other routes, including `/rpc`, are unavailable.

The [native public inspector](public-inspection.md) can inspect compatible
endpoints through its mandatory explicit SOCKS path. No browser-to-wrapper
private-query path is provided. Live hardware, approved release provenance,
freshness and key ownership, guest access policy, disk/KMS policy, and external
deletion requirements still govern any future genuine private service.
