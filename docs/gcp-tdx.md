# Google Cloud TDX

The native client defaults to `gcp-tdx`. Use `--platform phala-dstack` and
`--app-compose FILE` for the separate Phala backend. Google commands reject
`--app-compose`; the formats cannot substitute for one another.

Private mode requires a release embedded in the native client. This build has
none. Diagnostic policies and fixture measurements cannot enable private mode.

## Inspect evidence

Offline inspection uses an exact binary Intel quote, signed local collateral,
a binary CCEL, and independently reconstructed boot expectations:

```sh
cargo run --locked -p zrpc-cli -- inspect-workload --platform gcp-tdx \
  --quote quote.bin --collateral collateral.json --event-log ccel.bin \
  --policy gcp-workload-policy.json
```

The GCP policy contains expected MRTD, all four RTMRs, the ordered boot-event
reference, the UKI PE/COFF measurement, and artifact commitments. Obtain these
from reviewed firmware and build outputs. Do not turn a received quote into a
policy. Inspection checks signed measurements and CCEL entries against the
supplied references, including the UKI PE/COFF measurement. It does not derive
the other artifact hashes or firmware-endorsement hash from that evidence;
their provenance reports `not_checked`. Establish the relationship between
those commitments and the measured boot bytes before packaging a release.

To inspect a compatible wrapper through a local Tor installation:

```sh
cargo run --locked -p zrpc-cli -- inspect-endpoint --platform gcp-tdx \
  --endpoint-host "$ZRPC_ENDPOINT_IP" --endpoint-port "$ZRPC_ENDPOINT_PORT" \
  --socks 127.0.0.1:9050 --collateral collateral.json \
  --policy gcp-workload-policy.json
```

Set the SOCKS address to your actual local Tor listener. IPs remain numeric
SOCKS destinations; hostnames use remote DNS. No endpoint is contacted directly.
The client trusts your Tor installation; SOCKS negotiation does not prove that
the proxy is Tor. Collateral is supplied locally, with current-clock expiration
checks and no automatic downloads.

Inspection sends only a fresh nonce, compares authenticated evidence with the
original TLS session's exporter, then closes the connection. Its output never
grants release approval. Google project/zone/instance provenance is not appraised
by this workload comparison.

## Native queries and dashboard

`verify`, `query --stdin`, and `dashboard` share these connection options:

```sh
cargo run --locked -p zrpc-cli -- verify --platform gcp-tdx \
  --endpoint-host "$ZRPC_ENDPOINT_IP" --endpoint-port "$ZRPC_ENDPOINT_PORT" \
  --socks 127.0.0.1:9050 --collateral collateral.json \
  --release-policy config/release-policy.example.json
```

Replace `verify` with `query --stdin` or `dashboard` as appropriate. With the
empty release catalog, queries refuse before reading stdin or opening Tor.
The dashboard receives queries locally and delegates verification and transport
to Rust. `demo` remains a separate simulation with no cloud connection.

## Guest and deployment

The guest source profile is under `deploy/gcp/guest`. Zebra, the wrapper,
quote broker, and startup guard run as direct processes. Code and configuration
belong in the authenticated read-only image; writable durable storage is reserved
for public node state. Runtime state and TLS keys belong in memory.

The guest preparation tool checks the pinned Debian snapshot signature, package
index, and local package archive hashes before staging source files. Its
`preflight` command reports missing build capabilities. Staging does not
authenticate the complete builder toolchain, build or approve an image, or
establish Zebra release eligibility. Image building requires a supported
managed Linux environment; ordinary CLI development does not require
image-building privileges.

Record the `manifest_sha256` and `manifest_bytes` returned by `stage` outside
the staged directory. Immediately before handing that directory to a builder,
check its complete input inventory against those recorded values:

```sh
python3 tools/gcp-guest/prepare.py verify-stage \
  --output "$STAGE_DIR" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --expected-manifest-bytes "$MANIFEST_BYTES"
```

This checks staged bytes at inspection time. It does not freeze the directory,
inspect a built disk, or grant private-mode approval.

`zrpc-gcp-lifecycle` provides local package preparation and separate operator
actions. Run its `--help` for exact inputs. A package binds image identities,
resource configuration, current pricing, and the original evaluation deadline.
Preparation does not create cloud resources or activate deletion timers.

Deployment requires explicit spending approval for that package and working
external cleanup controls. The evaluation remains limited to 168 hours,
including synchronization. No Phala budget is applied to Google resource sizing.
Stopping a VM is insufficient cleanup: retain the ledger until tracked resources
are deleted and billing is reconciled. Keep cloud credentials outside the guest.
