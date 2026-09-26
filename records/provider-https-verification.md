# Read-only provider HTTPS foundation — 2026-09-25

Contract: implement the transport needed by external lifecycle reconciliation
without invoking it against Phala, exposing resource mutations, using real
credentials, installing jobs, or claiming that a page proves cleanup.

## Boundaries

The production origin is fixed to `cloud-api.phala.com:443`. The maintained
Rustls/Ring verifier performs normal certificate-chain, validity, hostname and
handshake verification against explicit operator-trusted DER roots. This is
separate from the deliberately untrusted public attestation bootstrap. TLS 1.3
and HTTP/1.1 are required; resumption, early data and key logging are disabled.
Compatibility with the live provider has not been exercised.

The client exposes fixed GET operations only. It has no endpoint override,
generic method/header/body interface, mutation, RPC, credential environment
lookup, proxy setting, redirect following, or application-request retry. Tests
may inject a loopback socket only inside the test build. Production DNS resolves
the fixed provider hostname; this operator control-plane client is separate from
the mandatory-Tor private-query path and cannot send private RPC selections.

`authenticate` calls the pinned `/api/v1/auth/me` operation with API version
`2026-06-23` and the explicit workspace. Only an exact returned workspace match
creates `ScopedReads`. Each later request retains those headers. Optional
per-CVM workspace data stays distinct from authenticated request scope; a
contradictory workspace fails. A detail 404 remains only an API observation.

`provider_request` builds origin-form routes for identity, inventory, CVM detail
and usage. Existing percent-encoding 2.3.2 encodes opaque identifiers and date
parameters. Empty IDs, literal slash/backslash separators and pure dot segments
are rejected. The pinned SDK defines returned IDs as strings, so no invented
canonical-ID regex or alias rewrite is added. This makes no claim about provider
double-decoding. Page/limit ranges come from the pinned OpenAPI. Usage dates are
explicit UTC RFC 3339 values; the future runner must bind them to the ledger's
original start and one scan cutoff. No provider default can silently choose a
seven-day window in the builder.

Positive time and response-body budgets are required from the caller. One
monotonic deadline starts during client construction and is retained through
authentication and subsequent reads, including DNS, TCP, TLS, HTTP, body
collection and post-decoding checks. A later page never receives a new deadline.
The response byte limit applies while reading, not just to Content-Length.
Provider error bodies are discarded; errors contain fixed categories only.

`ProviderFiles` loads explicit absolute key and DER-root files before constructing
the client; it performs no network operation. A caller-supplied positive per-file
bound is enforced against descriptor metadata and bytes actually read. Final
symlinks, nonregular files and dot traversal are rejected. O_NONBLOCK prevents a
FIFO from hanging the loader. API keys must be owned by the effective user and
inaccessible to group/others; trust roots may also be root-owned and may be
publicly readable, but not group/world writable. Parent-directory integrity and
hostile same-UID mutation remain operator filesystem trust assumptions.

Credential bytes are not trimmed or normalized. The maintained HTTP header
parser validates them, the header is marked sensitive, and `ApiKey` exposes no
Debug/Serialize/raw getter. Temporary input vectors are zeroized; this is not a
claim about erasing HTTP/TLS internal copies. No actual key is stored in this
repository. New tests use explicitly synthetic credentials and ephemeral test
certificates only.

All dependencies already existed at identical versions/checksums in Cargo.lock.
The scoped lock update added and removed zero package versions. The newly direct
percent-encoding pin is included in the existing dependency guard. No production
certificate bundle or provider endpoint was fetched during this implementation.

## Verification

The focused managed-container lifecycle run passed 81 unit tests and five
compile-fail documentation tests. The new tests exercise exact GET routes and
headers, real certificate/name rejection before API application bytes, workspace
and page mismatches, detail identity mismatch, fixed status errors, redirect
refusal, exact/oversized Content-Length and chunked bodies, original-deadline
expiry, post-parse expiry, cancellation closing the driver socket, TLS/key-log
configuration and credential redaction. Input tests cover file permissions,
symlinks, dot traversal, empty/oversized files, nonblocking FIFO rejection,
malformed trust roots and invalid credential/header bytes. Request tests cover
URI metacharacters, documented pagination bounds and UTC date overflow.

All HTTP fixtures run on loopback with synthetic CA/leaf certificates and
synthetic API keys. Their socket override is test-only; the production TLS
hostname remains fixed for real hostname verification. No live-provider
compatibility or DNS-network trace is claimed.

Full `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed in the
same managed untrusted browser-profile Linux shell: 183 workspace unit tests,
21 compile-fail documentation tests, 14 runtime-guard tests, dependency/fixture
guards, CLI/public-inspector/wrapper checks and required builds. No UI or user
docs changed, so this pass did not repeat visual QA or the user-doc scanner.

## Remaining work

There is no provider-read CLI or complete inventory/usage scanner yet. The API
client does not automatically persist observations, resolve usage/CVM identity
mapping, reconcile an interrupted deletion, or dispatch DELETE. Connecting these
pieces to the original ledger, testing external activation, and obtaining
independent disk/billing evidence remain prerequisites. No cloud privacy or
cleanup gate is closed by local TLS fixtures. No deployment or spending occurred.
