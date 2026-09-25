# Local ephemeral TLS listener — 2026-09-25

Contract: make the existing public attestation service runnable locally with an
owned ephemeral TLS identity, admission before handshake, one accepted-socket
lifetime, and owned cancellation. No private-mode acceptance, RPC route,
cloud deployment, credential use, or spending is added.

## Implementation

`BoundPublicListener` generates a P-256 key through pinned rcgen 0.14.10 and Ring,
loads borrowed PKCS#8 through maintained Rustls `any_ecdsa_type`, checks the
certificate/key match and installs `SingleCertAndKey`. The API has no key import,
export or configuration getter. `Zeroizing<KeyPair>` wipes rcgen's serialized
buffer on drop; this is not a complete erasure claim about Ring internals or
process memory. Default rcgen certificate dates are untrusted metadata, not
freshness evidence. See `ephemeral-tls-research.md` for immutable source references.

The listener owns every connection task. A shared permit is acquired before
spawning TLS work. The design's 300-second deadline starts when a socket is
accepted and includes TLS, HTTP and dstack work. HTTP reads/writes and quote
completion also check that original deadline. Shutdown drains owned tasks;
cancelling the listener future aborts its task set. TLS 1.3, HTTP/1.1 ALPN,
no resumption, no 0-RTT, no key logger and no secret extraction are explicit.

The executable requires an explicit numeric loopback address, absolute dstack
socket, positive connection/quote limits and positive quote spacing. No quota
defaults were invented. Its status reports unverified evidence and false private
acceptance, query dispatch and deployment. SIGINT/SIGTERM close the listener and
accepted work. The only served route remains nonce-only `/attestation`.

Dependency receipt `listener-dependency-receipt.json` records checksum, registry
publication/yank status and workspace seven-day hold checks for all 21 lock
additions. Seven occur in the actual native normal/build graph, with no new build
scripts or procedural macros. Optional X.509/PEM/AWS-LC features are inactive;
the regression guard checks the selected Cargo tree rather than treating every
metadata edge as active. Existing reviewed build inputs remain unchanged.

## Verification

Focused managed-container server run passed 38 unit tests and one compile-fail
test. New tests exercise fresh public keys and full signed handshakes, disabled
resumption/early data, admission before TLS, total handshake/HTTP deadline,
stalled handshake and ALPN rejection, shutdown/cancellation, exporter binding
through a synthetic Unix quote fixture, and cancellation of pending guest work.

The executable integration check passed: invalid/public/missing/repeated options
refuse without listening; RPC is rejected without reflecting input; absent
dstack fails safely; public certificates stay stable within a process and differ
after restart; SSLKEYLOGFILE is ignored; SIGINT and SIGTERM close established and
incomplete handshakes, followed by refusal of new connections. No private key
artifact is written by the harness.

Final `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed in the
managed untrusted browser-profile Linux container: 141 workspace unit tests,
16 compile-fail documentation tests, 14 runtime-guard tests, dependency/feature
and fixture guards, CLI/public-inspector/wrapper checks, and CLI/wrapper/example
builds. The user-doc boundary scanner passed for README and the wrapper guide.

The first full run passed its Rust tests but then failed while compiling an
object for the CLI build with `Permission denied` under `target/debug/deps`.
Container UID 502 owned the 0755 directory, it was writable, and the named failed
object did not exist. The unchanged full command passed on retry, matching the
previously recorded transient container output-write symptom. No permissions,
dependencies, code or shared execution policy were changed for that retry.

## Limits

Quote fixtures are explicitly synthetic. No live TDX quote was obtained, no
approved release provenance or production key-ownership policy was established,
and no Tor process was certified. The host/guest can still access process memory
unless the unresolved environment policy is satisfied. The production image,
no-administration rule, KMS/disk policy, current quote and independently tested
external deletion remain gates. No Phala resource was created or credit spent.

No UI files changed, so this pass does not repeat visual tests. Real lifecycle
adapter details and outstanding provider evidence are in
`live-lifecycle-adapter-plan.md`; that plan performs no API calls or scheduling.
