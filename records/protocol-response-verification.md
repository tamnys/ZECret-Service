# Protocol-aware response integration

Scope: design §9's response-identity checks in the internal loopback-node adapter.
No public RPC listener, private-mode acceptance, node deployment, wallet API,
customer keys or cloud operations are introduced. This is not a consensus-proof
protocol, and it does not establish live testnet readiness or inclusion.

The maintained parsers are `zcash_primitives =0.30.1` and
`zcash_protocol =0.10.5`, with all default features disabled. The source selection,
parser APIs and upstream expected identifiers are recorded in
`protocol-response-research.md`; public fixtures and MIT licenses are under
`tests/fixtures/zcash/`. Expected identifiers come from upstream tests rather than
the new implementation. The existing 16 MiB response policy remains authoritative.

Dependency resolution added 64 locked registry package versions and removed none
of the prior locked versions. Downloaded crate archives were SHA-256 checked
against both Cargo.lock and the primary crates.io version API. The initial
resolution selected `thiserror`/`thiserror-impl 2.0.21`, published September 23,
2026, which did not pass the workspace release hold. Neither was compiled.
The compatible `2.0.20` pair, published August 8, replaced them using a scoped
managed Cargo mutation. All final additions are non-yanked and pass the seven-day
hold; the newest publication is September 13, 2026. The complete version, checksum,
publication and source-URL receipt is `protocol-dependency-receipt.json`.

Upstream compatibility requires these prerelease versions: `bip32 0.6.0-pre.1`,
`block-buffer 0.11.0-rc.3`, `crypto-common 0.2.0-rc.1`,
`digest 0.11.0-pre.9`, `hmac 0.13.0-pre.4`, `ripemd 0.2.0-pre.4`, and
`sha2 0.11.0-pre.4`. The graph is not represented as containing only stable
releases. These are maintained upstream dependencies; no wallet interface,
signing flow or transaction construction is exposed by the wrapper.

The resolved feature graph leaves primitives, protocol, Orchard, Sapling,
transparent parsing and Equihash crate features empty. The existing guard now
checks that restriction, both direct parser pins, the reviewed dependency
checksums, public fixture hashes and license hashes. It still checks the offline
quote verifier's absence of network-fetch/override features and Ring-only TLS.
Build-script and procedural-macro execution review is recorded separately in
`protocol-build-input-review.md` before any scoped build opt-in.

Managed extraction checked exact sizes and Git blob identities for five immutable
official source files before parsing arrays/snapshot JSON as data. No upstream
Rust code or new cryptographic hash implementation ran in fixture extraction.
The v4 transaction and raw/verbose header are public testnet fixtures; v5 inputs
are upstream synthetic ZIP 244 vectors. A separately labeled derived v5 fixture
changes one scriptSig byte. It must demonstrate that equal v5 txids do not
authenticate every authorization byte or establish validity.

`node::identity` now requires complete maintained parsing before comparing raw
header hashes or transaction IDs with the requested identifier. Verbose
transactions must provide parseable `hex` and a matching `txid`. A verbose header
causes a raw-header companion call on the same already-network-checked connection,
under the same admission permit and original deadline. The parser's header hash
must match the request; version, predecessor, merkle root, commitment slot, time,
bits, nonce and solution must agree with the verbose response.

Header rendering follows the pinned
[Zebra RPC implementation](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-rpc/src/methods.rs)
and its
[commitment semantics](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-chain/src/block/commitment.rs).
Maintained testnet activation heights select the format. Reported height is an
unverified formatting input, not proven chain position. After Heartwood the
returned Sapling tree root is separate state metadata; only its representation
is checked. Confirmations, difficulty, next-block hash, decoded transaction
vin/vout, signatures, scripts, proofs and inclusion are not authenticated by
these identity comparisons.

The pinned
[encoding helpers](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/components/zcash_encoding/src/lib.rs)
reject noncanonical and above-codec-limit CompactSize values. Vector collection
reads elements until the first decoding failure rather than reserving the
declared element count. The maintained decoder's own count bound is reused;
no additional count cap was invented. Tests exercise tiny payloads declaring
maximum, above-maximum, noncanonical and truncated counts. The operation also
rechecks its original 15-second deadline after synchronous decoding: late
results are rejected, but CPU preemption is not claimed.

The focused managed server suite passed all 30 tests. Seven new identity cases
cover upstream header/v4/v5 identifiers, raw/verbose agreement, malformed and
trailing data, mismatches, forged verbose fields, activation-format boundaries,
forged lengths, and effecting versus authorizing mutations. Three added adapter
cases cover actual local HTTP rejection, the companion connection/deadline and
capacity, and late synchronous results. The v5 pair was confirmed by maintained
parsing to have the documented distinct scriptSigs, equal txids, and different
authorizing commitments; the original commitment matches upstream's expected
digest. Original admission, cancellation, network, size and error tests still pass.

The first server test build and first full workspace build each encountered a
permission-denied object-file creation under the workspace target directory
(server and lifecycle test artifacts respectively). The directory belonged to
the current UID/GID and was writable; each named object was absent on inspection.
The server retry passed without source, permissions or policy changes. The full
workspace retry result is below. These observations do not establish a root cause
or broader filesystem reliability.

The identical full workspace retry passed. Final managed execution used
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh`, scoped to the reviewed
locked inputs. It passed all 133 workspace unit tests, 15 compile-fail documentation
tests, 14 standalone runtime-guard tests, CLI checks, parser/verifier/TLS
feature-and-checksum guards, formatting and CLI/example builds. The fixture
provenance document passed the user-docs boundary check. No UI source changed;
browser layout tests were not repeated. The working tree contains no environment
or shared-container policy override.

The live Zebra release has not been run against a synchronized node in this pass.
Public fixtures and local HTTP peers are the validation inputs. Genuine client
acceptance, approved release provenance, Phala gates A–E and external deletion
activation remain unresolved. No deployment, cloud resource or spending occurred.
