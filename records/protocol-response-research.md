# Protocol response parser research — 2026-09-25

Scope: a dependency and fixture candidate for design §9's protocol-aware response
identity checks. This is source/registry research, not a completed integration,
consensus validation result, deployment approval, or private-mode acceptance.
No dependency installation, compilation, node execution, or cloud call occurred
in this research. The source design supplies requirements, not authorization.

## Candidate

Use **`zcash_primitives = "=0.30.1"` with `default-features = false`**, and
**`zcash_protocol = "=0.10.5"` with `default-features = false`** for `BranchId`.
The same maintained library already supplies both the transaction decoder and
the block-header decoder; a separate header implementation is unnecessary.
Its unconditional `no_std`/`alloc` modules expose the needed parse/hash/display
operations without `std`, `circuits`, `multicore`, `transparent-inputs`, or
test-dependency features. That feature choice is supported by source inspection;
the exact locked graph and managed compilation still need verification.

Both crates resolve to official librustzcash release source commit
`97aefdc39a037da9c4f19a0e8a450d2c7932f53e`. The annotated
`zcash_primitives-0.30.1` tag object is
`439435914db3e1d7aeb680c2bfbe216a3faf653f` and points to that commit.
The workspace source declares Rust **1.88**, edition 2024, and
**MIT OR Apache-2.0**. The local project now declares Rust 1.89.
[Tag object](https://api.github.com/repos/zcash/librustzcash/git/tags/439435914db3e1d7aeb680c2bfbe216a3faf653f),
[workspace manifest](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/Cargo.toml#L24),
[crate features](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/Cargo.toml#L96),
[unconditional modules](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/lib.rs).

Primary crates.io sparse-index records report both non-yanked and Rust 1.88:

| Crate | Published UTC | Archive SHA-256 |
|---|---|---|
| `zcash_primitives 0.30.1` | 2026-08-19 22:21:56 | `403d5be1e96339534be098e3377fb8a78d68ca7585b1780133d884b810277418` |
| `zcash_protocol 0.10.5` | 2026-08-19 22:19:25 | `314329b91ec4bbb517441840e47d0b2029bf0b946f086980c96c889c2d92dc5d` |

These publication dates pass the workspace's existing seven-day release hold
as of 2026-09-25. This is top-level eligibility, not a claim that unreviewed
transitive selections pass. Preserve exact direct pins and the committed lock;
inspect newly selected build scripts/procedural macros and apply the managed
dependency workflow before compiling.
[Primitives registry metadata](https://index.crates.io/zc/as/zcash_primitives),
[protocol registry metadata](https://index.crates.io/zc/as/zcash_protocol).

## Parsing and identity behavior

- `block::BlockHeader::read(&mut remaining)` parses the full Zcash header,
  including CompactSize-encoded Equihash solution. `header.hash()` is SHA-256d
  over its maintained serialization; `Display` returns the byte-reversed RPC
  hexadecimal convention. Use this implementation rather than reimplementing
  header layouts, SHA-256d, or endian conversion.
  [Header implementation](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/block.rs#L109).
- `transaction::Transaction::read(&mut remaining, BranchId::Canopy)` dispatches
  legacy/v4 to the maintained `HashReader`, which SHA-256d-hashes the consumed
  serialization. In this identity-only use, the supplied pre-v5 branch is stored
  in transaction metadata but does not change that txid; it is not evidence of
  the transaction's network, mined height, or consensus validity. The upstream
  real testnet v4 test itself uses `Canopy` for a transaction from block 280003.
  [Dispatch and v4 implementation](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/mod.rs#L736),
  [maintained SHA-256d reader](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_transparent/src/util/sha256d.rs#L4),
  [upstream v4 fixture assertion](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/tests.rs#L40).
- V5 instead reads its consensus branch from the serialized header and computes
  `to_txid(..., TxIdDigester)`, the maintained ZIP 244 personalized BLAKE2b
  component digest. Never apply legacy SHA-256d to v5 transaction bytes.
  `tx.txid().to_string()` supplies the RPC convention. A v5 txid commits to
  effecting data, not all authorizing bytes; a matching ID is not a proof of
  signatures, proofs, inclusion, or validity. Upstream tests check `txid` and
  `auth_digest` separately. No new consensus-proof protocol is proposed.
  [V5 digest construction](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/mod.rs#L708),
  [wire branch parsing](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/mod.rs#L850),
  [txid semantics and display](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/components/zcash_protocol/src/txid.rs#L10),
  [ZIP 244 assertions](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/tests.rs#L960).
- These are **stream parsers**, not EOF-enforcing helpers. Start with a mutable
  `&[u8]` and require `remaining.is_empty()` after success. This avoids assuming
  `std::io::Cursor` implements the crate's `corez::io::Read`, and rejects a valid
  object followed by garbage or a second object. Preserve the existing decoded
  response bound before parsing. Malformed hex, parse errors, trailing bytes,
  and calculated/requested identifier mismatch must return the fixed backend
  failure, with no raw response or selection logged.

The existing adapter's raw-hex and echoed-identifier checks do not establish
these properties. For verbose transaction output, decode its actual `hex` and
compare the calculated txid to both the requested ID and returned field. For
verbose header output, identity checking requires the maintained header value
constructed from every serialized header field, or an associated raw-header
response under the same existing admission/deadline policy. Merely comparing
the JSON `hash` field remains insufficient; uncommitted metadata such as
confirmations/height must not be described as cryptographically verified.

## Public immutable fixtures

Preserve upstream provenance/license notices if copying selected fixture bytes.
Use only the selected byte constants or snapshots, rather than enabling the
upstream test feature graph. Git blob IDs below identify source file contents;
they are **not** Zcash transaction/block hashes or download SHA-256 digests.

| Fixture | Immutable source and expected result | Size/source identity |
|---|---|---|
| Real testnet v4 transaction | librustzcash commit above, `zcash_primitives/src/transaction/tests/data.rs`, `tx_read_write::TX_READ_WRITE`; testnet block 280003; RPC txid `64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639` | Exactly 2005 transaction bytes; containing file 684905 bytes, blob `df009b2dabd2137ec4b6b1ef9ee63b34462dd465` |
| Public synthetic v5 protocol vectors | Same file, `zip_0244::make_test_vectors()`; each contains full `tx`, expected internal-order `txid`, and separate `auth_digest`; upstream test compares these with maintained parser results | Module starts line 5698; full arrays, not live/testnet-chain evidence |
| Real testnet raw header and JSON reference | Zebra v6.3.0 commit `f5c5277fe41eba9c74f37098738f93f35dd70d60`, paired `zebra-rpc/src/methods/tests/snapshots/get_block_header_hash@testnet_10.snap` and `get_block_header_hash_verbose@testnet_10.snap`; header height **1**, hash `025579869bcf52a989337342f5f57a84f3a28b968f7d6a8307902b065a668d23` | Snapshot files 3051 / 3501 bytes; blobs `7942eddd2e2f6581b6f6cdc385eef27ec6b5411a` / `03ae04e2e84a983a12fe9596d37fb118ddfe9135` |
| Optional real testnet v5-containing block | Same Zebra commit, `zebra-test/src/vectors/block-test-1-842-421.txt`; upstream describes a v5 transaction with four Sapling spends and two Orchard actions | 24735 ASCII-hex file bytes, blob `1e77de6e1177bd03326d4d2b10bffacf00d06ac4`; its individual txids were not independently extracted in this research |

[V4 byte constant](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/tests/data.rs#L1),
[V5 arrays and expected digests](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/tests/data.rs#L5698),
[raw header snapshot](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-rpc/src/methods/tests/snapshots/get_block_header_hash%40testnet_10.snap),
[verbose header snapshot](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-rpc/src/methods/tests/snapshots/get_block_header_hash_verbose%40testnet_10.snap),
[v5-containing testnet block](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-test/src/vectors/block-test-1-842-421.txt),
[upstream block description](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-test/src/vectors/block.rs#L272).

## Dependency comparison and smallest verification

`zcash_primitives 0.30.1` has **21 nonoptional normal direct dependencies** in
the published registry metadata; it still necessarily parses shielded bundles
using Orchard/Sapling libraries. Selecting `std` additionally enables the
optional `document-features` dependency. Default features enable circuits and
multicore, which these parsing operations do not require. Two mandatory
upstream pins are prereleases (`block-buffer =0.11.0-rc.3` and
`crypto-common =0.2.0-rc.1`); do not silently substitute different versions or
claim the dependency closure contains only stable releases.

The eligible Zebra v6.3.0 release packages `zebra-chain 12.0.0` (published
2026-08-10 19:27:17 UTC, Rust 1.88, MIT OR Apache-2.0), with **54 nonoptional
normal direct dependencies**. Its graph includes `zcash_primitives` with default
features plus `transparent-inputs`, and additional chain/consensus/runtime
support such as Halo2, Rayon, futures, secp256k1, serde tooling, and tempfile.
There is no need to add that broader dependency for the two requested parsers.
Counts are direct manifest/registry counts, not transitive totals or measured
binary/build sizes. No resolved graph or binary size is claimed.
[Zebra manifest](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-chain/Cargo.toml),
[Zebra registry record](https://index.crates.io/ze/br/zebra-chain).

The next local implementation should prove: upstream expected header/v4/v5
identifiers; raw and verbose agreement where bytes are available; valid objects
with appended bytes rejected; truncated objects and malformed encodings rejected;
and a structurally parseable effecting-field mutation rejected against the
original requested ID. Include a v5 authorizing-data mutation demonstration
when describing the txid guarantee, so the test suite does not accidentally
assert that v5 txid authenticates every returned byte. Existing network,
admission, deadline, and private-mode gates remain unchanged. These tests and
the managed locked build have **not** been run by this research task.
