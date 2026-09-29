# Payment POC dependency gate — 2026-09-29

Status: **partial storage, wire-format, private file exchange, HTTP header codec, read-only CLI, and separately locked local cryptography; integrated POC incomplete**. The new `zrpc-payments` crate contains separate SQLite stores, internal RFC 9578 type-2 wire values, and versioned batch files. `zrpc payments balance` reads counts from an existing private client store. A separate local helper now performs blind, sign, finalize, and public verification operations but is not connected to the CLI or RPC server. No paid RPC admission, simulated-settlement CLI, or live testnet redemption is enabled.

## Requested outcome and acceptance

Implement the approved CLI-first prepaid Privacy Pass type-2 ticket plan: persistent simulated issuance, private ticket-authorized testnet queries, and duplicate issuance/redemption rejection across ordinary restarts. The requested `blind-rsa-signatures =0.17.2` dependency must pass dependency-policy checks and standard vectors before integration. No custom cryptographic replacement is authorized if that gate fails. Approved private deployment remains an external dependency.

## Environment and observed blocker

- Base commit: `ec2d90932c00400b3e9a741d2fd1361a7a14a205`, recorded `origin/main`.
- Isolated branch: `codex/payment-tickets`.
- Verification environment: managed untrusted Linux amd64 container, Cargo/Rust 1.94.1.
- Original `Cargo.lock` SHA-256: `61c01dda40caae8525ef5bf6a39b74f9ade3bf07fe1a031790ad5bf33c90c7a0`.
- Current `Cargo.lock` SHA-256 after adding SQLite, CLI, and existing locked file/header dependencies: `ebc4b42230b9742a0481c4c6cf12646b9a72caf383fc6b86eab698ae5f907028`.

Official crates.io sparse-index metadata confirmed that `blind-rsa-signatures 0.17.2` is not yanked and was published on `2026-05-21T07:44:08Z`. Its checksum is `f7c8e1ec3966bafbe115ad484420b260f5fabf88528e4ef8cd3024ffedb50e46`. The repository's seven-day release-age check passed for that release. A separate scratch crate resolved the exact dependency and passed the repository's release-age preflight for its 57 registry packages after pinning three transitive packages to eligible releases. Its lockfile SHA-256 is `1329892e261f86b1f477d42137898a0fffac2084ba29d7d99de41d81e64b328d`. That separate graph does not resolve the service workspace conflict.

Adding the requested dependency to a new workspace payments crate and resolving with the managed reviewed-mutation gate failed:

```text
error: failed to select a version for `crypto-common`.
    ... required by package `digest v0.11.3`
    ... which satisfies dependency `digest = "^0.11.3"` of package `blind-rsa-signatures v0.17.2`
versions that meet the requirements `^0.2` are: 0.2.2, 0.2.1

all possible versions conflict with previously selected packages.

  previously selected package `crypto-common v0.2.0-rc.1`
    ... which satisfies dependency `crypto-common = "=0.2.0-rc.1"` of package `zcash_primitives v0.30.1`
```

The attempted resolution command was `CODEX_ALLOW_REVIEWED_PACKAGE_MUTATION=1 cargo update --workspace`, through the guarded Cargo entrypoint. It could not produce an updated workspace lockfile. An initial isolated amd64 vector build stalled on a Cargo artifact lock and was stopped. The same exact scratch manifest and lockfile were copied into `/Users/j/Code/payment-rsa-vector-check`, a dedicated top-level folder, and checked in a native untrusted managed container. Its fresh registry preflight passed at `2026-09-29T20:05:08Z`; `cargo fetch --locked` succeeded; `cargo test --locked --test vectors rfc9474` passed the upstream RFC 9474 issuance/finalization vectors. A separate `cargo test --locked --test rfc9578` passed RFC 9578 Appendix A.2 public token vector 1: canonical SPKI round trip and signature verification succeeded, while altered signed input, altered signature, and a different issuer key were rejected. These are isolated primitive-compatibility results, not an integrated service build or live ticket redemption.

Fresh official index reads at `2026-09-29T18:37:25Z` confirmed that `zcash_primitives 0.30.1` is the latest published version and retains the exact prerelease `crypto-common` requirement. No newer published Zcash primitives release was available to remove this conflict. The requirement is not an optional feature in its published metadata. A scratch resolution using the unchanged upstream prerelease `crypto-common` source through a Cargo path patch also failed with the same conflict; no patch was committed.

A fresh `cargo tree --locked -i crypto-common@0.2.0-rc.1` in the service worktree showed multiple dependents, including `zcash_primitives`, `zcash_transparent`, and `bip32` through prerelease `digest`, `hmac`, `ripemd`, and `sha2` packages. The current upstream `librustzcash` workspace manifest still pins `crypto-common =0.2.0-rc.1` and `block-buffer =0.11.0-rc.3`, while its `zcash_primitives` manifest still inherits both. Changing one `zcash_primitives` manifest entry is therefore not a demonstrated resolution; this probe made no source or lockfile change.

The unsuccessful blind RSA workspace dependency was removed. No cryptographic source patches, alternative algorithm, workspace dependency downgrade, approval entry, or live deployment change was made.

## Payment components and verification

`zrpc-payments` is now a workspace crate using exact `rusqlite =0.37.0`, bundled SQLite, and the worktree `Cargo.lock`. A fresh preflight of that lockfile passed on `2026-09-29T21:16:28Z`: 303 registry packages, no release younger than the repository's seven-day hold, no Cargo fetch/build in the preflight. Two pinned Git packages remain outside this registry audit, as before. After adding the HTTP header codec, `cargo test --locked --quiet -j 1 -p zrpc-payments` passed all seventeen tests in the managed untrusted Linux amd64 container.

After connecting the CLI to the local payments crate, `cargo test --locked --quiet -j 1 -p zrpc-cli payments::tests::balance_reads_only_existing_private_store` passed in the managed Linux amd64 container and was rerun successfully against the current lockfile after the header dependency update. The test verifies that a missing database fails closed, a created empty store reports zero counts, and a relative path is rejected. No ticket content is printed.

- Client store: durable pending blinding state and requests, atomic final collection, available/uncertain/spent state, and one transaction that locally validates an available ticket before committing its uncertain state and returning it. A validation failure leaves it available; a concurrent-client test admits only one taker and confirms the uncertain state after reopening. No ticket content enters `balance` or Debug output.
- Issuer store: exact authorized quantity, one request commitment per purchase, persisted blind signatures, identical replay result without re-signing, altered/unpaid rejection. An abrupt child-process exit after writing an uncommitted response leaves no partial issuance after reopening; the authorized batch can then be issued and replayed exactly.
- Redeemer store: issuer-scoped spent marker pair only; atomic insert permits at most one concurrent admission and rejects replay after reopen. A write failure does not admit.
- Store opening: explicit owner-only directories outside Git checkouts, private database files, application/schema identity, full SQLite integrity check, and exact expected SQL schema for all three roles. Added columns, tables, views, indexes, or triggers that could silently retain extra payment records cause a client, issuer, or redeemer reopen to fail closed. Canonical directory selection also rejects an ancestor owned by another non-root user or writable by others without the sticky bit, which could otherwise permit pathname replacement after validation; a sticky shared parent remains allowed.

These storage tests use synthetic bytes, not real signatures. The methods that would collect verified tokens, sign blinded requests, and commit admission remain crate-private and are unreachable from the CLI or RPC server until the cryptographic verifier is implemented. The CLI exposes only read-only `payments balance` and explicitly reports that issuance and paid RPC are unavailable.

The internal wire module now encodes and checks the RFC 9578 type-2 token input, blinded request, blinded response, and unverified token lengths and fields. It rejects wrong token type, truncated issuer key ID, challenge digest, and message length; its sensitive Debug output is redacted. The public challenge, nonce, key ID, and token prefix from RFC 9578 Appendix A.2 vector 1 match the encoded token input. This is a wire-format check only: its intentionally invalid test authenticator is never considered verified, and the module exposes no RPC admission path.

The private exchange module encodes request batches and blind-signature response batches with a versioned binary envelope. The request commitment covers the complete canonical encoded batch; response parsing requires the expected purchase identifier, full issuer key identifier, and request commitment. Length and quantity checks reject truncation, trailing bytes, and malformed envelopes before batch allocation. File output uses an owner-only temporary file, syncs its bytes, then publishes a hard link only if the chosen destination does not already exist. Reads require an explicitly selected private directory, an owner-only regular file with one link, and the exact length derived from the authorized quantity; symlink and hard-link cases are rejected. An abrupt process exit can leave an uncollected private temporary file, but not a parseable partial published batch. This is not cryptographic signing or finalized-token validation; the module remains crate-private until those gates are implemented.

The internal HTTP module formats `Authorization: PrivateToken token="..."` and parses canonical base64url type-2 credentials per RFC 9577 Section 2.2.2. It ignores unknown credential parameters, rejects duplicate token parameters, malformed framing, wrong challenge and wrong issuer key, and redacts its header wrapper from Debug output. It returns only an unverified token; signature verification and server admission remain absent.

The internal common-challenge module encodes a type-2 RFC 9577 challenge from an explicitly configured issuer server name with empty redemption context and empty origin list. The encoded bytes match RFC 9577 Appendix A.1's empty-context, empty-origin vector; malformed or ambiguous issuer names are rejected. A shared empty context requires every redeemer accepting the same issuer key and challenge to share one double-spend store. The POC currently has no deployed redeemer, issuer-name configuration, or cross-node state coordination. After the directory-path check, `cargo test --locked --quiet -j 1 -p zrpc-payments` passed all 22 tests in the managed Linux amd64 container; the affected CLI balance test also passed against the current schema. The full CLI suite had separately passed at the preceding checkpoint (6 and 16 tests across its two test targets).

Server-path inspection places paid admission in `crates/server/src/attestation.rs`: `handle_rpc` first requires this TLS session's attestation, reads a bounded body, and calls `zrpc_protocol::parse_request`, which rejects forbidden methods and malformed requests. Ticket parsing, local signature verification, and an atomic spent-marker commit must occur after that allowed-request check and before `node.query` can forward to Zebra. The current `zrpc-node-wrapper` launcher accepts only platform, listener, node, and resource-limit inputs; it has no explicit free/ticket-required access selector or issuer/spent-store configuration. No paid server path or measured deployment input has been changed in this branch, and the separate GCP image work remains isolated.

## Independent status

| Area | Result |
| --- | --- |
| Simulated settlement and persistent issuance | Transactional stores, idempotence tests, and private batch file exchange implemented; no signing or issuance CLI yet. |
| Cryptography | Direct release age/yank check, isolated graph preflight, upstream RFC 9474 vectors, RFC 9578 public-token verification vector, and the internal RFC 9578 wire-prefix test passed. Workspace graph resolution still failed; no integrated cryptographic issuance or redemption ran. |
| Paid transport verification | The RFC 9577 authorization-header codec passed local tests; token transmission and server admission are not implemented or tested. Existing release, Tor, attestation, and connection gates are unchanged. |
| Chain data / joint live acceptance | Not run. This checkout has no embedded approved private release; no synthetic approval was added. |
| Read-only CLI balance | Implemented and focused test passed against an existing private client store; no purchase or redemption command is enabled. |
| Website handoff | Prepared separately in `records/website-build-prompt.md`; requires the website chat to inspect actual payment availability. |

## Isolated local cryptography checkpoint

The specified crypto dependency and existing Zcash dependency cannot currently resolve together in this workspace. `zcash_primitives` is used in `crates/server/src/node/identity.rs` to decode returned block headers and transactions and compute their identifiers; dropping it would remove a maintained check on real testnet data. The GCP image thread independently investigated a released compatible Zcash graph and found none; its image work remains separate.

`tools/payment-crypto` is an isolated Cargo workspace inside this repository, with its own committed lockfile and exact `blind-rsa-signatures =0.17.2` dependency. It does not change the service workspace's Zcash parser or lockfile. Its bounded binary stdin interface accepts operation, issuer SPKI, and only the bytes needed for the selected operation: token input for blinding; private DER and blinded request for operator signing; saved blinding state and blind signature for finalization; or signed token input and authenticator for public verification. It prints no diagnostic data; nonzero exit denies malformed input or invalid verification. The issuer private key must remain operator-only. This is local process isolation, not an issuer network call or an authorization path.

The exact helper lockfile passed the fresh registry release-age and checksum preflight at `2026-09-29T22:25:29Z` (57 registry packages, zero younger than the seven-day hold, no Git packages). `cargo fetch --locked` then succeeded in the managed container. `cargo test --locked --quiet` passed the upstream RFC 9474 vectors, RFC 9578 Appendix A.2 public token vector, a fresh blind/sign/finalize/verify round trip, wrong-key and altered-input rejection, canonical-SPKI rejection, and malformed/trailing local-frame rejection. `cargo clippy --locked --all-targets -- -D warnings` passed. The verification operation emits no output; issuance operations return only binary results over local stdout for the caller to capture. This proves the separate crypto component's primitive and local-frame behavior only; it does not prove a paid query, issuer authorization, recovery, measured-image packaging, or live chain data.

Next integration work must connect `zrpc-payments` to this helper with strict length and outcome checks, enforce the common challenge and issuer key ID in the main process, preserve the issuer's purchase authorization before signing, and make the redeemer commit its spent marker before Zebra dispatch. The helper executable and configuration must enter the reviewed measured-image inputs before a ticket-required deployment can be approved. A free demonstration must remain explicit; missing helper or payment state must fail closed in ticket-required mode.

A website can proceed independently with public fixtures, native-client instructions, and honest unavailable/planned states. It must not advertise a working payment system based on this handoff.
