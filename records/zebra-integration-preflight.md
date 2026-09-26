# Zebra integration preflight — 2026-09-26

Internal evidence for the next real-node integration step. No Zebra binary was
downloaded or executed, no chain was synchronized, and no cloud or private-query
path was enabled. The current node adapter remains an internal loopback library.

## Release selection

The previously recorded dependency review applies a seven-day publication hold
before installation. Public metadata identifies the following candidates:

| Release | Immutable source commit | Release publication (UTC) | Decision |
| --- | --- | --- | --- |
| v6.3.0 | `f5c5277fe41eba9c74f37098738f93f35dd70d60` | 2026-08-10 19:31:24 | Old enough, but not selected for public P2P synchronization because later releases fix peer-triggered synchronization failures. |
| v6.4.0 / v6.4.1 | Not selected | 2026-09-23 | Upstream withdrew artifacts and advises against running these releases. |
| v6.4.2 | `e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291` | 2026-09-25 19:45:25 | Patched candidate; its artifact has not cleared the hold. |

Sources are the official [v6.3.0 metadata](https://api.github.com/repos/ZcashFoundation/zebra/releases/tags/v6.3.0),
[v6.4.2 metadata](https://api.github.com/repos/ZcashFoundation/zebra/releases/tags/v6.4.2),
[release notices](https://github.com/ZcashFoundation/zebra/releases), and
[September security changes](https://github.com/ZcashFoundation/zebra/pull/11502).
The separate [V6 advisory](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h5rr-8pqv-grp9)
affects v6.4.0/1 and explicitly excludes v6.3.0 from that particular regression;
this does not remove the older release's other synchronization issues.

The v6.3.0 native ARM64 GNU archive is 65,974,080 bytes, published
2026-08-10T19:43:57Z, with metadata SHA-256
`807db2dce0692b3fe237e7e470dabab952af0e30bb9ea2549d43c5ad2da77360`.
Signed checksum and provenance metadata exist but were not cryptographically
verified. Its [release workflow](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/.github/workflows/zfnd-release-binaries.yml)
supports a native ARM64 route, so another nested container image is not inherently
required. Actual ELF/runtime compatibility remains untested.

The v6.3.0 and v6.4.2 testnet activation tables agree through NU6.3, height
4,134,000, branch `0x37a5165b`:
[v6.3.0 constants](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-chain/src/parameters/constants.rs),
[v6.4.2 constants](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-chain/src/parameters/constants.rs).
This is source compatibility evidence, not successful synchronization.

The v6.4.2 ARM64 archive's recorded publication time is September 25 at
19:59:10 UTC. Adding the existing seven-day hold gives October 2, 2026, at
19:59:10 UTC. This is an earliest age eligibility time, not scheduled execution
or approval: recheck immutable artifact identity, signatures/provenance,
withdrawals and advisories before selecting it. No hold exception was applied.

## Local decoder correction

The advisory prompted inspection of the already locked `zcash_primitives 0.30.1`,
whose source revision is
[`97aefdc39a037da9c4f19a0e8a450d2c7932f53e`](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/mod.rs).
Its `Transaction::read` computes an identifier during decoding but does not
enforce the existing `TxVersion::valid_in_branch` rule. The local wrapper's
matching-identifier check therefore did not reject every invalid version/branch
combination.

A synthetic empty-bundle regression reproduced this with V6 and `Nu6_1`: the
old `node::identity::transaction` returned success when supplied the codec's
computed identifier. The test failed at the rejection assertion, not at a
decoder panic. No crash exploit or general decoder panic-freedom claim is made.

The wrapper now uses maintained `TxVersion::read` to identify the format, reads
the fixed four-byte little-endian branch field for V5/V6, and applies maintained
`BranchId::try_from` and `valid_in_branch` before full `Transaction::read`.
Unknown/truncated or incompatible branches return the existing sanitized error.
No branch field is inferred for earlier formats. Complete consumption and
matching identifiers are still required afterward; no cryptographic algorithm,
consensus validator, dependency change or private acceptance path was added.

Tests cover all known branches predating each branch-bearing version, both raw
and verbose response paths, supported V5/V6 combinations, missing/unknown branch
prefixes, trailing/truncated bodies and wrong identifiers. Empty-bundle test
inputs are synthetic parser fixtures, not consensus-valid transactions. Existing
immutable public V4/V5/header vectors remain part of the focused checks.

The pre-fix rejection test exited 101 with the expected assertion failure:
`.codex-tmp/branch-rejection-before.log`. After the correction, all ten focused
identity tests passed: `.codex-tmp/branch-rejection-focused.log`.

The full managed-container `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash
scripts/check.sh` passed on the unchanged rerun, recorded in
`.codex-tmp/branch-rejection-workspace-repeat.log`: 298 workspace unit tests,
25 compile-fail documentation tests and 14 runtime-guard tests (337 total),
plus dependency/fixture guards, native builds, CLI, public-inspection and wrapper
checks. No UI or dependency change required another visual check or download.

The first full run stopped at the previously observed intermittent
`persistence::tests::retry_and_retry_outcome_faults_never_replace_prior_intents`
fixture-setup failure (`persistence.rs:1124`, `UnsafePath`), before later packages
ran. The isolated test then passed and the complete unchanged rerun passed.
The initial log is `.codex-tmp/branch-rejection-workspace.log`; the isolated log
is `.codex-tmp/branch-rejection-lifecycle-probe.log`. The cause is unresolved;
this patch does not claim to fix it or weaken any lifecycle path check.

The current CLI's `doctor` command was also run successfully. It reports
`public_endpoint_inspection_available: true`, requires explicit loopback SOCKS
for that diagnostic, and keeps all A–E gates unresolved, private mode blocked,
deployment disabled and created resources zero. This supersedes the older
diagnostic wording saying that the CLI had no Tor path; neither wording is a
successful Tor connectivity test.

## Remaining real-node evidence

Use the eligible, independently verified artifact with explicit local testnet
configuration and container-only loopback RPC. Actual node readiness, allowlist
response compatibility, RAM-only cookie handling, resource fit, restart behavior
and RPC isolation still need execution evidence. Synchronization and performance
measurements cannot be supplied by the current fake-node tests. None of this
resolves the supported Phala OS/KMS tuple, fresh attested TLS-key ownership,
administrative/disk controls, pricing or external deletion gates.
