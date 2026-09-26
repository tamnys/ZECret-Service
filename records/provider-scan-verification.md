# Ledger-bound provider observations — 2026-09-26

Contract: complete the provider read path from an existing committed experiment
ledger through inventory/detail/usage scans and an explicit read-only CLI. Keep
all observations separate from accepted charges, deletion authority and cleanup
proof. Exercise the path with local synthetic TLS fixtures only.

## Implementation

Inventory pagination requires the requested page/page size, stable total/pages,
unique IDs and a final unique count equal to the declared total. Empty inventory
accepts the existing zero-page or one-empty-page conventions. Usage advances its
offset by the returned count and continues through short pages until an empty
page. A repeated billing key, including an exactly equivalent amount, invalidates
that scan rather than being accepted as pagination progress. A failed accumulator
cannot later yield a completed result. Page cost summaries are not added as
charges.

Caller-supplied positive record bounds constrain retained inventory items and
usage rows per tracked app. These bounds have no production defaults. Along with
the existing HTTP response-byte bound and finite original tracked set, they bound
retained projections and duplicate-detection sets. All reads and post-decoding
checks share the HTTP client's original monotonic deadline. No page renews it.

`ObservationSession` borrows the writer-locked `LedgerStore` throughout the
operation. It validates the committed reference and pending-draft state before
network access and revalidates history before returning. Workspace, canonical
CVM IDs, distinct app IDs and the original usage start derive only from retained
ledger history. A single cutoff comes from the actual wall clock; no public
clock override exists. Backward wall time is rejected. Every retained resource
continues to contribute to the modeled cost floor, including resources absent
from the API and observations after the deadline or $50 ceiling.

Explicit app/instance contradictions fail the observation. Missing values remain
incomplete; optional per-item workspace evidence remains distinct from the
authenticated request scope. Untracked inventory IDs are reported, never adopted.
The usage identifier is never joined to either CVM identifier, even when their
strings match. No usage charge is accepted. CVM absence from a completed list plus
detail 404 is reported only as those API observations; disk deletion, billing
reconciliation and cleanup remain false.

`zrpc lifecycle observe` requires an existing initialized ledger, explicit key
and DER-root files, transport/file bounds and scan settings. It opens no new
ledger, installs no job, persists no report, changes no cost/deletion history,
and exposes no provider mutation or private RPC. Credential bytes cannot be
supplied on argv. Unsupported options, targets and clock overrides are rejected.
The JSON output preserves exact decimal identities as strings and excludes
account/credit/configuration fields discarded by the wire decoder. There is no
CLI endpoint override or test-fixture transport switch.

## Verification

The focused managed-container lifecycle run passed 100 unit tests and five
compile-fail documentation tests. New coverage includes accumulator interruption,
changed/missing/duplicate pages, usage empty-page termination, checked offset
overflow and caller record bounds; local TLS request sequencing, fixed windows
and cancellation; original-ledger scope, pending drafts, backward time, lock
retention, explicit/missing identity, unresolved matching usage text, historical
apps after the deadline and unchanged persisted bytes after success/failure.

The first focused run exposed a test assumption about exact Tokio timer precision:
expiry occurred one millisecond after the requested instant. The test now compares
against the renewal boundary derived from its deliberately advanced half-budget,
which detects a renewed page budget without an invented scheduling tolerance.
No production timeout behavior changed.

Full `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed in the
same managed untrusted browser-profile Linux shell: 205 workspace unit tests,
21 compile-fail documentation tests and 14 runtime-guard tests, for 240 Rust
tests total. Dependency/fixture guards, CLI/public-inspector/wrapper checks and
required builds passed. The CLI adds three argument-validation tests and command
checks for explicit help, incomplete input and unsupported mutations. The README
user-doc boundary check passed. No UI changed, so visual QA was not repeated.

Successful authenticated observations were exercised through the library's local
TLS fixture, not by redirecting the production CLI or using a live account.
Managed logs: `.codex-tmp/provider-scan-focused.log` and
`.codex-tmp/provider-scan-workspace.log`. Dependencies and lockfile are unchanged.

## Remaining work

The command reports observations in memory; it is not the durable reconciliation
runner or deletion executor. Cross-invocation usage reconciliation, provider-backed
identity mapping, interrupted-deletion recovery, deletion dispatch, external timer
activation and independent disk/billing evidence remain outstanding. Local scans
do not resolve the live feasibility gates. No Phala account calls, credentials,
resources, jobs, deployment or spending were used in this increment.
