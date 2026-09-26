# Durable provider observations — 2026-09-26

Contract: consume a completed authenticated provider read, bind it to the exact
original ledger and source snapshot, and durably append a historical observation.
Advance only existing conservative cost/time accounting. Keep usage identity,
deletion outcomes, cleanup, billing finality and retry authority unresolved.

## Implementation

`LedgerStore::commit_observation` consumes the opaque `ReadObservation`. It checks
the full current `CommittedLedgerReference` (original path, snapshot path and
generation) and every original binding field before writing. Production commit
time comes from `SystemTime`; callers cannot select a clock. The source cutoff,
scan finish and recorded time must be nondecreasing and cannot precede the
previous committed observation time.

`ObservationRecord` and its projections are serializable historical statements,
not constructors for authenticated reads. Records retain tracked CVM projections,
untracked inventory IDs and exact canonical decimal usage rows grouped by the
requested app. Validation checks identities, inventory counts, unique/disjoint
resource sets, exact app coverage, duplicate billing/app keys, generation links,
ordered times and cost arithmetic. New records cover every resource in the prior
snapshot; earlier records remain valid subsets after later tracking additions.

All retained appearances of `(requested app, billing key)` must have identical
full row content, including canonical exact cost. Equivalent numeric spellings
normalize identically. Late rows are retained; omission cannot erase earlier
evidence or allow a later conflicting row. No usage-to-CVM join is inferred.

Generic commits and original/generation-zero initialization reject inserted
observation records. Both new writes and history replay reconstruct the expected
successor from the previous snapshot, append exactly one observation and advance
modeled cost/time, then compare the complete ledger. Combined target, attempt,
accepted-charge or deletion changes are rejected. Previous observation entries
cannot be removed or modified. The existing writer lock, immutable snapshot,
fsync, pending-draft recovery and poisoned-writer rules remain in force. Local
history is not signed provider evidence or protection against hostile same-UID
filesystem replacement.

`zrpc lifecycle reconcile` uses the same explicit inputs, fixed-origin HTTPS
reads and original-ledger scope as `observe`, then commits the completed read.
Its report distinguishes source and committed references and scan/committed cost
floors. `observe` remains ephemeral. Both reports keep usage unjoined, provider
mutation/private acceptance/deployment/cleanup/billing reconciliation false, and
explicitly grant no deletion retry authority. Neither command initializes,
recovers or resets a ledger, accepts caller time or installs a job.

## Verification

New model tests cover late/omitted/equivalent/conflicting rows, atomic rejection,
later resources, exact current coverage, immutable prior statements and malformed
identity/time/generation/cost/shape/duplicate fields. Synthetic loopback TLS
integration exercises the public observation commit with real nonempty scans,
pending deletion history, unchanged accepted charges, reopen, full cross-store
reference rejection and stale-generation rejection. No production endpoint
override or fake `ReadObservation` constructor was added.

Persistence tests cover all six existing write interruption points, held writer
locks, durable reference publication, no automatic draft promotion, original
preservation, forged initialization/generic commits, generation/combined-mutation
rejection on write and reload, later tracking and commit-clock reversal. CLI
checks exercise help and refusal of incomplete inputs or unsupported mutation and
secret-on-argv options. Targeted source review found no reproducible gap in these
invariants.

The focused lifecycle run passed 123 unit tests and seven compile-fail
documentation tests. The final managed untrusted browser-profile Linux run of
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed 228 workspace
unit tests, 23 compile-fail documentation tests and 14 runtime-guard tests: 265
Rust tests total. Required builds, dependency/fixture guards, CLI/public-inspector/
wrapper checks and the changed README's user-doc boundary scan passed. No UI
changed, so visual QA was not repeated. Logs are
`.codex-tmp/provider-reconciliation-focused.log` and
`.codex-tmp/provider-reconciliation-workspace.log`.

## Limits and remaining work

Tests use synthetic TLS, credentials, CVMs and usage. No live Phala account call,
deployment, deletion, scheduler activation or spending occurred. Dependencies,
lockfile and UI are unchanged. This increment does not resolve Phala gates A–E,
the billing identifier join, independent disk deletion/billing finality, explicit
retry policy or tested external deadline/backstop activation. Those remain
requirements before any hosted evaluation; account credit is not authorization.
