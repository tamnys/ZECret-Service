# Local operator ledger workflow — 2026-09-26

Contract: make the durable ledger usable without custom Rust or hand-written
storage JSON. Support prospective initialization, generation-bound attempt and
resource recording, read-only inspection and explicit discard-only recovery.
Retain original policy, prior resources and journal history, including after
interrupted writes. No provider request, credentials, creation, deployment,
scheduler activation or retry authority belongs to these operations.

## Implementation

`zrpc lifecycle ledger` has `init`, `record-attempt`, `record-cvm`, `inspect` and
`discard-draft` commands. Every operation requires an absolute original-binding
path. Initialization additionally requires a new store path, experiment/workspace
IDs, absolute deletion deadline and initial expense floor. It samples actual
system time for the original start and validates the existing 168-hour/$50/$45
policy. The original starts before resource creation, so setup time consumes its
window. No historical-start import, default lifetime, current-time override or
implicit zero expense is exposed. Existing or partially published outputs fail
instead of being replaced or resumed.

Attempt and CVM recording require the exact current generation. An attempt starts
at actual time and is refused when the original deadline or deletion threshold
has been reached. Resource recording derives the workspace from the original,
accepts explicit canonical identity/rate and historical creation time, rejects
future creation and evaluates conservative cost at actual recording time. It
clones and validates the successor before writing under the existing lock.
Returned IDs and rates remain operator assertions, not provider authentication.
No generic ledger import, accepted-charge entry or identity adoption is added.

The resource validator previously rejected creation at or after the original
deadline. That restriction prevented recording a leaked resource when an earlier
attempt finished late. Such resources are now retainable against an existing
pre-deadline attempt, without changing the original window, permitting another
attempt or authorizing provider creation. Future creation is still rejected by
the operator recording path. Prior resources and their conservative rates remain
immutable across generations.

`LedgerStore::inspect` revalidates all committed history and original/store
identity, retaining the writer lock. It exposes a serializable historical view,
current reference, pending-draft state and modeled current floor without writing
the ledger. A poisoned writer must reopen; a backward clock or invalid committed
history is rejected. A pending draft can be inspected without being promoted.

`discard-draft` separately checks the expected generation and current complete
history before invoking existing discard-only recovery. The original and store
identity now receive the same validation on this older recovery path as on normal
writes. Only the reserved pending filename is removed; every committed snapshot,
observation and deletion intent remains. Uncertain directory synchronization
poisons the writer. No draft is adopted, and recovery never authorizes DELETE.

## Verification

Six library tests cover actual-clock setup/attempt/resource/reopen, invalid or
partial initialization, stale and duplicate mutations, future/backward clocks,
late resources after the deadline and $45 threshold, read-only modeled-cost
advancement, pending inspection/recovery, corruption refusal and both mutation
types at all six existing write interruption points. These are local process
fault tests, not physical power-cut evidence. Existing original/store symlink,
reset, receipt, locking and deletion/observation history tests remain applicable.

Parser tests reject missing/repeated arguments, malformed paths/numbers/IDs and
unsupported credential, clock, import, reset or retry options without echoing
inputs. CLI subprocess checks exercise the complete setup→attempt→resource→inspect
workflow, reopening on every invocation, stale-generation refusal, unchanged
bytes after inspection and explicit draft recovery without promotion. They use
only newly created synthetic workspace files; no provider configuration exists
on this command path. Targeted source review found no reproducible contract gap.

The focused CLI/lifecycle run passed 141 unit tests and seven compile-fail
documentation tests. The final managed untrusted browser-profile Linux run of
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed 239 workspace
unit tests, 23 compile-fail documentation tests and 14 runtime-guard tests: 276
Rust tests total. Required builds, dependency/fixture guards, CLI/public-inspector/
wrapper checks and both changed user documents' boundary scan passed. No UI or
dependencies changed; visual QA was not repeated. Logs are
`.codex-tmp/operator-ledger-focused.log` and
`.codex-tmp/operator-ledger-workspace.log`.

## Remaining requirements

This is a prospective operator assertion workflow, not historical ledger
migration or a provider creation receipt verifier. No cloud resources, account
calls, spending or jobs were involved. Automatic deletion/retry, measured external
timing, live disk/billing finality and all Phala private-mode gates remain
unresolved. Public-source boot-support findings are recorded separately in
`records/phala-boot-support-refresh.md`; no image or KMS tuple was approved.
