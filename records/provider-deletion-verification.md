# Prepared deletion dispatch — 2026-09-26

Contract: connect a durably recorded, already tracked deletion target to one
fixed-origin DELETE exchange, with explicit local preparation and no live
invocation. Preserve pending/uncertain state after cancellation or write failure;
do not turn an HTTP result into storage or billing proof.

## Capability and persistence boundary

`ProviderClient::authenticate_deletion` creates a separate `ScopedDeletion`
after the same ordinarily authenticated `/auth/me` workspace check used for
reads. `ScopedReads` still has no mutation or conversion into this capability.
No CLI command, scheduler or automatic activation uses the deletion capability.

`ScopedDeletion::prepare` checks the locked store's actual committed generation,
original workspace, retained canonical target and lack of prior deletion intent.
It validates the target route and uses actual wall time. It reads only that
target's detail; full inventory and billing scans cannot delay preparation.
Explicit CVM/workspace/app/instance conflicts or failed detail reads stop before
an intent is created. Missing app/instance fields stay explicitly incomplete;
they neither replace the original identity nor establish a usage join. A detail
404 is a preparation observation, not a DELETE outcome.

After readback, preparation rechecks time and uses the existing durable intent
commit. `PreparedDeletion` privately owns both the authenticated client and the
committed intent, retaining the store's writer lock. The intent's new internal
dispatch check revalidates current history and pending-draft state. `dispatch`
consumes the value with no target, URL, method, or caller time argument. A dropped
value performs no network or filesystem operation and leaves its intent pending.

The GET and DELETE paths share the same private socket/TLS/HTTP-header exchange
and cancellation guard. DELETE derives its one encoded path segment solely from
the committed target, sends an empty body and retains the workspace/version/key
headers. No redirect, retry, arbitrary URL, creation, stop, resize or RPC operation
is exposed. Authentication, detail and DELETE retain the original monotonic
invocation deadline, including a deadline check after synchronous intent fsync.
Passing the original experiment deadline or spending ceiling does not prevent
cleanup. Budget and resource history remain unchanged except for the journal's
conservative elapsed cost accounting.

DELETE 204 records initiation; DELETE 404 records that status. Other supported
statuses retain their raw numeric code as rejection. Bodies and Location are
discarded. The HTTP parser also accepts status codes above the journal's retained
100–599 range; these are classified as `UnexpectedStatus`/`TransportUncertain`
instead of trying to persist an invalid outcome. Other transport failures also
remain uncertain and cause no retry.

After a response or transport failure, the same future synchronously attempts
the outcome commit using actual nondecreasing wall time. Its report separates the
provider outcome from `OutcomeJournal::{Committed, ClockRejected, NotConfirmed}`.
A write error never means the response was durably recorded; an uncertain write
may have published a snapshot. Cancellation owns and drops the HTTP driver and
intent, with no detached DELETE or finalizer. Disk verification and cleanup
remain false for every report. The local journal is not signed provider evidence.

## Verification

The production lifecycle library passed managed-container `cargo check --locked`.
The focused lifecycle run passed 111 unit tests and seven compile-fail
documentation tests. New local TLS cases check exact DELETE headers/path/empty
body, durable pending intent and writer lock at server receipt, 204/404/rejection
classification, unchanged original policy and nondecreasing cost, generation/
scope/target/route/time/history rejection, conflicting/incomplete detail, distinct
GET-404 and DELETE-404, dropped/unpolled capabilities, cancellation after receipt,
original-deadline exhaustion, lost replies, unsupported status 700, outcome-write
failure and clock reversal after a response. The timeout test also compares
against a renewal boundary derived from its explicit fixture budget.

Existing store fault tests cover all intent/outcome write boundaries. A new
dispatch-check test rejects a draft or altered committed history introduced after
token creation. Compilation tests preserve the noncloneable prepared capability
and prohibit deletion through `ScopedReads`.

Full `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed in the
same managed untrusted browser-profile Linux shell: 216 workspace unit tests,
23 compile-fail documentation tests and 14 runtime-guard tests, for 253 Rust
tests total. Dependency/fixture guards, CLI/public-inspector/wrapper checks and
required builds passed. No UI or user documentation changed, so visual QA and
the user-doc scanner were not repeated. Dependencies and lockfile are unchanged.
Logs are `.codex-tmp/provider-deletion-check.log`,
`.codex-tmp/provider-deletion-focused.log` and
`.codex-tmp/provider-deletion-workspace.log`.

## Remaining work

This is a library capability tested against synthetic local TLS fixtures, not
an operator deletion CLI or an activated external controller. A failed detail
readback refuses preparation; there is no claim that the eventual deletion
latency budget has been measured or proven. Reconciliation of prior intents,
explicit retry authorization, durable observation/cost reconciliation, external
timer/backstop activation, live disk disappearance and billing finality remain
unfinished. The existing CLI still rejects real teardown. No cloud resources,
account credentials, Phala requests, jobs or spending were used in this work.
