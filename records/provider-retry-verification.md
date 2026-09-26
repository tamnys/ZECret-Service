# Explicit tracked deletion retries — 2026-09-26

Contract: allow a separately selected operator retry after a retained deletion
intent, with fresh authenticated detail for the exact committed target and a
new durable linked intent before one DELETE. Preserve every earlier attempt and
outcome, original policy and cost history. Never infer retry permission from a
timer, response, persisted observation or deserialized readback. This implements
the explicit reconciliation boundary in `live-lifecycle-adapter-plan.md` and
design §13; it does not activate external cleanup or permit a deployment.

## Implementation

`zrpc lifecycle retry-tracked` requires the existing deletion inputs, the current
ledger generation and the latest same-target intent's committed generation.
The original `delete-tracked` command remains first-attempt-only. Local history,
workspace, target, link and clock checks precede authentication. The fixed-origin
client then authenticates the original workspace and reads the exact target's
detail. Explicit ID/workspace/app/instance conflicts or unsuccessful detail reads
other than 404 refuse dispatch. Missing optional identity fields stay incomplete;
detail 404 is retained as that response, not proof of complete resource absence.
Full inventory and billing availability are not prerequisites for this narrowly
selected cleanup request.

The new intent retains `DeletionRetryRecord`: prior intent generation, invocation
start and readback times, and the typed provider detail projection. Preparation
is crate-private; public historical DTOs cannot mint a dispatch capability. Each
public retry invocation obtains its own readback. An optional omitted `retry`
field preserves serialization compatibility with existing first intents. Chains
must name the immediately preceding intent for the same CVM, even when other CVM
intents occur between them. Original identity, rates, deadline, prior billing and
observations remain unchanged; modeled cost continues after the cap or deadline.

Append and outcome commits reconstruct the exact permitted ledger successor.
A retry cannot be combined with new targets, charges or unrelated history edits.
Superseded pending intents remain pending permanently; later completion cannot
retroactively resolve an earlier uncertain request. Generic commits cannot
change the deletion journal. The existing writer lock, full-history replay,
durability sequence and explicit pending-draft recovery remain in use.

Authentication, detail, intent persistence and dispatch retain the same original
monotonic invocation deadline. Deadline checks surround synchronous intent
persistence and precede dispatch; expiry after publication leaves the new intent
pending. Dispatch sends at most one request and never follows a redirect or
retries automatically. Cancellation aborts its owned HTTP driver. The response
or transport uncertainty is recorded separately; a journal failure cannot be
reported as a confirmed commit. CLI output distinguishes retry mode and parent
generation while keeping future retry authority, cleanup, disk deletion, billing
reconciliation and private acceptance false.

## Verification scope

Synthetic HTTPS tests cover pending, uncertain, rejected, 204 and 404 prior
outcomes; fresh authentication and exact-target GET/DELETE; intent publication
and the held writer lock before transmission; retained original policy/cost;
stale or missing links, invalid local history and backward clocks before network
traffic; conflicting/incomplete/404 detail; cancellation before and after DELETE;
lost replies, unsupported status and the original deadline across phases. A
separate deadline test expires the budget after durable preparation and proves
that no DELETE is sent. This is not a measurement of real fsync or provider
cleanup latency.

Model and persistence tests cover latest same-target chains, legacy JSON,
invalid readback times/identity, immutable superseded pending entries, generic
commit forgery, combined journal/charge changes and tampered history replay.
Both retry append and outcome recording exercise all six existing local write
interruption points. These are process fault injections, not physical power-cut
tests. The compile-fail guard rejects restoring a dispatch token from JSON.
Parser and CLI subprocess checks require explicit selection and both generations,
reject supplied clocks/readback/evidence, automatic execution and retry counts,
and retain sanitized refusal output without provider calls.

The final managed untrusted browser-profile Linux run of
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed 252 workspace
unit tests, 24 compile-fail documentation tests and 14 runtime-guard tests:
290 Rust tests total. Required builds, dependency/fixture guards, CLI,
public-inspector and wrapper checks passed. The README documentation boundary
scan and `git diff --check` passed. No dependencies or UI changed, so visual QA
was not repeated. The retained result is
`.codex-tmp/provider-retry-workspace.log`. The earlier focused run exposed an
undersized synthetic response bound after changing the workspace marker; that
fixture now derives its limit from the actual response, and the complete suite
was rerun successfully.

## Remaining requirements

No live credentials, provider requests, resources, spending, jobs or UI changes
were involved. Synthetic success does not prove provider idempotency, disk
deletion, billing finality or a functioning external watchdog. Actual resource
quotes, measured cleanup/timer bounds, external periodic and absolute-deadline
controllers, an independent backstop and a successful live teardown remain
deployment prerequisites. All private-mode Phala gates remain unresolved.
There is no new count, backoff, evidence-age or network-budget default; each
retry is separately selected with the existing explicit invocation bounds.
