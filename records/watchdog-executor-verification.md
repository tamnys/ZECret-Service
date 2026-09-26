# One-shot external watchdog executor — 2026-09-26

Contract: implement one explicitly invoked pass over the entire existing,
original-bound experiment. Check current deadline, cost and reserve before
optional reads; prioritize already-due deletion; bound reads and all target
attempts by one original network budget. Preserve durable history and partial
results without creating resources, installing jobs, granting future execution
authority or claiming independent storage/billing cleanup. All verification in
this change uses local synthetic services and disposable ledgers.

## Implementation

`zrpc lifecycle watchdog-once` requires the exact retained experiment ID, the
existing provider/file bounds, observation limits and every timing/fee input.
The library opens no store, takes an already writer-locked store, validates full
history and the exact experiment/workspace, and uses the current committed
generation. The CLI opens only an existing original; it cannot initialize,
reset or recover a draft. Policy validation precedes credential/file loading.
Unsupported target, clock, endpoint, job-installation and simulation flags are
rejected. Completed execution emits one JSON report; partial work exits 1.

Policy retains the original $50 ceiling, $45 trigger and at-most-168-hour
window. Required whole-millisecond assumptions satisfy `R + D <= B`,
`R + S <= P`, and `D <= L`. Reserve arithmetic evaluates
`$45 + ceil(rate * (P + L) / hour) + fees <= $50` using exact integers and all
tracked compute-plus-disk rates. Insufficient reserve causes early cleanup;
expired deployment quotes or exceeded budgets do not call the deployment
planner and veto cleanup. Large u128 monetary projections serialize as exact
decimal strings. No production interval, delay, fee, retry-count or memory
default was added. Timing values remain assumptions, not measured receipts.

Already-due startup skips inventory and billing scans. Otherwise the optional
observation cutoff is the earliest of its configured budget, the original
invocation deadline minus the dispatch reserve, and the next time/cost trigger.
The cost trigger is found from the retained monotone whole-second model, with
no polling interval. Only a completed opaque observation can be committed;
partial reads never manufacture charges, adopt untracked resources or prove
billing reconciliation. After preemption or an ordinary read failure, current
time and policy are checked again so required known-target cleanup can proceed.
Identity, authentication scope, local state and clock failures stop mutation.

Due cleanup visits the deterministic retained target set once. Every target
authenticates the original workspace and reads its exact detail again. It
selects either the first intent or a new linked retry of that target's latest
committed intent. The existing durable-intent-before-DELETE capability is
reused unchanged. A normal provider rejection or lost response can leave a
recorded unsuccessful attempt while processing later targets; scope/identity
conflicts, uncertain journal writes and clock failures stop the pass.

The provider configuration can be forked only inside this crate. Child
deadlines are capped by the original deadline, with no credential-file reread
or public clone/deadline override. The dispatch deadline is calculated once
outside the target loop. Authentication, readback and dispatch share it.
Cancellation drops the owned HTTP driver. A pending durable intent is retained
if a request or outcome remains uncertain. Reports retain completed targets,
the retained target count, original/final generation references, policy
decisions and sanitized failure categories. No report is accepted as an
execution capability. Cleanup, independent disk verification, final billing,
deployment, private acceptance and future invocation authority stay false.

The prior activation proposal now acknowledges the one-shot implementation,
but still supplies no executable arguments or installed jobs. It cannot be
activated. A scheduler cadence must account for work time and overlap; the
offline proposal's interval is not a ready-to-install execution schedule.

## Verification

Managed untrusted browser-profile Linux execution of
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed:

- 277 workspace unit tests, 25 compile-fail documentation tests and 14 runtime
  guard tests: **316 Rust tests total**.
- Required native builds and verifier/TLS/parser dependency and fixture guards.
- CLI help and invalid-input checks, private-mode refusals, public endpoint
  inspection and wrapper executable checks.
- User-documentation boundary scanning and `git diff --check`.

New tests cover exact arithmetic/overflow, no deadline renewal, timed-out
optional reads with dispatch time remaining, completed observation persistence
without charging/adoption, incomplete read refusal, time and cost transitions
into cleanup, backward clocks, multi-target overdue cleanup, durable snapshots
and held locks visible before DELETE, latest-linked retries, rejection/lost
reply continuation, identity conflicts, no-network local refusals, and original
invocation expiry on a later target after an earlier successful attempt.
The time-transition tests use a private test-only clock callback and Tokio's
controlled monotonic clock; production has no clock injection input.

The first focused run exposed a synthetic fixture whose deadline exceeded
168 hours by 60 seconds. Its deadline was corrected to the original allowed
window, and the complete affected workspace suite was rerun successfully.
Final results are retained in `.codex-tmp/watchdog-executor-workspace.log`;
safe command-help and doctor output are in `.codex-tmp/watchdog-help.txt` and
`.codex-tmp/watchdog-doctor.json`. Dependencies and UI were unchanged, so no
additional downloads, release rebuild comparison or visual QA was needed.

## Limits and remaining gates

Network phases use monotonic deadlines. A wall-clock jump during a request is
detected at the next check. Synchronous validation/fsync can extend elapsed
runtime; these tests establish neither real filesystem failure timing nor a
live end-to-end deletion bound. Historical and unjoined provider observations
cannot establish independent disk deletion or billing finality. A 204 or 404
response remains limited provider evidence.

No live credentials, provider requests, cloud resources, spending, jobs or
deployments were involved. Synthetic test success cannot satisfy private-mode
acceptance. Remaining prerequisites include an approved hardware/workload and
fresh TLS-key proof; a supported measured runtime/admin-access configuration;
resolved KMS/disk trust; fresh account-specific resource pricing; independently
installed periodic and absolute-deadline execution, measured timing, a separate
backstop, and a successful live deletion/storage/billing evaluation. An explicit
operator action is required before any live execution or spending.
