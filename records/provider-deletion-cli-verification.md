# Explicit tracked deletion command — 2026-09-26

Contract: expose the existing durable first-deletion capability as an explicit
operator CLI action for one existing ledger target and reviewed generation.
Reject invalid local selection before authentication, keep the request and
outcome journal semantics, and distinguish a recorded HTTP result from cleanup.
Implement and test locally without invoking Phala or activating external jobs.

## Behavior

`zrpc lifecycle delete-tracked` requires the original binding path, expected
generation, exact tracked CVM ID, private credential file, independently selected
DER roots, invocation budget, response limit and input-file limit. It accepts no
default target, URL override, caller clock, secret argument, retry, initialization,
recovery, simulation, deployment or scheduler option. Observation-only page and
retention options are not accepted by deletion. The command's help explicitly
labels it a real provider operation; reading help performs no operation.

Shared `ProviderSettings` preserves the existing observation commands' explicit
file, trust and resource settings. The binding exposes a read-only workspace
accessor so the CLI can configure its client without serializing policy fields
or creating an unrelated observation session. Local binding data does not
authenticate a provider workspace.

`ProviderClient::delete_tracked` validates the locked store's current history,
generation, configured workspace, exact tracked target, prior-intent absence,
canonical route and actual wall time before authenticating. The same helper runs
inside preparation after authentication. A wall-clock lower bound also covers
the authentication interval. The existing client deadline spans authentication,
detail and DELETE; no new budget or retry is created. It reads only the chosen
detail, durably commits intent, dispatches once, and journals the outcome using
the existing capability. Passing the original deadline or cost ceiling does not
prevent cleanup. No inventory or billing scan delays the selected deletion.

Exit 0 requires `Initiated204` or `NotFound404` plus `OutcomeJournal::Committed`.
Rejection, transport uncertainty, clock rejection and uncertain writes exit 1.
A completed dispatch emits exactly one structured report. The normal error
path handles preparation/dispatch failures before a report exists and warns
that a committed intent may remain; it does not imply unchanged history or safe
replay. Every result keeps cleanup, disk verification, billing reconciliation,
private acceptance, deployment and retry authority false. Any retained prior
intent still blocks another request, including after observation reconciliation.

## Verification

Existing synthetic TLS dispatch tests now exercise the complete entrypoint over
204/404/403/302/429/503, checking the exact auth/detail/DELETE sequence, headers,
empty body, durable pending intent and held lock at receipt, original preservation,
outcome persistence and refusal of a second invocation before network traffic.
The same local rejection matrix covers both the new entrypoint (zero requests)
and staged preparation (authentication only): stale generation, workspace,
untracked/invalid-route target, future clock, prior intent, pending draft and
corrupt committed history. Existing cancellation, lost response, deadline and
write-failure tests continue to cover the shared dispatch implementation.

CLI tests check required/duplicate/invalid inputs, generation zero, repeated
roots, unsupported authority options without secret echo, and the outcome/journal
exit matrix. Subprocess checks read explicit help and reject missing original
state and unsupported options without initializing files or contacting Phala.
Review caught and removed a redundant boolean that inferred whether any HTTP
response had been seen from the retained outcome enum; unsupported statuses can
leave a response uncertain, so the report retains only the outcome and issue.

The focused CLI/lifecycle run passed 133 unit tests and seven compile-fail
documentation tests. The final managed untrusted browser-profile Linux run of
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed 231 workspace
unit tests, 23 compile-fail documentation tests and 14 runtime-guard tests: 268
Rust tests total. Builds, dependency/fixture guards, CLI/public-inspector/wrapper
checks and the changed README's user-doc boundary scan passed. No UI changed,
so visual QA was not repeated. Logs are
`.codex-tmp/provider-deletion-cli-focused.log` and
`.codex-tmp/provider-deletion-cli-workspace.log`.

## Remaining requirements

No live account call, deletion, deployment, spending, scheduler or backstop was
used or activated. Dependencies, lockfile and UI are unchanged. Synthetic local
TLS proves the command wiring, not live deletion latency or attached-disk billing
cessation. All Phala security gates, the billing identifier join, independent disk
and billing finality, retry policy, complete external watchdog/deadline activation
and a successful operator-approved live deletion test remain unresolved. This
single-target command does not implement an automatic whole-experiment controller.
