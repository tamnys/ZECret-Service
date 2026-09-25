# Proposed live lifecycle adapter — 2026-09-25

This is an implementation plan from the current local lifecycle code and pinned
official source. No provider adapter, CLI command, credential, job or cloud
operation was created. Deployment and automatic activation remain unavailable.
The next useful local change is a narrow HTTP response normalizer plus a
persistent, explicitly invoked reconciliation/deletion runner, tested against a
local fake provider. An adapter alone cannot close the external-cleanup gate.

## Source contract

Use the [Phala OpenAPI at `5176d4c53fcee5aec3a8ccbbb05840a0a678c553`](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json)
and [SDK transport at `ee941461e05004e4f80c26694f43c833bbc208b6`](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/client.ts).
The SDK declares `2026-06-23` as its default API version; pin that header and its
response shapes explicitly, rather than follow future defaults or accept the
OpenAPI's legacy/new union opportunistically. The OpenAPI server is
`https://cloud-api.phala.com`; the SDK base is that origin plus `/api/v1`.

Required request headers are `X-API-Key`, `X-Phala-Version: 2026-06-23`, and
`X-Phala-Workspace` containing the original binding's workspace ID. The SDK also
supports bearer/cookie authentication and environment overrides; the initial
Rust adapter needs only the explicitly supplied API-key credential. Do not copy
the SDK's debug request logging, environment-selected base URL, or generic
request surface into this narrowly scoped adapter.

| Operation | Actual contract and normalization |
| --- | --- |
| Workspace identity | `GET /api/v1/auth/me`. This route is absent from the pinned OpenAPI; the pinned [`getCurrentUser`](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/actions/get_current_user.ts) calls `/auth/me`. Its [versioned schema](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/credentials/current_user_v20260121.ts) has `user`, `workspace`, `credits`; compare `workspace.id` exactly with the immutable binding. Credits are account information, not an experiment expense total or hard spending cap. Do not persist the returned user/email fields. |
| Inventory | `GET /api/v1/cvms/paginated?page=…&page_size=…`. OpenAPI: page starts at 1, page size 1–100, default 30. Response fields: `items`, `total`, `page`, `page_size`, `pages`. Send no owner/node/family/type filter that could hide residual CVMs. The pinned [SDK action](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/actions/cvms/get_cvm_list.ts) selects the 2026-05-22 schema for 2026-06-23. |
| Detail | `GET /api/v1/cvms/{cvm_id}`. 200 is a present resource; 401 is authentication failure, 403 is outside the workspace, and 404 is not found. The [versioned CVM schema](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/types/cvm_info_v20260121.ts) exposes `id`, `status`, optional/null `workspace`, `app_id`, `instance_id`, `vm_uuid`, `created_at`, `deleted_at`, and resource fields. A status or `deleted_at` value does not prove disk disappearance. |
| Deletion | `DELETE /api/v1/cvms/{cvm_id}`, no body. OpenAPI 204 means **deletion initiated**; 401/403 are failures and 404 is not found. Preserve raw status. The [SDK deletion action](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/actions/cvms/delete_cvm.ts) returns `void` after its request; its example's success wording is not deletion/readback evidence. |
| Usage | `GET /api/v1/apps/{app_id}/usage?start_date=…&end_date=…&limit=…&offset=…`. Explicit ISO-8601 dates are required by this adapter: original experiment start through one fixed observation cutoff, including post-deadline scans. The provider's omitted-date default is seven days and must not truncate experiment history. Limit is 1–5000, default 500; offset starts at 0. `AppUsageResponse` contains `usage`, `total` (number of rows returned), `total_cost` (JSON number). `MeteredUsageResponse` has `instance_id`, `project_id`, `team_id`, `timestamp`, `event_type`, `cost` (JSON number), nullable `details`, `usage_type`, `billing_start`, `billing_end`, `duration_minutes`, `billing_key`, `billing_hour`, `billing_day`. It has no `app_id`; add request-context app identity explicitly after a proven tracked-instance join. |

The inventory envelope has no workspace field; the current mock's
`InventoryPage.workspace_id` is not a literal wire field. Carry authenticated
request scope separately. Every page uses the same bound workspace header, after
the identity check. Compare an item's `workspace.id` whenever present; an explicit
mismatch fails the observation. Missing/null item workspace is not invented
per-item evidence: any use of the documented current-workspace list scope must
remain explicit in the normalized type. Before deletion, retain the exact
canonical CVM/app/instance identity established when it was tracked; reject a
present detail response that contradicts that identity.

Use only the canonical `id` returned by the selected API version and already
committed in the experiment ledger. Do not accept a new deletion target from a
CLI name, app ID, UUID alias, URL or wildcard. The upstream
[`CvmIdSchema`](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/types/cvm_id.ts)
intentionally accepts and rewrites several identifier aliases; that behavior is
unnecessary here. Encode a ledger ID as one URL path segment, with no raw path
concatenation. Null/missing identities in a newly observed partial creation are
not permission to invent values or adopt a resource automatically. Future
creation integration must durably record the returned canonical ID immediately;
it is outside this deletion-only adapter.

One identity mapping remains unresolved in the sources: metered usage describes
its `instance_id` as a CVM instance UUID, while CVM detail exposes both `vm_uuid`
and `instance_id`; the SDK describes the latter as a 40-character identifier
separately from UUID. Do not assume that identically named fields join. Retain
those identifiers separately and require provider-supported mapping evidence
before accepting a usage row for a tracked resource. The existing mock ledger's
single `instance_id` does not prove that mapping. This can leave billing
reconciliation incomplete without disabling explicit deletion of the committed
canonical CVM ID.

## Runner and operator boundary

Keep the HTTP implementation internal and asynchronous. Split read operations
from the deletion capability instead of simply unsealing `MockProvider` and
exposing `tick_mock` to arbitrary providers. The current tick interleaves I/O and
in-memory mutations, hard-codes simulation, and records a deletion request only
after the call; it is not a crash-safe live executor. Reuse its pure identity,
pagination, usage, watchdog and state-transition rules behind the new boundary.
The mock remains a distinct test implementation and cannot emit live evidence.

Proposed CLI interface, **not implemented and not runnable today**:

```text
zrpc lifecycle reconcile --original-binding PATH --provider-config PATH --api-key-file PATH
zrpc lifecycle delete-tracked --original-binding PATH --expected-generation INTEGER --provider-config PATH --api-key-file PATH
```

`reconcile` may perform only the listed GETs and append a local observation/cost
snapshot. It reports the committed generation and exact tracked deletion set,
original deadline, original $50 cap/$45 trigger, current conservative floor and
untracked residual IDs. It never sends DELETE even when deletion is due.

`delete-tracked` is a separate explicit operator action. The expected generation
binds it to the reviewed tracked set; a changed generation requires a new
reconciliation/review, not silent adoption of new targets. It may request early
teardown and must remain usable after the original deadline or cost ceiling has
already been exceeded. Those conditions increase urgency; they must not prevent
cleanup. No create/start/resume/stop/resize/update/scheduled-delete method belongs
in this capability. Neither command installs a timer or authorizes later runs.

The provider configuration binds the selected API version, trusted original
policy/timing reference, HTTPS trust anchors and explicit transport budgets; it
cannot override workspace, experiment start/deadline, target set or cost history.
Use the existing Tokio/Hyper/Rustls stack with normal certificate-chain and DNS
name validation against an explicitly supplied, operator-trusted CA bundle read
by a maintained certificate parser. The current diagnostic TLS verifier does
not establish a certificate chain and cannot be reused for API-key transport.
Production origin remains fixed; test transport injection is private to tests.
Reject redirects instead of forwarding credentials. No environment proxy,
endpoint fallback, automatic HTTP retry, or response-provided URL is needed.
This operator control-plane client has no RPC/query method and is not exposed to
either browser UI or the private-query transport.

Read the explicit credential file outside the guest, without printing its
contents or accepting the secret itself on argv. Keep it out of Debug/Serialize,
errors, snapshots and request traces. Use sanitized status/error categories;
drop provider error bodies rather than persist arbitrary account/configuration
data. Credentials and the original/store ancestors retain the existing local
file-owner trust assumption; this adds no authenticated-filesystem claim.

One invocation opens `LedgerStore::open`, holds the existing writer lock, checks
`planning_reference()`/pending recovery and loads the latest committed ledger.
It must not call `initialize`, discard a draft, reset a binding, lower a rate,
replace an attempt, or accept a caller-controlled current time. Validate current
wall time against retained observation time and use a monotonic clock for I/O
budgets. Retain every prior attempt and every tracked resource, including absent
or stopped resources; credits/refunds do not lower the experiment expense floor.

Before each DELETE, commit an intent for that exact tracked ID under the lock.
Only after successful durable commit may the request leave the process. Record
the response or ambiguous transport outcome in a successor snapshot. A lost
response, cancellation, persistence failure or process exit leaves intent
pending; reopen and reconcile before another explicitly authorized attempt.
This is at-least-once request/reconciliation behavior, not a claim of provider
idempotency or an invented idempotency header. Preserve 204/DELETE-404 as pending.
Only complete authenticated inventory plus detail-404 corroborates CVM absence.
401/403, redirects, malformed data, 429/5xx and transport failure never do.

When deletion is explicitly authorized, an unavailable inventory or billing
scan need not veto attempts against previously verified, committed IDs after a
successful workspace identity check. It does prevent proving absence or cleanup.
Do not let slow read-only scans consume the deletion-start budget. Wrong identity
or conflicting resource identity prevents dispatch; incomplete information
never authorizes deleting untracked resources.

## Pagination, amounts and timing

Use the documented page-size/limit defaults (30 and 500) explicitly if no
operator choice is supplied; these are provider defaults, not new project caps.
Read inventory through its declared last page, requiring stable `total/pages`,
matching requested page/page size, unique IDs and the final unique count equal
to `total`. Changing/duplicate/missing pages make that scan incomplete. There is
no provider snapshot token, so call the result a completed scan, not an atomic
inventory snapshot or independent proof.

For each distinct tracked app, hold start/end fixed throughout one usage scan,
require `total == usage.len()`, advance offset by that returned count with
checked arithmetic, and continue until an empty page. Do not interpret `total`
as the total available records or stop merely because a page is short. Require
progress in billing keys; retain cross-scan deduplication and reject a key whose
identity/category/exact amount changes. Track only matching committed
app/instance pairs; unrelated rows must be reported as outside scope, not
silently charged to the experiment or silently called a complete experiment
reconciliation. Repeat the original-start window on later invocations to catch
late arrivals. A missing app/usage 404 is missing billing evidence, not zero cost.

Decode typed JSON objects with duplicate critical-field rejection. Preserve
`cost`/`total_cost` numeric lexemes using the already enabled Serde `RawValue`;
never pass them through `f64`, JavaScript numbers or a lossy generic value map.
The wire schema permits JSON exponent notation, whereas the current
`decimal_usd_to_microusd` accepts only plain decimals. Add an exact decimal-token
normalizer and matching ledger amount representation/parser before live use:
validate JSON number grammar, preserve canonical
exact coefficient/exponent identity for deduplication, then use checked upward
rounding to the existing six-decimal microUSD unit. Do not expand an exponent
into an arbitrarily large zero-filled string or collapse different sub-microUSD
amounts to the same deduplication identity. Reject negative charges/overflow as
unresolved billing; do not silently net refunds. Page `total_cost` is a summary,
not a second charge. The existing floor remains monotonic and all quoted fee
categories remain in the overall cost/reserve calculation.

Let `P` be `maximum_poll_interval_seconds`, `L` be
`deletion_latency_upper_bound_seconds`, `R` the aggregate quoted/existing hourly
microUSD rate and `F` all quoted fee upper bounds. The existing authority is:

```text
45_000_000 + ceil(R * (P + L) / 3600) + F <= 50_000_000
deletion request start <= original deadline - L - timer accuracy allowance
```

For eventual scheduling, elapsed waiting plus reconciliation/detection must fit
`P`; dispatch, provider completion and required readback must fit `L`. Give each
HTTP request the remaining monotonic phase budget, including DNS, connect, TLS,
headers, body and decoding; pagination, progress and retries must not reset it.
Check original cost/deadline before reads and between pages, and preempt optional
reconciliation at the proposed deletion-start time when dispatch is authorized.
Timeout/cancellation after transmission is an uncertain outcome, never absence.

`P` and `L` do not determine a safe arbitrary per-request timeout or a split
between network time and provider deletion latency. The SDK's 60-second default
is not evidence for this experiment. Positive phase budgets and the split must
come from the operator's measured deletion/reconciliation evidence and fit the
inequalities above. The current periodic proposal already spends almost all `P`
on its timer interval: measure runtime and account for service overlap before
claiming that a live schedule respects the detection bound. No scheduler change
is proposed in this step. A synthetic zero-latency fixture is not a live bound.

The OpenAPI has per-page row limits but no maximum response bytes or string
lengths. Therefore it cannot justify a hard-coded body-size cap. A finite
response allocation/decoding budget needs explicit operator input or measured
evidence before a buffered live adapter can claim bounded responses. Pass that
budget as required configuration, without an invented default; validate oversized
Content-Length and streamed/chunked bodies against the same limit. A time limit
alone is not a memory bound. Local tests can supply limits derived from their
fixture lengths without promoting those values to production policy.

## Evidence still missing and local proof

The inspected OpenAPI has no independently addressable disk inventory/delete
operation, disk-deletion receipt or definitive billing cutoff field. CVM
`resource.disk_in_gb`, nullable `deleted_at`, `status` and usage categories do not
fill that gap. Its `PATCH /api/v1/cvms/{cvm_id}/scheduled-delete` changes a provider
schedule; it is neither the required independent external deadline controller
nor an allowed operation in this adapter. No such schedule will be installed.

The documented [storage policy](https://cloud.phala.com/about/pricing) says
stopped disks keep billing until deletion. Closing the gate still needs evidence
tying the tracked CVM's attached storage to actual disappearance/no residual
billable storage, and a provider-supported billing finality/reconciliation
method, including usage availability after CVM/app deletion. The source has no
finality watermark, maximum billing ingestion delay, stable offset snapshot
guarantee or documented recovery path for post-deletion usage 404. Do not invent
a delay after which silence means settlement. Keep
`independent_disk_deletion_verified = false` and `cleanup_complete = false` until
those independently reviewed receipts exist. Empty scans and credit balances
cannot set either flag.

Before any explicit live invocation, local fake-HTTP/TLS tests should prove:

- Exact method/path/version/workspace headers, ordinary TLS trust rejection,
  credential redaction, no redirects and no provider mutations from reconcile.
- Only the committed generation's canonical IDs can be deleted; wrong workspace,
  conflicting readback or stale generation sends no DELETE; unrelated IDs are
  reported without mutation.
- Complete and interrupted inventory/usage pagination, late usage, duplicate or
  conflicting billing keys, exact exponents and upward microUSD rounding,
  overflow/negative/duplicate JSON fields and streamed response-budget failure.
- Durable intent precedes HTTP; crashes before/after transmission, 204, 404,
  401/403, 429/5xx and lost replies preserve pending state and original history.
- Reopening keeps the original 168-hour window, $50 cap/$45 trigger and all prior
  costs; expired policy or uncertain outcomes do not renew the experiment or
  create optimistic cleanup status. Phase exhaustion stops optional reads and
  never resets its deadline on the next page.

These are adapter/persistence proofs, not a live deletion exercise. External
credential access, measured latency, periodic/absolute jobs, independent
backstop, real deletion/disk/billing receipts and explicit operator activation
remain separate prerequisites. No cloud credentials or Phala API requests were
used for this source review; public pinned GitHub source reads were the only
remote requests.
