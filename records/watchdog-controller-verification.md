# Local watchdog controller record

The controller in `crates/lifecycle/src/controller.rs` is a local model backed
only by a sealed, in-memory provider. It cannot activate cloud access, install a
scheduler, create resources, or authorize spending. Its report always identifies
simulation, unavailable live activation, and incomplete cleanup.

The experiment binding retains the original workspace, start, absolute deadline,
$50 total cap, and $45 deletion trigger. Attempts append resource identities and
costs without replacing this binding. JSON restoration compares the saved binding
with a separately supplied original and validates resource/cost relationships.
This is not authenticated storage: an independent trusted binding store, atomic
ledger persistence, concurrency control, and crash-safe activation are unfinished.
Creating another ledger is not evidence that an existing experiment ended.

The controller reuses the existing watchdog policy. Cost is the maximum of the
retained floor, all modeled resource costs, and recorded expenses, including prior
attempts. Stopped or absent CVMs receive no automatic cost discount because final
billing and disk deletion are unverified. Usage records are scoped to tracked app
and instance IDs, deduplicated by `billing_key`, and summed with checked integer
arithmetic. Plain decimal USD values round up to microUSD; unsupported numeric
syntax is rejected. A future HTTP adapter must preserve numeric tokens and handle
scientific notation exactly instead of converting through floating point.

A mock tick verifies workspace identity, reads every inventory page, requests
deletion only for explicitly tracked CVM IDs, and corroborates inventory absence
with a detail 404. A 204 is only a pending deletion request. Authentication errors,
incomplete pagination, stale absence, and unknown replies cannot prove absence.
Untracked workspace IDs are reported and never deleted. The staged outputs are
deletion requested, absent from inventory, and billing reconciliation pending;
there is no successful independent-disk-deletion state.

The API mapping is source-grounded but no live HTTP adapter exists:

- `DELETE /api/v1/cvms/{cvm_id}`: 204 means deletion initiated.
- `GET /api/v1/cvms/{cvm_id}` and `GET /api/v1/cvms/paginated`: detail and complete
  workspace inventory, with 401/403 distinct from 404.
- `GET /api/v1/apps/{app_id}/usage`: explicit experiment start/end, offset-based
  pagination, and billing keys. A completed scan does not prove billing finality.

Sources: [pinned Phala OpenAPI](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json),
[pinned SDK transport contract](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/client.ts),
and [published storage billing policy](https://cloud.phala.com/about/pricing).
The inspected public API has no independent disk inventory endpoint; deleting a
CVM is documented to end its attached storage billing, but the mock cannot
establish that provider behavior or verify post-deletion billing availability.

Unit cases cover exact/overflowing amounts, JSON restoration, retries preserving
the original binding, cumulative usage at the trigger, late/missing billing,
conflicting duplicate billing keys, non-progressing pagination, incomplete
inventory, unrelated resources, partial creation, lost deletion responses,
204 pending state, stale absence, stopped resources, and workspace/authentication
failures. The root task ran `cargo test --locked -p zrpc-lifecycle` in its managed
container: all 22 unit tests passed, including the 11 new controller tests.

Next required layer is atomic external persistence and operator-reviewed
activation/job specifications. A live adapter, external periodic and absolute
deadline jobs, independent backstop, real teardown test, disk evidence, and final
charge reconciliation remain prerequisites to hosting. No mock receipt satisfies
those prerequisites or the genuine private-mode acceptance policy.
