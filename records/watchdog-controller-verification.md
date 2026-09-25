# Local watchdog controller record

The controller in `crates/lifecycle/src/controller.rs` is a local model backed
only by a sealed, in-memory provider. It cannot activate cloud access, install a
scheduler, create resources, or authorize spending. Its report always identifies
simulation, unavailable live activation, and incomplete cleanup.

The experiment binding retains the original workspace, start, absolute deadline,
$50 total cap, and $45 deletion trigger. Attempts append resource identities and
costs without replacing this binding. JSON restoration compares the saved binding
with a separately supplied original and validates resource/cost relationships.
The Unix persistence layer described below retains that original separately and
serializes writers. This is not authenticated storage. Creating another ledger
is not evidence that an existing experiment ended; live activation is unfinished.

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
failures. Before persistence was added, the root task ran
`cargo test --locked -p zrpc-lifecycle` in its managed container: all 22 unit tests
passed, including the 11 controller tests. The final expanded result is below.

`crates/lifecycle/src/persistence.rs` adds local filesystem persistence. An
explicit create-new operation publishes a read-only original binding outside
the mutable store, including its fixed store path and initial ledger. A separate
initialization receipt prevents the API from reinitializing a missing store or
retrying partial initialization as a new experiment. Interrupted initialization
fails closed for operator inspection; it does not invent recovery state.

Every opened store holds an exclusive OS file lock on a permanent lock inode.
New generations preserve previous attempts, resource identities, billing records,
original policy, clock and cost floor. Each generation is written to a create-new
draft, fsynced, published with an atomic hard link that cannot replace an existing
target, and followed by directory fsync. Committed snapshots are never overwritten.
Readers validate the complete contiguous history; any malformed newer snapshot
fails loading instead of selecting an older, cheaper state. Original and snapshot
records require JSON objects. Nested ledger JSON remains a `RawValue` until strict
typed validation, so duplicate fields cannot be erased by a generic value map.
Write/fsync failure
reports uncertain outcome and requires reopening. An explicit recovery method
can discard only an uncommitted draft after validating committed history; it never
promotes a draft or repairs a committed snapshot.

The store uses maintained `libc` constants through safe Unix `OpenOptionsExt`
for `O_NOFOLLOW`, `O_DIRECTORY`, and `O_NONBLOCK`. It rejects symlink outputs and
nonregular files. The original, initialization receipt, store, and ancestors must
remain operator-controlled: locks coordinate cooperating writers, and same-UID
replacement/deletion, malicious filesystem rollback, or file-owner compromise
are not prevented. Read-only permissions are an accident guard, not authentication.
No fsync or hard-link durability guarantee beyond the hosting filesystem is made.

The required Rust minimum is 1.89 because the standard library stabilized
[`File::try_lock`](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
in that release. The implementation does not clone or replace the locked file.
No new dependency version is required; it uses the already locked `libc` 0.2.189
and the existing pinned `serde_json` with its `raw_value` feature.

Persistence tests cover history roundtrips, attempted reset, exclusive locking,
existing/symlink outputs, malformed originals and newer snapshots, duplicate nested
cost/binding/resource fields, positional array rejection, explicit draft recovery,
uncertain writes, and subprocess exits without Rust destructors at each
write/publication boundary. Generated fixtures stay under the workspace's ignored
`.codex-tmp`. This is process-interruption evidence, not a physical power-cut test.
After persistence was added, the root task's managed-container workspace suite
passed all 109 unit tests and 15 compile-fail tests. That included all 33 lifecycle unit tests: the earlier
22 tests plus 11 persistence tests, including the strict JSON regressions.

`crates/lifecycle/src/activation.rs` now generates an offline activation planning
artifact from an actual committed snapshot, verified under the store's held lock.
It carries the original binding, generation and snapshot path; pending storage
recovery blocks generation. Retry plans must preserve the original deadline,
include the committed/modeled accrued cost, and retain every tracked resource's
conservative rate. The existing cost planner checks every quoted fee category and
the $45 trigger plus polling/deletion-delay cost against the $50 total cap.

The artifact contains proposed periodic and absolute timer directives and an
independent backstop check at the proposed deletion-start time. It emits no unit
files or runnable command; its executable and arguments are absent, installation
state is `proposed_only`, and activation remains unavailable. External reference
strings remain operator assertions, with explicit outstanding receipt categories
for the adapter, credentials/external store, installed jobs, measured delays,
deletion/readback/disk evidence, billing, independent backstop and operator action.

The [official systemd timer contract](https://github.com/systemd/systemd/blob/a446e8ff2ccb76a8719cb5f06a7fcf785dc116e2/man/systemd.timer.xml)
documents `AccuracySec=1us` for best accuracy and default zero randomized delay.
The proposal subtracts that one-microsecond window from the supplied maximum poll
interval. Its absolute trigger subtracts supplied deletion latency and the same
accuracy window from the original deadline. Kernel slack, service overlap,
suspension, and host downtime still require measured external controls; this
arithmetic does not establish a guaranteed cap. `Persistent=true` only affects
calendar timers and catches missed runs after reactivation. The command contract
separately requires an immediate startup policy check, never deadline renewal.

UTC conversion uses already locked `chrono` 0.4.45 with only `std` enabled,
without its clock feature. Output includes six fractional digits and explicit
`UTC`, as supported by the [official calendar syntax](https://github.com/systemd/systemd/blob/a446e8ff2ccb76a8719cb5f06a7fcf785dc116e2/man/systemd.time.xml).
It enforces the target parser's [1970–2199 year range](https://github.com/systemd/systemd/blob/a446e8ff2ccb76a8719cb5f06a7fcf785dc116e2/src/shared/calendarspec.c#L19)
rather than emitting chrono's wider dates as unsupported systemd expressions.
New unit cases cover exact UTC/leap-day conversion, unactivatable output, retries,
reserve boundaries including fees and latency, missed deadlines, and refusal of
pending or financially incomplete ledger plans. The root task ran the focused
managed-container lifecycle suite: all 39 tests passed, including these six
activation-planning cases. The final integrated managed-container check also
passed: 123 workspace unit tests, 15 compile-fail tests, 14 standalone runtime-guard
tests, feature/checksum checks, CLI checks, formatting and CLI/example builds.

A live adapter, external periodic and absolute deadline jobs, independent backstop,
real teardown test, disk evidence, and final
charge reconciliation remain prerequisites to hosting. No mock receipt satisfies
those prerequisites or the genuine private-mode acceptance policy.
