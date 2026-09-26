# Lifecycle test diagnosis — 2026-09-26

The intermittent `UnsafePath` failure remains unresolved. Three instrumented
runs passed; this is not evidence that the earlier failures were repaired.
The investigation stopped at the operator's three-round limit without changing
path checks, permissions, retries, test concurrency or container configuration.

## Established failure boundary

The retained failures are in
`persistence::tests::retry_and_retry_outcome_faults_never_replace_prior_intents`
and, in an earlier run,
`provider_http::deletion::tests::explicit_entrypoint_persists_before_one_exact_delete_and_blocks_another_invocation`.
Their original line locations (`persistence.rs:1124` and
`provider_http/deletion/tests.rs:69`) call `LedgerStore::initialize` after
`create_original_binding` has returned success. They do not show original
publication failing. See the earlier evidence in
[the scheduler verification](watchdog-schedule-verification.md) and
[the node preflight](zebra-integration-preflight.md).

Initialization reads the original through the checked directory/regular-file
paths, requires its mode to have no write bits, then creates the initialization
receipt and store. The public `UnsafePath` error alone does not identify which
check or underlying I/O operation failed.

The inspected fixtures use distinct canonicalized bases and process-ID/atomic
sequence names; cleanup targets their own directories. No parent-process
environment, current-directory, umask or file-descriptor-limit mutation was
found in the lifecycle tests. The crash-boundary helper modifies only its child
environment. These source observations do not establish the runtime cause.

The managed browser container reported a FUSE workspace filesystem and an open
file limit of 1024. Neither observation proves a filesystem bug, stale metadata
or descriptor exhaustion. No limit or filesystem setting was changed.

## Retained diagnostics

`crates/lifecycle/src/persistence.rs` now includes `cfg(test)` diagnostics at the
directory metadata/open, directory-type, regular-file open/type and original
writable-mode rejection sites. They identify the operation and report a raw
OS error number or observed mode as appropriate. They omit paths, original or
ledger contents, credentials and network data.

Successful tests retain normal libtest output capture. Production builds do not
contain these diagnostics. All errors still map to the same `StoreError`
variants, and a failed check still rejects immediately. No automatic retry or
permission correction was introduced.

## Execution evidence

All commands ran in one managed, untrusted browser-profile shell. Existing
dependencies and locks were reused. `CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1` was
set for the already reviewed dependency builds.

| Run | Command | Result | Retained log |
| --- | --- | --- | --- |
| 1 | `cargo test --locked --workspace --lib` | 283 unit tests passed | `.codex-tmp/lifecycle-path-diagnostic.log` |
| 2 | `cargo test --locked --workspace --lib` | 283 unit tests passed | `.codex-tmp/lifecycle-path-diagnostic-2.log` |
| 3 | `cargo test --locked --workspace` | 298 unit tests and 25 compile-fail documentation tests passed | `.codex-tmp/lifecycle-path-diagnostic-3.log` |

The third run includes all workspace test targets; it does not rerun the separate
CLI/browser/runtime-guard scripts, whose behavior this diagnostic change does
not modify. No new tests or dependencies were added. No live provider, node,
attestation, deletion or deployment operation ran.

## Next evidence

If a normal required verification run fails again, preserve the captured
operation/errno/mode diagnostic before selecting another investigation or fix.
Passing reruns cannot erase the unresolved failure. There is currently no
evidence justifying weaker path checks, blanket retries, test serialization,
permission changes or a container-system modification.
