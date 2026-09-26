# One watchdog invocation

`zrpc lifecycle watchdog-once` is a **real provider action** for an existing
retained experiment. It can send DELETE requests. Running it selects the whole
experiment at the current locked ledger generation; it does not select new
targets or authorize later invocations.

Inspect its required options without contacting Phala:

```sh
./target/debug/zrpc lifecycle watchdog-once --help
```

Use the Unix ledger created through `zrpc lifecycle ledger`. The immutable
original determines the workspace, start time, absolute deletion deadline,
budget and retained history. Supply its exact experiment ID. The watchdog opens
the existing store and keeps its writer lock; it does not initialize a store,
discard drafts, replace history or renew the experiment.

## Required inputs

Every option is required. Only `--trust-root` may repeat. Supply absolute file
paths, an owner-private API-key file and independently selected DER trust anchors.
The transport uses the fixed Phala API origin with ordinary certificate and
hostname validation; credentials never belong on command arguments.

| Option | Meaning |
| --- | --- |
| `--original-binding FILE` | Existing immutable original binding. |
| `--experiment-id ID` | Exact experiment ID retained in that original. |
| `--api-key-file FILE` | Owner-private regular credential file. |
| `--trust-root DER_FILE` | One DER trust anchor per file; repeat for additional roots. |
| `--invocation-budget-ms B` | Positive total network invocation budget shared by all phases, pages and targets. |
| `--max-response-bytes N` | Positive response-body bound. |
| `--max-input-file-bytes N` | Positive per-input-file bound. |
| `--inventory-page-size N` | Provider range 1–100. |
| `--usage-page-size N` | Provider range 1–5000. |
| `--max-inventory-records N` | Positive retained inventory bound. |
| `--max-usage-records-per-app N` | Positive retained usage bound for each tracked app. |
| `--maximum-detection-interval-ms P` | Positive assumed maximum interval to detect a cleanup trigger, including execution delays. |
| `--deletion-latency-upper-bound-ms L` | Positive assumed bound for deletion dispatch, provider completion and required readback. |
| `--scheduler-delay-allowance-ms S` | Explicit nonnegative scheduling allowance; zero is accepted. |
| `--reconciliation-budget-ms R` | Positive budget for optional observation/reconciliation. |
| `--deletion-dispatch-budget-ms D` | Positive dispatch budget for the whole retained target set. |
| `--fee-upper-bounds-microusd F` | Explicit nonnegative aggregate fee upper bound in microUSD. |

Choose timing, memory and fee bounds from the operator's measured execution and
quoted resource assumptions. The command has no production defaults for them.
All numeric inputs must be representable integers. Timing validation requires
`R + D <= B`, `R + S <= P` and `D <= L` before file loading.

These inputs do not establish that a scheduler exists or that the assumed
latencies are achievable. An external schedule must account for execution time,
missed or overlapping runs, provider delays and the independent deadline
backstop. This command installs none of those mechanisms.

## Cleanup decisions

The total infrastructure ceiling remains **$50**, with a **$45** conservative
cost trigger and an original lifetime no longer than **168 hours**. Cleanup is
due by the original deadline minus `L` and `S`. Retained compute/storage rates
and the fee reserve can require earlier cleanup when waiting would threaten the
ceiling. An expired deployment quote does not prevent cleanup.

If cleanup is already due at startup, optional scans are skipped. Otherwise,
the observation phase is bounded by `R` and preempted when the original time or
cost policy requires deletion. Usage remains unjoined evidence and is not
accepted as an experiment charge. Scans and modeled costs never replace the
original start, deadline, rates or earlier expenses.

Cleanup uses the already tracked targets. Fresh authenticated workspace and
target-detail reads precede each first deletion attempt or linked retry of its
latest retained intent. Conflicting identity prevents dispatch. The command
records intent before sending DELETE and preserves prior pending intents and
outcomes. It attempts each retained target at most once in this invocation;
there is no retry loop or provider-idempotency guarantee.

All pages and targets share the original `B` deadline. `D` covers the complete
deletion phase; it is not renewed for each target. A limit, timeout or
interruption can leave work unfinished and can leave committed observations,
intents or outcomes. The command does not create resources, install jobs,
activate deployment or authorize a subsequent run.

Network phases use monotonic deadlines. The optional-read cutoff also accounts
for the next trigger projected from the retained cost model and wall clock.
Wall time is checked again after observation and before each target; a clock
jump during a request is detected at the next check. Local ledger validation
and durable filesystem writes are synchronous and can extend elapsed runtime.
These bounds therefore do not establish an end-to-end deletion-time guarantee.

## Reports and follow-up

The command emits one JSON document. Exit 0 means `invocation_completed` is true
for this invocation's required work. Exit 1 means refusal or incomplete work;
inspect the report and retained ledger before explicitly choosing another
action:

```sh
./target/debug/zrpc lifecycle ledger inspect --original-binding /absolute/path/to/original.json
```

DELETE 204 means deletion was initiated; DELETE 404 does not prove that storage
is gone. Neither status establishes billing finality. **Stopping a CVM does not
stop storage billing.** Disk-deletion evidence, billing reconciliation, an
external deadline controller and an independent backstop are still required
before deployment. Private mode remains unavailable, and watchdog results do
not approve hardware/workload identity, TLS-key binding or private queries.
