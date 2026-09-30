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

## Prepare an offline scheduler bundle

`zrpc lifecycle export-watchdog` creates uninstalled systemd files for review.
It reads the existing original-bound ledger and writes only a new private output
directory. It does not read the API key, trust roots or selected executable, and
does not contact Phala or a systemd manager. Show its required options with:

```sh
./target/debug/zrpc lifecycle export-watchdog --help
```

Supply all `watchdog-once` options above, plus:

| Option | Meaning |
| --- | --- |
| `--executable ABSOLUTE_PATH` | Native `zrpc` binary selected for the external Linux host. |
| `--service-user UID` | Existing nonroot numeric UID on that host; zero and the invalid UID sentinel are rejected. |
| `--unit-name STEM` | Unique literal name using ASCII letters, digits, hyphens or underscores; begin with a letter or digit. |
| `--ledger-mount-point ABSOLUTE_HOST_MOUNT` | Non-root mountpoint on the external Linux host that contains both the original binding and mutable ledger. Use a normalized absolute path made of ASCII letters, digits, slashes, hyphens, underscores, dots or colons. |
| `--process-runtime-bound-ms T` | Positive whole-service timeout, including local work; must be at least `B`. |
| `--manager-delay-allowance-ms J` | Explicit nonnegative allowance for manager/launch delays, timer slack and timeout-to-inactive overshoot outside `T`. |
| `--output-directory ABSOLUTE_NEW_DIRECTORY` | New private review directory outside the retained ledger. |

The destination's parent must already exist and be operator-controlled. Export
refuses existing output, symlink replacements and output inside the ledger,
including through a parent alias. Keep the bundle in private operator storage;
it contains account identifiers and local paths. API-key contents never belong
in unit text or command arguments. On export failure, inspect the retained
partial directory and choose a new destination; no history or output is reset.

The five files are `STEM.service`, `STEM-mount-ready.service`,
`STEM-periodic.timer`, `STEM-deadline.timer` and `manifest.json`. The manifest
records the selected mountpoint and its systemd mount unit, original binding,
reviewed generation, exact command arguments, timing calculation and file
contents. The future command loads the latest committed ledger under its writer
lock; it does not freeze that reviewed generation or accept new targets from a
timer. The service uses the original absolute paths, which must be accessible
to the selected UID on the external host. Export checks that the original
binding and mutable ledger paths are under the selected mountpoint. It cannot
verify that the external host actually mounts them there. Confirm the effective
mount unit and ledger location before installation. Export does not check host
account existence, binary provenance, file ownership, installed systemd
configuration or availability.

Enable only the mount-ready service after installing and reviewing all four
units. It is wanted by the selected `.mount` unit, waits for that unit to be
active, and requires the configured path to be a mountpoint. It then starts
both timers. The timers bind to the gate, and the watchdog service binds to the
mount. A manual timer start or a lost mount cannot run the watchdog against an
unmounted ledger path. Do not enable the timers directly under `timers.target`.

Both timers target one service and request a startup check. Its explicit
`Type=oneshot` timeout is `T`, with immediate final-signal handling on timeout,
no restart loop and no inherited start-rate suppression. The periodic timer
counts from service inactivity, including failure. The deadline timer retains
the exact original `deadline − L − S` time in UTC and uses `Persistent=true`
for missed calendar events after reactivation when it has a prior timer stamp.
On a timer's first activation after that event, the startup check still runs
through the periodic timer. Unit syntax targets systemd 255;
validate the complete files and effective configuration on the selected host.

For this bundle, `S` must cover a skipped timer event while the service is
already active, as well as scheduling delays. The periodic gap is derived as:

```text
A = 1 microsecond (configured timer accuracy)
I = S − T − J − R − A  > 0
T + I + J + R + A = S
R + S <= P
```

This leaves room for the active process, the next interval, manager delay and
observation before deletion must begin. `B` alone is insufficient because it
does not bound ledger loading or synchronous filesystem work. A configuration
that fits a standalone watchdog invocation can therefore fail bundle export.
No example timing values are production defaults.

The derivation is conditional on measured host/provider bounds. A timeout
cannot guarantee prompt termination during uninterruptible kernel I/O, a
calendar timer cannot eliminate downtime, and an event does not restart an
already-active service. Persistent state and the periodic catch-up policy do
not replace the independent external backstop.

Before any separately approved installation, verify the selected binary's
checksums, input ownership and permissions, service account, effective unit
configuration and host clock. Validate timing with local fixtures and then the
approved live deletion test. Both timers, the independent backstop, storage
deletion evidence and billing reconciliation remain required. Export grants no
installation, deployment or spending permission and emits no activation receipt.
