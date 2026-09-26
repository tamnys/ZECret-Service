# Offline watchdog scheduling bundle — 2026-09-26

Contract: make the remaining external periodic/absolute execution prerequisite
concrete and reviewable using the implemented `watchdog-once` command. Generate
original-bound service/timer files without loading credentials, creating a
provider client, installing jobs or authorizing deployment. Preserve the same
deadline/cost policy, current-history loading and independent-backstop requirement.

## Implemented boundary

`zrpc lifecycle export-watchdog` requires all watchdog inputs plus an absolute
binary path, nonroot numeric service UID, literal unit stem, whole-process
timeout, manager-delay allowance and new absolute output directory. It reuses
the existing watchdog argument parser. Generation opens only the original-bound
ledger under its writer lock; credentials, trust roots and executable paths can
be absent. Their existence, ownership, provenance and external-host location
are not asserted. The exporter never invokes the selected executable or a
systemd/provider command.

The generated command retains the exact original path and experiment ID and
all explicit watchdog settings. It loads the latest committed generation each
time instead of freezing the export generation. Existing intents, overdue
deadlines and current costs are retained; generation does not call deployment
quote validation or reset history. Reports contain the reviewed generation,
original binding, exact arguments, timing derivation and the three unit texts.
Installation, timing verification, credential reads, network use, activation,
deployment and private acceptance remain false.

Export creates one private directory and four private files: the service, a
periodic timer, an absolute timer and `manifest.json`. It rejects existing
destinations, final symlinks and paths inside the ledger, including via a parent
alias. Files are created exclusively, synchronized, and the manifest is written
last. Errors retain partial output for inspection; there is no overwrite or
automatic cleanup. Ancestor ownership/stability remains operator trust, as for
the existing ledger; this is not hostile same-UID filesystem protection.

## Scheduling and encoding contract

The service uses `Type=oneshot`, numeric `User`, `UMask=0077`,
`NoNewPrivileges=yes`, explicit `TimeoutStartSec`,
`TimeoutStartFailureMode=kill`, `Restart=no`, `RemainAfterExit=no` and
`StartLimitIntervalSec=0`. Both timers name the same service and `Wants` it for
startup evaluation. The periodic timer uses `OnUnitInactiveSec`; the absolute
timer uses the original watchdog due time and `Persistent=true`. Both set
`AccuracySec=1us` and `RandomizedDelaySec=0`. No installer is included.

The old offline activation proposal's `P−1us` interval is not reused. With
explicit whole-service timeout `T`, manager/launch/timeout-overshoot allowance
`J`, reconciliation budget `R`, catch-up allowance `S`, timer accuracy `A=1us`,
the new generator requires:

```text
I = S − T − J − R − A > 0
T + I + J + R + A = S
R + S <= P
T >= B
absolute event = original deadline − L − S
```

All supplied durations are exact whole milliseconds; the interval preserves
the subtracted microsecond. Overflow, mismatched policy/decision, no positive
interval, insufficient process budget and dates outside the calendar parser's
1970–2199 range are rejected. The event is not moved before the watchdog due
threshold: an early sole invocation could otherwise finish without deletion.

Systemd documents that an active service is not restarted by a timer event.
The catch-up equation therefore includes the active service and next periodic
check, conditional on the supplied bounds. `Persistent` addresses missed
calendar events after reactivation, not downtime itself. These semantics and
the documented precision come from the [versioned timer contract](https://github.com/systemd/systemd/blob/v257/man/systemd.timer.xml).
The reviewed [timer implementation](https://github.com/systemd/systemd/blob/a446e8ff2ccb76a8719cb5f06a7fcf785dc116e2/src/core/timer.c#L745)
also reschedules after a triggered service becomes inactive or failed.

For oneshot services, `TimeoutStartSec` bounds configured execution;
`RuntimeMaxSec` does not. Final-signal timeout handling avoids an implicit stop
grace period, but cannot guarantee prompt termination of uninterruptible I/O.
See the [service contract](https://github.com/systemd/systemd/blob/v257/man/systemd.service.xml).
These remain operator assumptions until measured on the actual external host;
no hard real-time or billing guarantee is claimed.

ExecStart contains one quoted absolute executable and separate quoted arguments,
with literal backslash/quote/dollar/percent handling and control/line-separator
rejection. There is no shell. Executable dollar signs, quotes and backslashes
are rejected because systemd resolves executable paths separately from argv
environment expansion. The encoder follows [command parsing](https://github.com/systemd/systemd/blob/v257/src/core/load-fragment.c),
[argument expansion](https://github.com/systemd/systemd/blob/v257/src/core/exec-invoke.c)
and [versioned syntax](https://github.com/systemd/systemd/blob/v257/man/systemd.syntax.xml).
Literal non-template unit names fit the documented [255-character total limit](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml).

## Verification and limits

Managed untrusted browser-profile Linux execution of
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 bash scripts/check.sh` passed **334 Rust
tests**: 295 workspace unit tests, 25 compile-fail documentation tests and
14 runtime-guard tests. Required builds, dependency/fixture guards, CLI,
public-inspection and wrapper checks passed. New coverage includes arithmetic,
calendar boundaries, skipped-event budget, literal argument encoding, malformed
input, pending/corrupt history rejection, missing/FIFO provider inputs,
unchanged ledger bytes, private outputs and overwrite/alias refusal.

The initial focused run returned `UnsafePath` while two existing fixtures were
being created. The isolated persistence case and complete unchanged affected
suite subsequently passed; the cause was not established and no filesystem
check was weakened. Logs are `.codex-tmp/schedule-focused.log`,
`.codex-tmp/schedule-failure-probe.log` and
`.codex-tmp/watchdog-schedule-workspace.log`.

`python3 scripts/check-schedule-units.py` generated an additional synthetic
bundle with spaces, quotes, dollars, percent specifiers, backslash and semicolon
in arguments. `systemd-analyze verify --man=no` from **systemd 257.13-1~deb13u1**
accepted all three files with no warnings or stderr. Original/ledger bytes
were unchanged. Artifacts are retained in
`.codex-tmp/schedule-units-5eohqoko/`; the check summary is
`.codex-tmp/schedule-unit-parser.log`. This is maintained-parser validation,
not service execution, a timer firing test or actual-host installation evidence.
The README/watchdog documentation boundary check and `git diff --check` passed.
No UI or dependencies changed; visual QA and dependency downloads were unnecessary.

No cloud credentials, Phala calls, jobs, resources or spending were involved.
All generated validation data is synthetic. Live approval, measured host and
provider timing, independently installed periodic/absolute controls, a separate
backstop, real teardown/storage/billing evidence and all private-mode Gates A–E
remain required. The new files are deployment preparation, not activation.

An internal coordination issue occurred: a sub-agent printed its Agent Mail
registration response, including its registration token, into tool output.
The token was not placed in project files or exported bundles, and no provider
credentials were accessed. The exposed MCP tools offer no token-revocation
operation; this is recorded separately from the application's security gates.
