# Selected external watchdog host preflight — 2026-09-30

The operator selected this Mac mini, if it stays on, as the candidate host for
the independent Phala deletion watchdog. This records read-only host checks
and synthetic offline bundle generation, not an installed scheduler, live
deletion rehearsal, provider quote, or spending approval.

At 05:02 UTC, `colima status` reported a running native ARM64 Linux VM under
macOS Virtualization.Framework, using Docker and VirtioFS. In that VM,
`systemctl --version` reported systemd 255 (Ubuntu 255.4-1ubuntu8.12),
`systemctl is-system-running` returned `running`, and `timedatectl show`
reported `NTPSynchronized=yes`. Guest and host clocks displayed the same UTC
second in the sampled checks. The Colima login user had numeric UID 502.
`/Users/j/Code` was visible on VirtioFS with owner UID 502, GID 1000 and mode
0755. These observations establish a possible Linux/systemd execution host;
they do not validate the future watchdog executable, retained ledger mount,
service account, credentials, effective units or timer behavior.

The current Phala-primary `zrpc` was built with `cargo build --locked -p
zrpc-cli` in the managed ARM64 container. Its SHA-256 was
`4f53e45c1d4726d8302f4558bc842f2b9a83cf6f1fec041dd8547324d9508edc`.
Running that exact shared-workspace binary's `doctor` command inside Colima
exited 0, reported `primary_platform: phala-dstack` and kept private mode
blocked. Colima recomputed the same binary hash. This proves basic binary
compatibility on the selected VM, not an immutable host installation or a
successful provider deletion.

The repository's synthetic schedule checker had become stale: it omitted the
required `--ledger-mount-point` argument. After that repair, the managed
browser-profile container's systemd 257 parser accepted all four generated
service/timer files plus an explicit synthetic `workspace.mount` parser
fixture. The same exact generated files and fixture passed
`systemd-analyze verify --man=no` on this Colima VM's systemd 255 with exit 0
and no systemd diagnostic. The synthetic watchdog service executes
`/usr/bin/false`, not `zrpc`, so accidental activation fails; it and the mount
fixture are uninstalled. The synthetic ledger was
unchanged, no job ran, and no provider network call occurred. This is parser
and static dependency evidence only, not effective-unit, timer, restart,
latency or deletion evidence.

At 05:24 UTC, a second synthetic experiment was initialized directly on the
selected Colima VM under ignored workspace scratch storage. Its original
deadline remained within 168 hours; its experiment and workspace IDs do not
name a provider resource. `systemctl show Users-j.mount` reported the actual
`/Users/j` VirtioFS mount as loaded and active, with fragment
`/run/systemd/generator/Users-j.mount`. An offline `export-watchdog` run used
that exact mountpoint, UID 502, host-visible ledger paths, absent credential
paths and a `/usr/bin/false` watchdog executable. The manifest records four
uninstalled files, `jobs_installed: false`, `credentials_read: false`,
`network_used: false` and `timing_verified: false`. Colima's systemd 255
accepted those exact four files when the real generated mount unit was also
given to `systemd-analyze verify --man=no`; without the mount unit in that
parser invocation, it correctly reported an unresolved `Users-j.mount`
dependency. `systemd-analyze condition ConditionPathIsMountPoint=/Users/j`
succeeded. The retained scratch bundle is
`.codex-tmp/watchdog-host-rehearsal-20260930/bundle/`; it is a synthetic
artifact and grants no activation or deletion authority. On the selected VM,
the scratch and bundle directories had mode 0700, the original binding mode
0400, and the bundle manifest mode 0600, all owned by UID 502. All four unit
files matched the manifest's embedded bytes, with no extra bundle file.

`launchctl list` showed no Colima, Phala or `zrpc` job, and a file inventory of
the inspected macOS LaunchAgents and LaunchDaemons found no Colima auto-start
definition. This is bounded evidence, not proof that every possible startup
mechanism is absent. The previous authorized Colima restart did not itself
establish recovery after a Mac reboot. The selected host therefore cannot yet
be treated as an independent, always-running deletion control. Neither
synthetic bundle was installed here; no watchdog unit, timer, provider call or
cloud resource was activated in this preflight.

At 05:29 UTC, `pmset -g custom` showed AC-power `sleep=0`, `standby=0` and
`autorestart=0`; `pmset -g sched` showed no scheduled wake. The idle-sleep
setting is favorable for an attended evaluation, but power-loss recovery and
Colima startup after a Mac reboot remain unproven. No Mac power setting was
changed.

Before a billable Phala deployment, bind the original experiment ledger and
selected native binary to a persistent mount accessible to the chosen nonroot
UID, verify owner-private provider credentials and trust roots, derive timing
and fee bounds from the selected configuration, export the exact systemd 255
bundle, and validate its effective units and restart behavior on this host.
Provide a separate deadline/manual backstop that still works if the Mac or
Colima is down. Provider deletion must later be reconciled with attached
storage inventory and billing evidence; a stopped VM or DELETE response is
insufficient. The initial inventory alone satisfied none of those prerequisites.

## Volatile effective-unit rehearsal — 2026-09-30

The existing four synthetic bundle files were copied into Colima's volatile
`/run/systemd/system` and loaded with `systemctl daemon-reload`. The service's
exact `ExecStart` begins with `/usr/bin/false`; its credential and trust-root
paths do not exist. No provider-capable executable or credential was installed.
Starting the generated mount-ready service activated both generated timers.
The gate reported `active/exited` and `Result=success` while the actual
`Users-j.mount` was mounted. The synthetic service ran at 10:25:59 EDT and
failed with exit status 1 as designed. The periodic timer fired at 10:26:52
EDT, ran the same inert service again, and scheduled its next firing for
10:27:45 EDT. The absolute timer reported its next event as October 7 at
05:21:56 UTC, matching the generated calendar value. This is observed systemd
255 behavior on the selected Colima VM, not merely unit-file parsing.

All four units were stopped, unlinked from `/run/systemd/system`, and removed
from systemd's loaded configuration. A final `list-timers` showed zero matching
timers, and both synthetic timers reported `LoadState=not-found` and
`ActiveState=inactive`. The synthetic original-binding file still matched its
initialized copy byte-for-byte. No Phala API call, deletion attempt, billable
resource or real watchdog activation occurred.

This rehearsal confirms initial gate activation and one periodic firing only.
It does not prove behavior after a Colima or Mac reboot, mount loss, provider
outage, a slow deletion, or a real authenticated watchdog invocation. Those
tests, the independent deadline backstop, current quote, and billing/storage
reconciliation remain deployment prerequisites.

## Isolated mount-loss and authenticated invocation rehearsal — 2026-09-30

The earlier owner-private ARM64 CLI was found stale: its `export-watchdog`
interface lacked the current `--ledger-mount-point` requirement. The current
worktree was rebuilt inside the managed container with `cargo build --locked
-p zrpc-cli`; `cargo test --locked -p zrpc-lifecycle schedule::` passed 17
tests. The updated executable SHA-256 is
`3b58199bdb2975ed58c100d15770966313b2deb28f76d6deef80e87a7fb1c6ba`.
The VM copy matched and advertised the mount-bound export interface.

A separate tmpfs was mounted at `/run/zrpc-watchdog-probe`, containing only a
synthetic ledger with no tracked CVM. The current CLI exported four uninstalled
units; a matching disposable mount unit was added under volatile
`/run/systemd/system`. Colima's systemd 255 accepted the five units. Starting
the mount gate activated both timers, and the generated service executed the
current `zrpc lifecycle watchdog-once` binary successfully against the empty
experiment. The provider credential and explicit TLS root were used for
authenticated reads, but there was no tracked deletion target.

Stopping the **disposable test mount**, without touching `/Users/j`, caused
the gate and both timers to become inactive. The mount and all five volatile
unit files were removed; both timers then reported `LoadState=not-found` and
`ActiveState=inactive`. This proves effective fail-closed mount-loss behavior
for an isolated synthetic ledger on this VM. It does not prove Mac reboot
recovery, provider deletion latency, mounted production-ledger recovery,
attached-storage deletion, or billing finality. No Phala CVM or billable
resource was created.

The retained inert `/usr/bin/false` bundle on the real `/Users/j` VirtioFS
mount was then installed temporarily under `/etc/systemd/system` and enabled
for `Users-j.mount`. Its gate and both timers were active before a Colima VM
restart. An immediate force-stop lost those recently written `/etc` files;
the VM disk uses an ext4 commit interval, so an unsynchronized force-stop is
not a valid persistence test. Repeating the installation with `sync` before
the force-stop preserved all four files and the enablement link. After boot,
`Users-j.mount`, the gate, and both timers were active. The route still chose
`col0`, and the current CLI survived on the VM disk. The synthetic units were
stopped, disabled, removed, and synchronized; both timers then reported
`LoadState=not-found` and `ActiveState=inactive`.

This establishes one synchronized **Colima VM** restart recovery, not Mac
power-loss recovery or an assurance that an abrupt crash immediately after
installing production units preserves them. A production installation must
sync its unit files and ledger before any billable call, then verify effective
units and the mounted ledger again.
