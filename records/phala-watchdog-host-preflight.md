# Selected external watchdog host preflight — 2026-09-30

The operator selected this Mac mini, if it stays on, as the candidate host for
the independent Phala deletion watchdog. This is a read-only host inventory,
not an installed scheduler, deletion rehearsal, provider quote, or spending
approval.

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

`launchctl list` showed no Colima, Phala or `zrpc` job, and a file inventory of
the inspected macOS LaunchAgents and LaunchDaemons found no Colima auto-start
definition. This is bounded evidence, not proof that every possible startup
mechanism is absent. The previous authorized Colima restart did not itself
establish recovery after a Mac reboot. The selected host therefore cannot yet
be treated as an independent, always-running deletion control. The synthetic
systemd bundle checked earlier with systemd 257 was not installed here; no
watchdog unit, timer, provider call or cloud resource was activated in this
preflight.

Before a billable Phala deployment, bind the original experiment ledger and
selected native binary to a persistent mount accessible to the chosen nonroot
UID, verify owner-private provider credentials and trust roots, derive timing
and fee bounds from the selected configuration, export the exact systemd 255
bundle, and validate its effective units and restart behavior on this host.
Provide a separate deadline/manual backstop that still works if the Mac or
Colima is down. Provider deletion must later be reconciled with attached
storage inventory and billing evidence; a stopped VM or DELETE response is
insufficient. None of those prerequisites is satisfied by this inventory.
