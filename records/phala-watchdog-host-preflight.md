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
