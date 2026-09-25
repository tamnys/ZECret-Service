# Candidate runtime storage guard

Internal experiment, 2026-09-25. `experiments/ephemeral-runtime/runtime-guard.rs` is a dependency-free Rust/Linux pre-start checker for a proposed immutable image. It is not installed, part of the stock image, an approved workload measurement, or a private-mode acceptance path.

## Contract and implementation

The executable accepts no arguments or fixture paths. On each invocation it reads `/proc/self/mountinfo` and `/proc/swaps`, canonicalizes the existing Docker, containerd and Sysbox directories under `/var/lib`, and requires their covering filesystems to be `tmpfs` or `ramfs`. Canonical paths handle the image's volatile-directory symlinks; equal or nested resolved runtime roots are refused. A memory filesystem may cover a root through an ancestor mount. A source-device name such as `tmpfs` is not accepted as filesystem identity.

Every mount beneath a runtime root must also have a directly identified memory filesystem. Relevant stacked mountpoints, duplicate mount IDs, and parent-ID relationships inconsistent with the nearest path ancestor fail. The parent check prevents treating a hidden child mount beneath an ancestor overmount as the visible filesystem. Path comparisons use complete components; proc octal escapes are decoded once before comparison. Unknown optional mountinfo fields are ignored as Linux specifies. Incomplete or malformed records fail.

The swaps file must contain the expected header and no additional records. Unused swap and zram are both refused because the selected candidate contract requires no active swap. The guard rereads the proc files and canonical roots before success and rejects changes it observes. These reads are not an atomic transaction and do not prevent later changes.

The parser follows the [Linux mountinfo documentation](https://www.kernel.org/doc/Documentation/filesystems/proc.txt), [kernel mountinfo emitter](https://github.com/torvalds/linux/blob/v6.6/fs/proc_namespace.c#L135), and [swaps header/record emitter](https://github.com/torvalds/linux/blob/v6.6/mm/swapfile.c#L2627). The documented backing properties of [tmpfs](https://docs.kernel.org/filesystems/tmpfs.html) and [ramfs](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html) motivate the explicit filesystem checks; tmpfs can otherwise use swap. Kernel v6.6 source grounds the proc format, not the selected Phala kernel's approval or a claim of boot compatibility.

## Candidate service integration

`runtime-guard.conf` proposes immutable `Requires`/`After=dstack-prepare.service` and an unignored `ExecStartPre=/usr/bin/phala-runtime-guard` for Docker, containerd, Sysbox, Sysbox manager/filesystem, and app-compose services. It is a source template, not an installed drop-in. The guard must execute in the runtime's effective mount namespace with the same paths, including socket-activated and automatic starts. A separate oneshot, readiness marker, `RemainAfterExit` result or `ExecCondition` skip is not a substitute for checking before each start.

The fixed image must still include checked hook extraction and a reviewed preparation sequence. The guard does not establish that memory was freshly initialized, that no persistent bytes were copied into it, or that configuration and runtime data paths cannot redirect file access. Nor does it prevent later mounts, swap activation, kernel compromise, guest administration or writes through surviving file descriptors. Post-hook orphan cleanup must already use memory-backed runtime roots before these services start.

Overlay, bind-mounted public chain state, and other non-memory filesystem types below a runtime root are refused without trying to infer backing from mountpoint names or overlay option strings. This can block a daemon or app restart when surviving containers or shims retain such mounts, even when the underlying writes are memory-backed. Stock `KillMode=process` leaves that lifecycle unresolved. This experiment neither stops those processes nor remounts storage; a reviewed quiescent restart sequence and exact-image tests are still required.

## Local verification

The committed proc-format fixtures are synthetic and cannot authorize private mode. Embedded Rust tests cover memory-backed roots, inherited memory coverage, persistent roots, escaped nested persistent mounts, overlays, safe nested memory mounts, component-prefix siblings, stacked/hidden mounts, contradictory parents, duplicate IDs, canonical-root aliases, active/unused/zram swap, malformed/truncated records, numeric overflow and pathname escapes.

Run in the existing managed shell with the already-pinned Rust toolchain; no dependency download is needed:

```sh
rustc --edition=2021 --test experiments/ephemeral-runtime/runtime-guard.rs \
  -o .codex-tmp/runtime-guard-tests
.codex-tmp/runtime-guard-tests
rustc --edition=2021 experiments/ephemeral-runtime/runtime-guard.rs \
  -o .codex-tmp/runtime-guard
```

Managed-container verification on 2026-09-25 passed all 14 embedded tests. Both the test binary and the standalone, non-test guard compiled with the commands above and the existing managed Rust toolchain. No dependency installation was needed.

The standalone guard was not invoked to claim acceptance of the current namespace. No mount-namespace/tmpfs integration test, Phala guest boot, systemd start, root mount operation, cloud call or deployment was performed. The tests do not prove guest administrative access absent or establish the actual image's runtime lifecycle. Any success output still reports `private_accepted: false`. No memory sizing cap is introduced.
