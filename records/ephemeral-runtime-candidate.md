# Local checked-hook candidate

This experiment closes the reproduced shell extraction failure only. It is not an approved image, a runtime isolation implementation, or a deployment configuration. No mount, daemon, VM or cloud operation is performed by its tests.

`experiments/ephemeral-runtime/prepare-candidate.py` accepts only the preparation script with SHA-256 `1636030add2dfd5a85272a246939d7d1b472aa2a400e76b158dc39577a9c442a`, from [dstack 282eeb27d22d8f091ad0fa5a90e638f85cf68751](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/basefiles/dstack-prepare.sh). It creates a separate source candidate and refuses to overwrite existing output. It does not install that candidate.

The replacement requires the PoC's nonempty string `init_script`. It checks temporary-file creation and the complete `jq` extraction before sourcing any bytes. The standalone `source` remains under the parent's `set -e`; wrapping it in a conditional would disable the failure behavior being tested. No readiness marker is created. A hook can explicitly exit the shell successfully, so even exit zero cannot prove runtime readiness.

The local probe covers a valid environment-changing hook; missing, null, empty, array, number and malformed inputs; temporary-file failure; extraction failure before output and after an executable prefix; nonzero hook execution, a failure followed by success, and signal termination. It also demonstrates the successful-exit boundary. These are controlled process failures, not actual OOM or guest-boot tests.

## Requirements for an eventual image candidate

The selected v0.5.9 source [imports reused ZFS storage](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/dstack-util/src/system_setup.rs#L1171) before the init hook without `-N`. The pinned [OpenZFS import manual](https://github.com/openzfs/zfs/blob/33174af15112ed5c53299da2d28e763b0163f428/man/man8/zpool-import.8#L194) explains that `-N` suppresses filesystem mounting. Persisted mountpoint and overlay properties are therefore consumed before hook execution. This is a configuration trust gap, not proof of provider key access or exploitation.

The proposed measured configuration must explicitly select `storage_fs: "ext4"`, which uses the fixed-target ext4 setup branch, and `swap_size: 0`. The exact image must also exclude active swap and unwanted ZFS import paths. No complete measured app-compose policy or image approval is included here.

The immutable boot configuration must require successful preparation before Docker, containerd, Sysbox manager/filesystem services and the app launcher start, including Docker socket activation. Before each runtime start, an independent check must verify actual memory-backed `/var/lib/docker`, `/var/lib/containerd` and `/var/lib/sysbox` mounts and the absence of swap. Post-hook orphan cleanup must already use the memory-backed Docker root. A saved marker or systemd `RemainAfterExit` state is insufficient.

Runtime restarts should reuse the established memory-backed roots. Same-boot preparation restart cannot safely remount roots beneath surviving containers or shims: stock daemon `KillMode=process` does not prove those processes have stopped. That lifecycle requires exact-image process and unit tests. No such barrier is claimed by the loader patch.

Required live or exact-image evidence remains: unit ordering and socket activation; failures throughout extraction, mount setup and post-hook preparation; clean and unclean reboot with poisoned persistent runtime directories; actual mount and swap checks; runtime restart behavior; and RAM/storage-driver operation with the node. RAM allocation limits must follow measured resource needs. The supported-image source still fails the disk policy until an acceptable immutable change and its measurements are available.
