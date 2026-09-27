# Unsigned GCP guest build feasibility in the managed container

Date: 2026-09-26. This is an execution-capability record, not a guest image,
release manifest, or deployment approval. No package install, image build,
signing operation, cloud API, or host-policy change was performed.

The supported `--trust untrusted --platform linux/amd64` default container is
`x86_64`, but runs as UID 502 with `CapEff: 0000000000000000`.
`python3 tools/gcp-guest/prepare.py preflight` exited 1 and reported missing
`mkosi`, `systemd-repart`, `ukify`, `gpgv`, `sbsign`, and `veritysetup`, plus
denied user namespace creation. `unshare --user --map-root-user true` returned
`Operation not permitted`.

The hash-matched mkosi 25.3 source (commit
`54c625c380ef5500f17460981a3c67b109b6a847`) was exercised directly as
`PYTHONPATH=.codex-tmp/gcp-source/mkosi-source/mkosi-25.3 python3 -m
mkosi.sandbox -- /usr/bin/true`. It exited 1 at
`sandbox.py:375` (`unshare(CLONE_NEWUSER)`) with `PermissionError: [Errno 1]
Operation not permitted`. The command requested no package installation or
image output. The failure occurs before mkosi can mount its sandbox or invoke
repart/ukify.

The [pinned mkosi manual's REQUIREMENTS section](https://github.com/systemd/mkosi/blob/54c625c380ef5500f17460981a3c67b109b6a847/mkosi/resources/man/mkosi.1.md#requirements)
says mkosi needs unrestricted ability to create and act within namespaces.
Its source calls `acquire_privileges()` and unshares a user namespace for a
non-root process, then unshares the mount namespace. The manual also documents
`RepartOffline=yes`, which can avoid loop devices for disk construction; that
does not remove the namespace requirement. The managed `CONTAINER_SYSTEM.md`
contract rejects
privileged services, added Linux capabilities, direct devices, host/user
namespaces, and unconfined seccomp/AppArmor settings in Compose inputs.

Therefore the existing supported container cannot produce even an unsigned
mkosi raw/UKI candidate. Installing or copying the missing tools alone would
not solve the `CLONE_NEWUSER` denial. A separate, reviewed image-builder
environment with supported namespace and exact toolchain inputs is required
before a build can be attempted. The project still lacks the full authenticated
package/base-tree/kernel/initramfs closure and an eligible Zebra binary; those
would remain gates even in a capable builder. No first-seen measurement or
synthetic image can enter the approved-release catalog.

## 2026-09-27 opt-in guest-builder follow-up

The reviewed `guest-builder` container profile was prepared by the canonical
container-system full verifier (`2937.143s`), activated, and loaded with its
hash-checked, boot-scoped AppArmor policy. The policy check passed. This is a
local container capability change, not an image build or cloud deployment.

`colima list` reports one VM: the `default` Colima profile is `aarch64`.
`uname -a` inside that VM reports an `aarch64` Linux kernel. The new
`guest-builder-amd64` and existing `amd64` names identify Docker container
profiles on that ARM VM; they do not identify native x86_64 VMs. The x86_64
container runs through QEMU user-mode emulation.

Inside `guest-builder-amd64`, `python3 tools/gcp-guest/prepare.py preflight`
reported x86_64 architecture but exited blocked. The expected build tools
(`mkosi`, `systemd-repart`, `ukify`, `gpgv`, `sbsign`, `veritysetup`) are still
absent. More importantly, `unshare -U` variants returned `EINVAL`, so the
user, network, and mount namespace probes failed. Native ARM `unshare --user`
in Colima succeeded; the guest-builder had dropped capabilities, enabled
no-new-privileges and seccomp, and was under the named enforcing AppArmor
profile. No AppArmor denial was observed. This matches [QEMU's linux-user
namespace limitation](https://gitlab.com/qemu-project/qemu/-/issues/871),
so widening the reviewed policy is not a justified fix.

The signed September 18 builder archive cache contains all 194 source-pinned
packages, and the offline APT-plan verifier passed. The script-free stager
still reports an unbuilt diagnostic. Real extraction stops before output
creation because signed `libpam-runtime` contains both `PAM.7.gz` and
`pam.7.gz`, which collide on the current case-insensitive `/workspace`
backing volume. A project-local case-sensitive APFS probe image was created,
but macOS refused to attach it at the project mountpoint (`Permission
denied`); the disposable probe was removed. No package scripts ran. A native
x86_64 Linux builder with case-sensitive workspace-backed storage, or a
separately reviewed equivalent environment, is still needed before an
unsigned image build can be attempted. The approved-release catalog remains
empty. No cloud resource was created, and no private query was sent.

## 2026-09-27 native x86 runner probes and unsigned guest binaries

The manually dispatched [public standard GitHub runner probe](https://github.com/tamnys/ZECret-service/actions/runs/36332370259)
ran on `x86_64` with a case-sensitive workspace. A root-owned mount, network,
and PID namespace smoke test mounted and unmounted a temporary `tmpfs` and
observed no routes. The runner account's user-namespace mapping failed with
`write failed /proc/self/uid_map: Operation not permitted`. Mapping a new
user namespace's root to the runner UID from a root-owned process also failed:
`newuidmap: uid range [0-1) -> [1001-1002) not allowed`. This workflow used no
checkout, dependencies, cache, artifact upload, or signing key. The rootful
smoke test stayed in the initial user namespace; it does not establish the
mkosi offline build boundary or a production builder.

A later [root-owned user-namespace probe](https://github.com/tamnys/ZECret-service/actions/runs/36333351728)
mapped UID/GID 0 to 0, isolated mount/network/PID namespaces, and let a nested
process create another mount/network namespace and mount `tmpfs` at `/tmp`.
The earlier attempt to mount over a runner-owned workspace scratch directory
failed; `/tmp` is the pinned mkosi sandbox's actual mount target. The workflow
still exits 1 because its original unprivileged user-namespace checks fail.
No mkosi sandbox, authenticated package installation, or complete image build
ran. This is a possible root-owned builder capability, not proof that the
offline build boundary or resulting artifact is safe.

A separate locked, offline build in the emulated `linux/amd64` managed
container produced five **unsigned candidate binaries** from repository commit
`5afdbe2`. They are ELF x86-64 inputs for later review, not a reproducible
image, boot evidence, or an approved release. The local, ignored output is
`.codex-tmp/gcp-guest-binaries-5afdbe2`; SHA-256 values are:

| Binary | SHA-256 |
| --- | --- |
| `zrpc-gcp-cookie` | `ece15c31e1c0fa123316b208b1d69a208f19aecf8cabf4c5191946248ded749f` |
| `zrpc-gcp-early-init` | `a91fec6ed83727ce76216824dca6de76d9ddf1ed9c0d827d168c6c1d497559a3` |
| `zrpc-gcp-guard` | `a1e5a09f61dcc097fc3556346bf41465482b226f1684407b4bf26f901c74fe25` |
| `zrpc-gcp-quote-broker` | `021c0f4844fb173c0b48a444d3c1323c42117b61ce9f3a875d0a7b1ac78990a5` |
| `zrpc-node-wrapper` | `5bd17278b188684cc43ec4a54e00f063f383bd619747e5f51eac4070c821f875` |

An escalated local recheck created a disposable 64 MiB case-sensitive APFS
image, but `hdiutil attach` still returned `Permission denied` at the
project-local mountpoint. `hdiutil info` and the mount table showed no attached
image; the image and empty mountpoint were removed. The case-sensitive staging
problem remains open independently of the x86 namespace problem.
