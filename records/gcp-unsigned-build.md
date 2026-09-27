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

The [pinned mkosi sandbox probe](https://github.com/tamnys/ZECret-service/actions/runs/36334452473)
then passed on the standard public x86_64 runner. It checked Git commit
`54c625c380ef5500f17460981a3c67b109b6a847`, tree
`f5d828707aa0b1bd0235c55e13f7d4b41dba409e`, and exact archive SHA-256
`16a58d4aab33a8f28dc996dc4c816711686d1e58fa6af23131b8e84ff11917d0`
before execution. The runner copied only the byte-compared standalone
`sandbox.py` into a root-owned temporary directory: the preceding failed run
showed that `/home/runner` is not traversable by the UID 0-to-0 mapped child.
Inside a distinct user, mount, network, and PID namespace with no routes,
`python3 -I sandbox.py --ro-bind / / --unshare-net -- /usr/bin/true` exited 0.
This proves the pinned sandbox's narrow launch path on that runner, not a
complete mkosi image build, authenticated runnable toolchain, package-script
confinement, or a production offline boundary. No guest image, signing key,
cloud resource, cache, or uploaded artifact was involved; private mode remains
blocked.

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

## 2026-09-27 native x86 builder-payload staging

The manually dispatched [standard public runner
job](https://github.com/tamnys/ZECret-service/actions/runs/36335225880) completed
successfully on merged commit `ab5883fae577d742076c5a875a1102bef4127aa3`.
It used Ubuntu 24.04.5 on x86-64, fetched that exact repository commit, checked
the source-reviewed builder-closure lock at SHA-256
`0b5c02fabc0279c8e8e8712a62de8249089039c0e0af419a86cbcf8da72d1a4e`,
and fetched all 194 Debian archives with their locked size and SHA-256 checks.
The selected archives total 65,078,068 compressed bytes. The workflow did
not recheck the Debian InRelease signature on this runner; the signed snapshot
membership was established in the earlier local receipt, and the run's own
`signed_snapshot_rechecked` field is `false`.

The existing script-free stager completed on the runner's case-sensitive
workspace with `package_count: 194` and `entry_count: 8240`. Its generated
`.zrpc-builder-toolchain.json` SHA-256 was
`58d6b6121b4fb455d1ae613c4b5eb2a9d26bfdf036c639b911fe6c5ae63fd830`.
The job's final diagnostic reported `runtime_execution_verified: false`,
`complete_builder_toolchain: false`, `image_built: false`, and
`private_mode_approved: false`. The GitHub run lists zero uploaded artifacts.
No package maintainer script, staged executable, mkosi image build, signing
operation, or cloud API ran. This resolves the case-sensitive payload-staging
feasibility question on the free runner; it does not authenticate a runnable
builder closure or a production build environment.

## 2026-09-27 isolated staged-tool diagnostic and coreutils correction

The manually dispatched [chroot startup probe](https://github.com/tamnys/ZECret-service/actions/runs/36335785016)
ran on merged commit `d012a8965aa34b811c12f77fa35ee3c821905cfe` and exited 127.
It fetched and hash-checked the same 194 archives and reproduced the 8,240-entry
staging manifest above. In a distinct mount and network namespace with no IP
routes, the root-owned `chroot` dropped to the runner UID. The staged Python
UID check passed, the ELF loader listed staged systemd-repart dependencies, and
`mkosi --version` and `systemd-repart --version` printed 25.3 and 257.
`/usr/bin/ukify --version` then failed with `No such file or directory`. The
hash-checked `systemd-ukify` archive contains a regular executable at that
path, but its `#!/usr/bin/env python3` shebang needs `/usr/bin/env`; the original
194-package lock omitted `coreutils`, which supplies it. The run lists zero
uploaded artifacts and did not build or sign an image.

In the emulated AMD64 managed container, the pinned `gpgv` accepted the
September 18 Debian InRelease with the reviewed archive signer; its signed
`Packages.xz` lists `coreutils 9.7-3` with archive SHA-256
`1299ab6f9389a288eb2f5f3dd222c26cc777b9a2d5ecb6ee4cbd340cebcdada2`.
The hash-matched archive contains a regular executable `/usr/bin/env`.
Selecting `coreutils` as a direct tool-runtime seed in the pinned offline APT
simulation adds exactly that package: 195 selected, none removed or changed.
The updated direct-lock SHA-256 is
`26e36ea4af71b701e472e514e207392232bd0b8868c0ab141fc87ade89d59039`;
the updated closure-lock SHA-256 is
`d663fd006afa141c8e7686bd13a94dafe33cd055ee4e09ad1409ed311e1f6714`.
Both signed-index/direct-archive and offline APT-closure verifiers passed over
the 195 local hash-matched archives. Individual managed-container test suites
passed for direct packages (9), closure (7), fetch (7), and staging (5). A
combined wildcard test invocation instead segfaulted; its cause is unproven,
and no combined passing result is claimed.

The subsequent [merged-main diagnostic](https://github.com/tamnys/ZECret-service/actions/runs/36336741585)
succeeded on commit `2b170a1625dccf1ce6a5757d554b6b62c12bcd26`. Its full job log
reports 195 hash-checked archives, 8,601 staged entries, and staging-manifest
SHA-256 `5d3b8b1d4dc309db01810412ad702bbae6747d3c43d550b21ce1285ac5d8a923`.
The script checked distinct mount/network namespaces, only loopback link, no
IPv4 or IPv6 routes, and staged-command UID 1001. Through the chroot it ran
`mkosi --version` (25.3), `systemd-repart --version` (257.13-1~deb13u1), and
`ukify --version` (257.13-1~deb13u1); the loader also listed
`systemd-repart` objects from staged paths. The run exited successfully and
its GitHub artifact inventory contains zero uploads.

This proves only startup of those exact staged commands under the tested
isolation. The runner did not recheck the Debian signature
(`signed_snapshot_rechecked: false`), run package scripts, build or sign an
image, or verify later-loaded components and every mkosi helper. It did not
establish a complete runnable builder closure or change private-mode approval.
The release catalog remains empty.

## 2026-09-27 native signed-builder APT-plan diagnostic

The first [manual public-runner attempt](https://github.com/tamnys/ZECret-service/actions/runs/36338263152)
on `9c744e8` fetched the 195 hash-pinned archives and the exact Debian
InRelease and Packages index, then reached the signed APT loader inspection in
the networkless staged chroot. It exited 1 because the existing parser rejected
an unrecognized loader-report line. It did not report a matched APT plan or
change any release status.

The [refusal-only diagnostic rerun](https://github.com/tamnys/ZECret-service/actions/runs/36338601743)
on `96cb117` escaped the actual APT loader report into its error. It showed
one leading `linux-vdso.so.1 (0x...)` line, followed by the 16 sealed
`/proc/self/fd` library objects and the sealed `/proc/self/fd` interpreter.
There was no ambient disk-backed loader object. The vDSO is supplied by the
kernel, not by a signed Debian archive. That rerun also exited 1; the
temporary full-report error was removed after the format was identified.

The [corrected manual run](https://github.com/tamnys/ZECret-service/actions/runs/36338861781)
on `af7cb75` succeeded on the standard free `ubuntu-24.04` x86-64 runner.
It rechecked the signed September 18 Debian snapshot and the source-reviewed
APT plan for all 195 packages inside the no-route chroot. Its report lists
17 loader file objects from signed archives and
`apt_kernel_vdso: {observed: true, disk_authenticated: false}`; a single
leading vDSO is excluded from the disk-object count. The run also observed
staged-command UID 1001 and started mkosi 25.3, systemd-repart 257, and
ukify 257. The GitHub artifact inventory has zero uploads.

This remains a builder diagnostic. The report explicitly keeps
`apt_post_start_elf_loads_verified: false`,
`complete_builder_toolchain: false`, `image_built: false`, and
`private_mode_approved: false`. No package maintainer script, image build,
signing operation, cloud API, or private query ran. The verifier has not
authenticated every later-loaded helper or produced a reproducible guest
image; the approved-release catalog remains empty.
