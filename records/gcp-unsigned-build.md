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
