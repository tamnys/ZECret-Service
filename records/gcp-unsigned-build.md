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
