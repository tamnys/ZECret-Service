# Public boot-support refresh — 2026-09-26

This source review found no supported production image/KMS tuple that resolves
the memory-only runtime or no-administration requirements. No account operation,
quote refresh, support message, image build or cloud cost was involved. Gates C/D
remain unresolved; an upstream source change is not account availability.

The inspected dstack `next` revision is
`635e7a2200bf267fe40cd6a4b7819531278f4060`. Its
[preparation script](https://github.com/Dstack-TEE/dstack/blob/635e7a2200bf267fe40cd6a4b7819531278f4060/os/common/rootfs/dstack-prepare.sh#L288)
still bind-mounts persistent Docker, containerd and Sysbox state before running
init scripts. It now also persists `containerd-stargz-grpc` and `nerdctl` roots.
Init extraction uses `mapfile` fed by a process substitution containing `jq`,
followed by sourcing another process substitution. Source inspection therefore
does not eliminate the previously reproduced extraction failure boundary. The
earlier v0.5.9 candidate patch and runtime-root list cannot be transplanted to this
revision and called complete.

The newer mkosi
[volatile overlay script](https://github.com/Dstack-TEE/dstack/blob/635e7a2200bf267fe40cd6a4b7819531278f4060/os/mkosi/mkosi.skeleton/usr/bin/dstack-volatile-binds.sh)
uses temporary writable layers over several `/var` directories. Its
[service](https://github.com/Dstack-TEE/dstack/blob/635e7a2200bf267fe40cd6a4b7819531278f4060/os/mkosi/mkosi.skeleton/usr/lib/systemd/system/dstack-volatile-binds.service)
is required by the local filesystem target. These are useful boot dependencies,
but preparation later places persistent mounts over runtime subdirectories.
That conclusion is an inference from the two source paths, not a guest boot test.

The inspected
[production recipe](https://github.com/Dstack-TEE/dstack/blob/635e7a2200bf267fe40cd6a4b7819531278f4060/os/mkosi/mkosi.profiles/prod/mkosi.conf)
removes getty generators/services, login tools and debug-shell components from
the root filesystem. This is relevant source evidence; it does not replace
exact-artifact inspection of rescue/emergency access, startup mutation and
privileged workload paths for the selected supported image.

The published
[0.6.0-rc5 OS release](https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.0-rc5)
is marked prerelease at commit `ad92cfeb4ab6960275498c31b66004b9bb1df068`. Its
guest/KMS protocol change requires matching rc5 components. It is not evidence
that the previously inspected Phala 0.5.9 catalog image and rc0 KMS can accept it.

The pinned Phala
[OpenAPI](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json)
filters available images using node availability, KMS allowlisting and production
compatibility. Public build instructions alone cannot establish that a custom
fixed image is accepted by the account's node/KMS selection. Local work may
continue on a clearly unapproved candidate and exact-image failure/restart tests;
selection for a hosted evaluation still requires supported-image/KMS evidence.
