# dstack 0.6.0 runtime persistence — source-only review, 2026-09-30

This asks whether the newly listed production `dstack-0.6.0` image removes
the runtime-on-disk barrier to genuine private RPC. It inspects public upstream
source and a small release hash manifest only. It is not an inspection of
Phala's installed image, a boot test, an attestation result, or approval to
move this project from the pinned 0.5.9 public preview.

At 14:56 UTC, Phala's unauthenticated [KMS info](https://cloud-api.phala.com/api/v1/kms/kms_opjg1KBD/info)
listed `dstack-0.6.0` for `prod9`, but gave only its name, version and
`is_dev: false`; it did not provide the catalog OS digest. The upstream
[`mkosi-os-v0.6.0` release](https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.0)
is dated September 28. Its tag resolves to source commit
`4699c48ea3a7e568dff4f8792421299f27d50758`. The release's
`image-hashes.txt` was downloaded and its SHA-256
`8e9c6d045d8fbce97feb89d31498f28b498f1211a1facd5eb0ac57947c310525`
matched the GitHub release asset metadata. It reports upstream
`os_image_hash` `8409e2a24ea8325f3ea45d7c50622c952a8a4a961ffc139f5d9a81c4e47bd744`.
The public response provided no Phala catalog digest to match against that
value. The full 616,751,881-byte OS archive was not downloaded or executed,
and its rootfs commitment was not reconstructed.

At that source commit, the mkosi guest's
[`var-volatile.mount`](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/os/mkosi/mkosi.skeleton/usr/lib/systemd/system/var-volatile.mount)
mounts tmpfs at `/var/volatile`, and
[`dstack-volatile-binds.sh`](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/os/mkosi/mkosi.skeleton/usr/bin/dstack-volatile-binds.sh)
uses it for writable `/var` overlays before local filesystems finish. That
early memory backing does **not** leave the container runtime in memory:
[`dstack-prepare.sh`, lines 286–304](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/os/common/rootfs/dstack-prepare.sh#L286-L304)
mounts the persistent data disk and then recursively binds its
`var/lib/docker`, `var/lib/containerd`, `var/lib/containerd-stargz-grpc`,
`var/lib/nerdctl` and `var/lib/sysbox` subdirectories over the runtime roots.
It also exposes the preparation work directory at `/dstack`. The five named
runtime bindings are explicit persistence paths in the source, even though
the underlying `/var/lib` overlay began on tmpfs.

The same script processes `init_script` only **after** those binds
([lines 312–334](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/os/common/rootfs/dstack-prepare.sh#L312-L334)).
Upstream's [security guidance at that commit](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/docs/security/security-best-practices.md#L65-L85)
places `init_script` before dockerd and `pre_launch_script` after dockerd;
Docker can restore old containers before the latter. The image's
[`docker.service` drop-in](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/os/common/rootfs/docker.service.d/dstack-prepare.conf)
orders preparation with `Wants=` and `After=`, while
[`app-compose.service`](https://github.com/Dstack-TEE/dstack/blob/4699c48ea3a7e568dff4f8792421299f27d50758/os/common/rootfs/app-compose.service)
uses `Requires=`. This static reading does not prove effective failure
behavior, restart isolation, administrative access, KMS authorization, or
the actual Phala boot order.

The source therefore does not remove the project's memory-only runtime gate.
If Phala offers this exact image for a later reviewed release, the corrected
guest must account for all five persistent runtime bindings before daemon
startup, plus the other write and administration paths. No first-seen quote,
public version string, release hash, or provider `verified` field may approve
the workload. The existing stock 0.5.9 path remains a public,
unverified-for-private-use preview; a custom-image/KMS admission decision and
exact-artifact hardware tests remain necessary for genuine private mode.
