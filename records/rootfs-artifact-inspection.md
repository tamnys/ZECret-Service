# Exact-image rootfs evidence

Internal verification record; executed 2026-09-25. Independent userspace verity verification and all ten selected source-to-artifact comparisons passed. The probe is not an approved image, an administrative-access proof, a runtime barrier, or a private-mode acceptance path. No guest, service, VM or cloud operation was started.

## Fixed inputs

The public [v0.5.9 archive](https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.9/dstack-0.5.9.tar.gz) has SHA-256 `f3888f64e215bc1e1af53a1f3d13b4df48fe40d4a3059049bb87d4c7c06aff97`, as reported by [release asset 401364871](https://api.github.com/repos/Dstack-TEE/meta-dstack/releases/assets/401364871). The previously verified component-manifest digest matches the account catalog: `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033`.

Metadata pins meta-dstack `e3655d1390feee3736476f4bda35c4354b4a12fc`, whose dstack gitlink is `282eeb27d22d8f091ad0fa5a90e638f85cf68751`. The observed rootfs commitment is `a2d0a2af747ac763d56745f81d6aba93c04112076a6c502a3a5e2b45dd8b7c96`, with hash-area offset `156594176`. These values identify the artifact; they are not newly approved attestation measurements.

The archived initramfs `init` was read without executing it and matches the [pinned source](https://github.com/Dstack-TEE/meta-dstack/blob/e3655d1390feee3736476f4bda35c4354b4a12fc/meta-dstack/recipes-core/images/dstack-initscript/init) at SHA-256 `ba4958aabc898aba9ee79931d63cdd9fc3381c1e8acbcf62429c515f50578366`. The [pinned verity recipe](https://github.com/Dstack-TEE/meta-security/blob/bc63d95746ef4f0ac6820165e5041d83647e8c9c/classes/dm-verity-img.bbclass) uses 1024-byte data blocks, 4096-byte hash blocks, and a reproducible salt/UUID. A raw header inspection matches those parameters; this is distinct from verifying every data block.

## Probe and execution boundary

`records/probes/inspect-v059-rootfs.py` requires explicit native `veritysetup` and `unsquashfs` paths and a new output directory inside this workspace. Verify the tool packages and required libraries independently before invocation. It performs no download or installation and does not certify tool provenance from a binary hash alone.

The probe hashes the archive before copying any member, rechecks the component manifest/catalog identity and metadata, and copies only the fixed regular `rootfs.img.verity` member. It invokes maintained `veritysetup dump` and `verify` against a regular file, then `unsquashfs -lls` and selective `-cat` reads. It never mounts the image, extracts its directory tree, executes guest binaries, or starts systemd. [Verity verification is a userspace operation](https://manpages.debian.org/trixie/cryptsetup-bin/veritysetup.8.en.html#VERIFY); [unsquashfs supports listing and individual file reads](https://manpages.debian.org/trixie/squashfs-tools/unsquashfs.1.en.html).

Run through the existing managed shell, substituting the independently verified absolute tool paths and a fresh output name:

```sh
LD_LIBRARY_PATH=/workspace/.codex-tmp/apt/tools/usr/lib/aarch64-linux-gnu \
python3 records/probes/inspect-v059-rootfs.py \
  .codex-tmp/phala-artifacts/dstack-0.5.9.tar.gz \
  --veritysetup /workspace/.codex-tmp/apt/tools/usr/sbin/veritysetup \
  --unsquashfs /workspace/.codex-tmp/apt/tools/usr/bin/unsquashfs \
  --output .codex-tmp/rootfs-inspection
```

If verified extracted libraries are needed, supply their directory in `LD_LIBRARY_PATH` for this invocation. The probe discards other ambient loader/startup settings when invoking tools. Its structured stdout and `report.json` omit host paths, raw password fields and raw tool diagnostics. A failing tool is identified by stage and exit status. Failed output remains available for inspection; a rerun requires a new output directory.

The report compares ten script/unit/configuration files with their immutable source hashes, includes literal unit directives and enabled-path symlinks, and records relevant administration, generator, storage configuration and account-lock observations. It does not execute systemd or resolve the dynamic unit graph. Filename absence alone cannot establish absence of guest administration. Every report contains `private_accepted: false`.

## Results

The managed-shell execution used native arm64 packages checked against signed Debian trixie metadata at snapshot `20260918T000000Z`. Only the selected checksum-verified package data was extracted with `dpkg-deb -x`; no package installation or maintainer hook ran.

| Package | Exact version | Package SHA-256 |
| --- | --- | --- |
| `cryptsetup-bin` | `2:2.7.5-2` | `94b6bf78404b2e7d2329935960041b5306ef6adad53a3271b7a7ac9d33776c23` |
| `squashfs-tools` | `1:4.6.1-1+b1` | `c074f409b735b80ca5dbbf415436aef49a162e2daf148de007ffceabf0332304` |
| `libcryptsetup12` | `2:2.7.5-2` | `c09ef97b4ec26101b0812f32ce27c697ee2d88bf44b018a541c3afbf282ee56a` |
| `libdevmapper1.02.1` | `2:1.02.205-2` | `4d783b235eb9857ec96fabd0f161a84426706d079ec82ef5a91cbbf9dd644904` |

The stdout receipt `.codex-tmp/rootfs-inspection-result.json` and `.codex-tmp/rootfs-inspection/report.json` are identical, with SHA-256 `09401fecd54339c3b5dcca4debfa7e2abc4c4f69130f3d16ef2bc6d43e3562a8`. Their status is `offline_evidence_collected`, stage `complete`. Archive identity, dm-verity verification and all ten pinned source comparisons are true; the listing contains 2316 entries. The extracted rootfs file SHA-256 is `e92ad3aeae158f08706f634509f756d6d838c81dd08eded68cc4aab041fe7fd8`; this ordinary file digest is supplementary evidence, not the verity root hash.

The maintained verifier read hash type 1, SHA-256, 152924 data blocks of 1024 bytes and 1206 hash blocks of 4096 bytes. Its salt and UUID match the pinned format recipe. Thus the rootfs bytes pass verification against the commitment in the catalog-matched metadata; no measured boot or guest execution was performed.

The ten matching files are the preparation script; preparation, guest-agent and app-compose units; Docker/containerd preparation drop-ins; all three Sysbox units; and Docker's `daemon.json`. Their complete expected and actual digests and immutable source URLs are in the receipt. This confirms that the stock persistent-runtime mounts and previously reproduced unchecked hook invocation are present in this exact artifact.

### Observed service and configuration boundaries

- The enabled links include preparation, guest agent, app-compose, Docker, containerd and Sysbox under `multi-user.target`; Docker and guest-agent sockets under `sockets.target`; and the Sysbox manager/filesystem services under `sysbox.service`.
- Docker/containerd preparation drop-ins specify `Wants` and `After`. Preparation retains `RemainAfterExit=yes`, `OnFailure=reboot.target` and `FailureAction=reboot`. Docker's additional `ExecStartPre` waits for the guest-agent service and its two sockets; it does not check runtime storage. Docker and containerd both use `KillMode=process` and `Restart=always`. These literal directives do not establish an execution race or a fail-closed runtime guard.
- Docker listens on `/run/docker.sock` with mode `0660`, user `root`, group `docker`. The guest-agent service runs as root using `/dstack/agent.json`; its socket unit declares `/run/dstack.sock` and `/run/tappd.sock` with mode `0777`. Socket presence and permissions alone establish neither an exec API nor remote reachability.
- Sysbox manager uses `/var/lib/sysbox` as its data root. App-compose is ordered after Docker, preparation and the guest agent, works in `/dstack`, and references `/dstack/.host-shared/.decrypted-env` as an optional environment file. The selected image has no `etc/containerd/config.toml` or `etc/zfs/zpool.cache`; `etc/fstab` exists and was hashed, but its contents are not interpreted by this probe.
- ZFS target, cache-import, mount, share and event-daemon links are present. The scan-import unit exists without a corresponding enabled link in the recorded inventory. Both import units use `-N`; the separately reviewed preparation utility's ZFS import path remains a different boundary. The image includes ZFS, GPT, fstab, debug and run generators. This static inventory does not determine their runtime inputs, generated units, or the final boot graph.

### Observed administrative paths

The selected name checks found no `sshd` or `dropbear` executable, SSH unit, `sshd_config`, or `debug-shell.service`. They do find `systemd-debug-generator`, `systemd-sulogin-shell`, a `sulogin` symlink, and rescue/emergency services and targets. Both services invoke `systemd-sulogin-shell`. A `multi-user.target.wants/getty.target` link remains, while its target unit is absent from the recorded inventory.

The only UID-zero account is `root`, with shell `/bin/sh`; its shadow password field is classified as locked. `etc/securetty` is empty. No password field was emitted. These observations are not a demonstration that rescue/console paths, boot arguments, guest APIs or approved workload configuration cannot confer administrative access. Gate C remains unresolved.

All receipts retain `guest_admin_absence_demonstrated`, `runtime_guard_demonstrated`, `build_reproduced`, `live_attestation_verified` and `private_accepted` as false. Three negative execution checks passed in the managed shell: a synthetic wrong archive fails before creating output; an existing evidence directory is refused and its report hash stays unchanged; and a nonzero verifier result fails at the verity stage after archive identification. All failures retain false verity/private acceptance. The exact probe also passes Python syntax compilation.

## Remaining proof

The stock preparation hook issue remains despite successful artifact verification. A candidate barrier must precede every Docker, containerd, Sysbox and app startup path and check actual memory-backed runtime mounts and absence of swap on each start. A stored marker or retained oneshot state is insufficient. Exact-image boot and failure tests must observe runtime execution through preparation failures, socket activation, restarts and poisoned persistent storage. No artifact inspection here closes those dynamic, workload, KMS or live-attestation gates, approves an image, or authorizes deployment.
