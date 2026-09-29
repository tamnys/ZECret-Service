# Unsigned GCP guest boot observation, 2026-09-29

This is a synthetic, non-TDX diagnostic. It does not establish a signed image,
Secure Boot, real quote collection, release approval, or private-mode readiness.
No Google resource, signing key, or paid service was used.

The public x86-64 [GitHub Actions run](https://github.com/tamnys/ZECret-service/actions/runs/36532849789)
completed on source commit `d865e6d8da9a0f6964b5532bbafc5d024cbf60ca`.
It selected the successful exact-commit native Rust receipt from
[run 36519884896](https://github.com/tamnys/ZECret-service/actions/runs/36519884896),
attempt 1, artifact ZIP SHA-256
`3f6034e0dc513b5693fdd493c3519aaa86eebb9fb0547326e2be6f983420b1ac`.
The guest profile, early init, disk builder, and QEMU observer files did not
change between that commit and main at the time of this record.

The run built an **unsigned synthetic-service disk** in a no-route build
namespace. QEMU used one boot NVMe device, no guest network device, 2 GiB RAM,
and one vCPU. Its QMP report recorded an initial running state, a guest-initiated
`SHUTDOWN` event, and final `shutdown` state. The scheduled VGA frames show:

- The initrd used `/dev/mapper/root` as its verity-root device and switched to
  the real root. The Debian 13 systemd process then started.
- The guest attempted to start `zrpc-gcp-quote.service` and
  `zrpc-gcp-disk-trigger.service`. The quote broker failed; systemd reported
  dependency failures for `zrpc-wrapper.service` and `zrpc.target`, then
  powered off the guest. The wrapper did not start in these observed frames.

The QEMU setup does not provide Intel TDX ConfigFS quote hardware, so the
quote-broker failure is consistent with the intended fail-closed design. The
frames do not expose the broker's detailed error, and the observer cannot
authenticate the guest's printed text as a hardware measurement. The public
disk expected under `/dev/disk/by-id/google-zrpc-public-data` was also absent;
the trace does not isolate that independent startup dependency. The machine
report correctly retains `early_init_handoff_verified: false`,
`rootfs_ready_verified: false`, `boot_verified: false`,
`hardware_verified: false`, and `private_mode_approved: false`.

This result removes a question about how far the unsigned disk boots in
ordinary QEMU. It does not call for relaxing the quote dependency. A complete
service boot and hardware acceptance require the exact signed production
artifact on real TDX, the required public-data disk, and the remaining release
and lifecycle gates. The distributed approved-release catalog remains empty.
