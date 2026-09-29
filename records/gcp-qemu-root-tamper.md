# Unsigned GCP root-data tamper observation, 2026-09-29

This is a synthetic QEMU negative test, not a signed appliance or TDX
acceptance result. It used no Google Cloud resource, signing key, or paid
service. The distributed approved-release catalog remains empty.

The public [native Rust run](https://github.com/tamnys/ZECret-service/actions/runs/36540845021)
passed for source commit `42fb00fb4bde1e8068be3f6b62aaaf90ef406a31`
(attempt 1). The [unsigned disk and QEMU run](https://github.com/tamnys/ZECret-service/actions/runs/36541466751)
used that exact-commit artifact and the same source commit. Its observation
artifact, `gcp-unsigned-qemu-36541466751-1`, has ZIP SHA-256
`23bb66fc816b4cd3b22b67f45d326bb26092513022881da3897f4adb532417e1`;
the downloaded ZIP matched GitHub's reported digest.

The observer read the original diagnostic disk through a checked read-only
descriptor, copied it, changed one byte at disk offset 1,048,576 (the first
byte of the GPT root partition), and gave QEMU only the derived read-only
descriptor. It reported the source disk SHA-256 as
`0cf4d8379cae8609c5a17038c0fbd1f8e0b7ec90c6f1aced7950142246195458`
and the derived disk SHA-256 as
`e2a194455da810d761f898809b7dc99c70585bf7ef1c5173a0606c5ffd3a9a57`.
QEMU ran unprivileged in the isolated, no-route diagnostic environment with
2 GiB RAM, one vCPU, and no guest network device.

The 30-second VGA frame displays `device-mapper: verity: data block 0 is
corrupted` and repeated block-zero I/O errors. By the 110-second frame,
systemd had timed out waiting for `/dev/mapper/root` and reported failed
dependencies for `sysroot.mount` and `initrd-root-fs.target`. The captured
frames do not show a switch to the real root or the wrapper starting. QMP
recorded no guest shutdown event; the observer stopped at its explicit
120-second deadline. Thus the evidence supports refusal to mount this changed
root within the observed window, but does not prove that the guest shuts down
on root corruption or establish every startup-failure path.

The same run's full-disk log exercised the pinned `debugfs` inspector on the
built fixture and reported ext4 UUID
`6f61eae5-cae3-42b8-9943-58f173f575e3`, filesystem creation time
`Sat Sep 12 07:55:41 2026` in UTC, and directory hash seed
`d34f849c-e315-58a7-8472-c49396d8a373`. These are diagnostic filesystem
fields, not approved boot measurements.

The disk used unsigned UKI and synthetic service payloads. The report keeps
`boot_verified`, `hardware_verified`, `rootfs_ready_verified`, and
`private_mode_approved` false. Real signed-image boot, Secure Boot policy,
Zebra execution, TDX quote/CCEL binding, and all production release gates
remain untested by this run.
