# Unsigned GCP disk reproducibility, 2026-09-29

The public native x86-64 [GitHub Actions run](https://github.com/tamnys/ZECret-service/actions/runs/36535766857)
built the synthetic-service disk twice from the same pinned source and signed
Debian package inputs at main commit `cce707c4fd54b86dbcde5e915c96d93e70919aee`.
Both builds ran in the diagnostic no-route builder. The comparison reported
byte-identical root partitions, whole disks, compressed initrd CPIOs, kernel
images, split initrds, and unsigned UKIs. Both raw disks were 854,786,048 bytes
with SHA-256 `288f561cd13d97d178c7dbe82a9923e49103d6d6665d854152f1268e226d9918`.
Both root partitions were 358,035,456 bytes. The report's
`first_changed_block_owners` was null because it found no differing root byte.

This proves reproducibility only for the selected unsigned fixture under that
runner's inputs and environment. The service executables were deliberately
unexecutable fixtures; there was no Zebra binary, signing operation, TDX boot,
cloud API, release approval, or private query. A production build must compare
the exact signed artifact and independently bind its source, certificate,
rootfs commitment, firmware policy, and measurements. The distributed approved
release catalog remains empty.
