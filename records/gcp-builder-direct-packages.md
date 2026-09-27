# GCP guest builder direct-package checkpoint, 2026-09-27 UTC

This is an internal local-input receipt, not a complete or runnable image
builder. No package was installed, no package script ran, no signing key was
used, no image was built, and no cloud resource was created.

`deploy/gcp/builder-direct-packages.lock.json` pins 15 candidate Debian
13 `amd64`/`all` package archives at the same `20260918T000000Z` snapshot as
the guest lock. Its SHA-256 is
`9e6d797bc4ae9ca3e1431105ffc55da137c8e3ccf9b922201d72958db657a023`.
`tools/gcp-guest/verify_builder_packages.py` checks the reviewed InRelease
digest, the Debian 13 archive signature through the existing pinned-key and
pinned-`gpgv` path, the signed Packages.xz size and digest, each exact package
record, and each local content-addressed archive's size and SHA-256. It reads
the archives without installing them. It seals the exact InRelease bytes in a
Linux memfd for both `gpgv` and Release-field parsing, then parses the exact
Packages.xz bytes whose signed digest matched. The existing guest-package and
mkosi-source snapshot checkers now share that same byte-snapshot rule. The
index is read from one no-follow file descriptor with a bound from its signed
Release size; the current reviewed InRelease and index sizes also bound memory
use (140,421 and 10,540,436 bytes respectively). The snapshot has passed the
existing seven-day hold.

The managed untrusted `linux/amd64` container fetched those exact snapshot
URLs and checked each response against the signed-index hash before saving it
under ignored `.codex-tmp/builder-direct/debs`. Running the verifier against
those local files exited 0 and reported
`direct-builder-archives-matched-signed-snapshot`, `package_count: 15`,
`complete_builder_toolchain: false`, `image_built: false`, and
`private_mode_approved: false`. The signed InRelease SHA-256 was
`0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675`;
the signed Packages.xz SHA-256 was
`7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498`.
Nine synthetic negative/positive tests passed, including source replacement
between signature/hash checks and parsing and oversized local metadata. Their
signature check was mocked;
the separate local-input invocation above used the pinned `gpgv` executable.

Read-only `dpkg-deb --contents` inspection found the selected package-to-file
mapping: `mkosi` in `mkosi`; `systemd-repart` in `systemd-repart`; `ukify` in
`systemd-ukify`; `linuxx64.efi.stub` in `systemd-boot-efi`; `bootctl` in
`systemd-boot-tools`; `sbsign` and `sbverify` in `sbsigntool`; `veritysetup`
in `cryptsetup-bin`; `gpgv` in `gpgv`; `apt-get` in `apt`; `dpkg-deb` in
`dpkg`; `mount` and `umount` in `mount`; `unshare` in `util-linux`; and the
named `tar`, `gzip`, and `zstd` tools in their respective packages. This file
listing is corroborating inspection with the managed container's `dpkg-deb`,
not an independent executable or runtime-dependency verification.

The pinned mkosi 25.3 source also invokes APT and `dpkg-deb` for Debian
bootstrap, `systemd-repart` for disk images, `ukify` for the UKI, and `zstd`
for configured compression. The selected signing path requires `sbsign` or
`systemd-sbsign` once an external signing key and reviewed invocation exist.
The project's preflight additionally probes actual isolated mount/unmount and
requires `veritysetup`. The import archive uses GNU tar/gzip. These observed
paths do not enumerate all conditional mkosi subprocesses. An actual traced
build of the exact profile is needed to finish that inventory.

This checkpoint does not close mkosi's own Debian `Depends`, including Python
and its modules, `systemd-container`, `e2fsprogs`, `dosfstools`, `mtools`,
`cpio`, `kmod`, and their transitive libraries. It does not authenticate the
installed executable paths, dynamic loader or shared libraries, package
scripts, Python module load path, selected mkosi Debian packaging contents,
or the final build environment. The pinned `gpgv` executable's dynamic library
closure remains unreviewed. Those omissions, the unavailable namespace-capable
builder, exact Zebra input, signing setup, final-disk inspection, and real TDX
measurements keep image and private-mode acceptance blocked.
