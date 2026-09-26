# GCP guest integration evidence

This is an implementation record, not release approval. No Google resources,
images, signing keys, or cloud schedulers were created. The distributed approved
release catalog remains empty.

## Implemented local path

The Rust wrapper has an explicit `gcp-tdx` backend, retaining the original Phala
backend. Both use the same connection-owned TLS exporter and nonce-only public
attestation route. The GCP response carries the versioned raw quote and CCEL
format; it does not fabricate dstack Compose/KMS metadata.

`zrpc-gcp-quote-broker` publishes fixed Unix sockets as root with the measured
`zrpc-wrapper` service group. It additionally checks the peer UID from the kernel.
Its production ConfigFS and CCEL paths are fixed; no fixture filesystem, network
quote provider, or caller-selected path can be supplied. It checks the real
ConfigFS filesystem, requires `tdx_guest`, writes exactly 64 bytes, checks the
generation increment, and bounds quote/event-log reads and framing. The kernel
quote operation runs separately from the async liveness watch. A stalled or
failed operation stops the broker; systemd kills its process group on failure.

The API follows Linux's
[ConfigFS TSM ABI](https://github.com/torvalds/linux/blob/v6.12/Documentation/ABI/testing/configfs-tsm)
and Google's
[raw TDX quote retrieval](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance).
Neither the broker nor provider provenance establishes client acceptance.

The source guest profile runs Zebra and the wrapper under different UIDs.
Zebra's actual pinned candidate source creates its cookie with mode 0600 and
does not publish it atomically. A bounded startup handoff therefore reads it
through fd-relative `NOFOLLOW` opens, validates its owner, format and tmpfs
location, then creates a wrapper-owned memory-only copy. The timeout and polling
interval have no production defaults; staging requires measured configuration.
The wrapper's original owner-only cookie loader remains strict.

The immutable guard checks live mount and swap state before each main service.
A root precheck records each service's first start using exclusive creation;
a second unprivileged check runs inside the service's effective namespace.
Read-only root filesystem, tmpfs runtime storage, a single public ext4 node data
mount, disabled dumps, and restricted writable paths are required. The systemd
source profile has no runtime restart and powers off on failure or unexpected
successful service exit. Its effective boot behavior has not been exercised.

## Image tooling and source inputs

`deploy/gcp/guest` contains a Debian 13 direct-UKI source profile with ext4
dm-verity partition definitions. It disables Secure Boot auto-enrollment and
requires external signing input. No signing key is embedded or generated.

The selected mkosi parser source is upstream 25.3, commit
`54c625c380ef5500f17460981a3c67b109b6a847`; Debian stable carries package 25.3-7.
The downloaded upstream source archive matches SHA-256
`7b039fb3b34e1680173a7f4af1bc24b475465afe335c8b21c213167734061e35`, listed in
the retrieved Debian `.dsc`. The `.dsc` and InRelease signatures have not yet
been authenticated. Hash matching alone is not Debian archive authentication.
These metadata identities are recorded in `input-identities.json`; the file is
explicitly incomplete and non-deployable.

`tools/gcp-guest/prepare.py` provides local `preflight`, `inspect-inputs`, and
`stage` operations. It never executes package hooks, an image build, a signing
operation, cloud API, or scheduler. Staging checks a complete role/digest set,
ELF architecture, immutable snapshot syntax, package identities, and explicit
runtime inputs, then inventories files, modes, and symlink targets. Its output
remains `staged-unbuilt-unapproved`, including when synthetic inputs satisfy the
structural checks. It never writes quote measurements or a release approval.

The rootfs finalize audit rejects administrative binaries/services, unlocked
accounts, privileged executables, credential stores, and boot companions.
This does not establish exclusion of inputs consumed before the audit or before
the guest boots: the supplied initramfs, systemd-stub companion processing,
Secure Boot key configuration, CCEL semantics and actual boot remain release
gates. No source profile should be presented as a verified image.

## Build and acceptance blockers

The managed browser-profile preflight ran on aarch64 and found no mkosi,
systemd-repart, ukify or gpgv. `unshare --user --map-root-user true` returned
`Operation not permitted`; `/dev/loop-control` was absent. No host or privileged
container bypass was attempted. The supported untrusted amd64 default profile
was also checked: it reports x86_64, the same missing tools (including sbsign
and veritysetup), and denied user namespace creation. Its preflight correctly
returns blocked with exit 1; architecture alone cannot fix those capabilities.

The full authenticated Debian package closure and matching kernel, initramfs,
systemd tools, Secure Boot certificate and firmware policy remain unresolved.
The eligible Zebra artifact remains subject to the existing release-age,
checksum/provenance and advisory policy; the patched 6.4.2 candidate has not
cleared the previously documented hold. No older vulnerable release is selected
as a workaround.

Consequently there is no built raw disk, signed UKI, rootfs verity commitment,
measurement reconstruction, reproducibility result, real Zebra synchronization,
namespace/systemd boot result, or hardware acceptance evidence in this checkpoint.
Those are explicit remaining work, not successful simulated gates.

## Checkpoint verification

The hash-matched mkosi 25.3 source successfully parsed the source profile
with `python3 -m mkosi --directory=deploy/gcp/guest summary` (exit 0). It also
parsed a staged synthetic candidate. No image build was run. The final
managed-container full suite passed, including 56 server library tests,
two GCP guard tests, two node-wrapper option tests, two existing proxy tests,
and all five candidate staging/rootfs tests. The GCP tests exercise framing,
peer UID, cookie and namespace logic; they do not exercise a booted guest.
The shared target directory produced stale-object permission errors during
broader verification; the parent moved verification to a fresh target directory
on the managed workspace volume. These toolchain filesystem failures are not
guest-image or hardware evidence.
