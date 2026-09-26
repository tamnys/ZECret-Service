# Google Cloud TDX implementation checkpoint

Date: 2026-09-26. This checkpoint adds the local GCP implementation while
retaining Phala. It is not a built appliance, a complete deployment package,
hardware acceptance, or approval for private queries. No cloud resource was
created, image uploaded, credential accessed, or scheduler activated.

## Implemented

- Explicit provider framing, GCP CCEL parsing/replay, independently supplied
  boot expectations, and provider-specific release manifests. The distributed
  approved-release catalog is empty.
- GCP evidence travels through the existing nonce-only TLS exchange. Only the
  retained connection can become a `VerifiedRpcSession`; hardware, workload,
  exporter, clock, collateral, lifetime, and packaged-release checks precede
  private-body input. Inspection cannot authorize a session.
- CLI and local dashboard default to `gcp-tdx`; explicit `phala-dstack` retains
  the Compose path. Numeric IPv4/IPv6 endpoints and remote-resolved hostnames
  use the configured loopback SOCKS proxy with fresh isolation credentials.
- Direct-process guest source profile, quote broker, startup guard, cookie
  handoff, rootfs audit, and offline candidate staging. See `gcp-guest.md` for
  the boundary between source configuration and actual boot enforcement.
- GCP deployment-package types, durable lifecycle journal, async operation
  recovery, export-only external watchdog, and operator commands. See
  `gcp-lifecycle.md` for the compiled live-creation blocker and billing gap.

## Verification

`bash scripts/check.sh --browser` passed in the managed untrusted browser
container. It ran 352 Rust unit tests, 27 Rust documentation tests, 18 existing
standalone runtime-guard tests, five GCP staging/rootfs tests, 26 existing Phala
source-profile tests, executable/CLI checks, both provider inspection paths,
and browser checks. The 12 GCP lifecycle tests use synthetic provider state.
The binary builds and verifier dependency/feature guard passed. No new package
version was added to Cargo.lock; the operator tool uses additional already
locked dependencies.

The shared target directory first produced stale-object permission errors.
Final verification used `CARGO_INCREMENTAL=0` and a fresh workspace target,
`/workspace/.codex-tmp/gcp-validation-target`; test harnesses now honor
`CARGO_TARGET_DIR`. These settings are verification environment choices, not
guest build evidence. Desktop and narrow GCP dashboard screenshots were
visually inspected; they show no private acceptance or transmitted query.
The documentation boundary scanner and `git diff --check` also passed.

The GCP endpoint harness additionally
passed socket/connect syscall tracing using the previously checksum-verified
Debian strace artifact: exactly one connection to its loopback SOCKS fixture,
no direct endpoint connection or local DNS request. This fixture checks routing
behavior; it neither runs Tor nor proves a SOCKS server is Tor.

The pinned mkosi 25.3 Python source parsed both the guest source configuration
and a staged synthetic candidate without errors. Parsing is not an image build.
Debian metadata hashes match the recorded
downloads, but the archive signatures and complete package closure remain
unverified. Both the browser container and supported untrusted amd64 default
profile lack mkosi, systemd-repart, ukify, gpgv, sbsign and veritysetup, and deny
user namespace creation. The amd64 preflight reports `architecture: x86_64`
and `status: blocked` (expected exit 1). Architecture support does not grant
the image-building capabilities. No host or privileged-container bypass was used.

All new hardware/boot evidence in tests is synthetic, historical, or an upstream
parser vector. No guest systemd boot, disk-retention/OOM experiment, live Zebra
sync, real TDX quote, production CCEL reconstruction, or effective guest
administration test was performed.

## Current provider and pricing inputs

Google's [supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)
still list `c3-standard-*` Intel TDX and require NVMe Balanced Persistent Disk.
Region, capacity, and disk size are deliberately not selected before resource
measurements. Recheck availability for the actual project and zone before any
deployment package is approved.

Public USD rates checked on this date are inputs only, not a configuration
quote or spending authorization:

| Component | Published rate | Source |
| --- | --- | --- |
| C3 TDX surcharge | $0.0033982 per vCPU-hour plus $0.0004555 per GiB-hour | [Confidential VM pricing](https://cloud.google.com/confidential-computing/confidential-vm/pricing) |
| Balanced Persistent Disk, displayed Iowa region | $0.000136986 per provisioned GiB-hour | [Disk pricing](https://cloud.google.com/compute/disks-image-pricing) |
| In-use standard-VM external IPv4 | $0.005 per hour before applicable free allowance | [Network pricing](https://cloud.google.com/vpc/network-pricing) |

The general-purpose compute price page could not be retrieved successfully in
this session. Base C3 compute, image/staging storage, operations, egress, taxes,
selected-region adjustments, and measured quantities still need a complete
current quote. No total or monetary ceiling is asserted. The 168-hour limit
comes from the approved experiment plan and includes synchronization.

## Remaining work before a hosted candidate

1. Establish an approved managed x86_64 image-building environment; authenticate
   and lock the Debian/tooling closure, target binaries, initramfs and signing
   inputs. The [Zebra 6.4.2 security release](https://github.com/ZcashFoundation/zebra/releases/tag/v6.4.2)
   was published September 25 and has not cleared the existing seven-day hold.
   Recheck its eligibility/advisories; do not use a vulnerable predecessor.
2. Build, sign and reproduce the actual disk/UKI; reconstruct firmware and boot
   expectations independently; validate all companion/mutable boot inputs.
   Exercise namespace/systemd, disk poison, canary, crash and OOM scenarios.
3. Resolve incarnation-safe Compute cleanup, validate the independent Linux
   controller and backstop, implement billing reconciliation, measure node fit,
   and freeze a complete resource quote/deployment package for spending approval.
4. After that separate approval, exercise the exact artifact on real TDX using
   synthetic inputs. Review the TLS-exporter construction and every hardware,
   boot, storage, administration, Tor and cleanup acceptance result before a
   native-client release can package an approved manifest.

No gate may be replaced with a diagnostic match, simulation result, provider
`verified` flag, or first-seen quote.
