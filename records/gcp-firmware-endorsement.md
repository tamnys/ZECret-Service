# Offline GCP firmware-reference checkpoint

This checkpoint adds a local diagnostic tool under `tools/gcp-endorsement`.
It does not approve a release, accept a private session, fetch cloud evidence,
or establish that the project's guest has booted on TDX hardware.

The tool accepts local Google OVMF firmware bytes and a local binary
`VMLaunchEndorsement`. It uses the embedded, SHA-256-pinned Google root
certificate to validate the signing certificate and RSA-PSS endorsement with
the maintained Google verifier. It requires the firmware's SHA-384 digest to
match the signed digest, reconstructs MRTD with the pinned Google TDX library,
and requires an unambiguous signed generic TDX measurement equal to that
reconstruction. Its JSON status ends in `_unapproved`, and
`private_mode_approved` is always false. It never reads a quote or derives
trust from first-seen measurements. The verifier call leaves `Getter` nil;
there is no runtime certificate, collateral, or endorsement fetch.

The pinned source is
[google/gce-tcb-verifier commit `022f7554a942ea49f1085256104df1de9c8b3e98`](https://github.com/google/gce-tcb-verifier/commit/022f7554a942ea49f1085256104df1de9c8b3e98),
resolved as Go module `v0.3.2-0.20260521164455-022f7554a942` through the
public checksum database. Google publishes the root at
[`GCE-cc-tcb-root_1.crt`](https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt);
the committed DER SHA-256 is
`e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c`.
Google's [firmware verification guidance](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware)
defines the signature and TDX MRTD comparison. This root pin is a reviewed
source input, not evidence of any particular production firmware release.

Go 1.27.1 was downloaded only inside the managed container from the official
release URL and checked against the SHA-256 in `toolchain.json`. The Go module
graph is exact in `go.mod` and `go.sum`, with `GOTOOLCHAIN=local`. The pinned
Google library's older transitive `golang.org/x/crypto` was advanced to
`v0.56.0`, published September 2, 2026; its needed `x/sys` moved to
`v0.47.0`, published June 30. Both clear the existing seven-day release hold.

Managed-container checks passed: `go test -mod=readonly ./...` and
`go vet -mod=readonly ./...`. Tests include an upstream synthetic fake-OVMF
MRTD vector and locally generated signing certificates; they reject changed
firmware, signature, root, certificate expiry, wrong/ambiguous signed MRTD,
missing generic measurement, and non-TDX endorsements. No production Google
endorsement or firmware was used. `govulncheck@v1.1.4 -scan=package ./...`
reported zero affected imported packages. Module-only scanning still reports
`GO-2026-5932` for unmaintained `x/crypto/openpgp`; neither it nor SSH is in
the tool's imported package graph. The same govulncheck version's symbol
scan panicked in its older `x/tools` SSA builder under Go 1.27.1, so this
record does not claim a completed symbol-level scan or a zero-module audit.

Remaining release work includes obtaining and independently reviewing an
actual Google-signed endorsement and exact OVMF binary before any quote is
examined, checking launch options for the selected C3 shape, reconstructing
RTMR0-3 from the built UKI and boot inputs, authenticating the complete image,
and performing real TDX hardware acceptance. A diagnostic MRTD agreement
alone cannot set `firmware_endorsement_provenance` or release approval to
`verified` in the native client.
