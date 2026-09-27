# GCP verifier follow-up: unextended CCEL events

This local checkpoint adds a narrow format check. It does not approve a GCP
release, authenticate a production quote, or establish the guest boot policy.

The crypto-agile CCEL parser previously allowed a post-header `EV_NO_ACTION`
record with a nonzero digest. Replay correctly skipped that record, so the
reported RTMRs could still match while the log carried arbitrary digest bytes.
The [TCG PC Client Platform Firmware Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub-2.pdf)
requires all allocated-bank digests in such a record to be zero and says the
record is not extended. The [UEFI confidential-computing specification](https://uefi.org/specs/UEFI/2.11/38_Confidential_Computing.html)
uses the TCG event-log structure for CC firmware. The parser now rejects any
nonzero digest in every declared bank for post-header `EV_NO_ACTION` events.

The test constructs a matching replay with an appended advisory event, then
changes first its SHA-384 digest and then the SHA-256 digest in a two-bank log.
Both malformed variants are rejected. The zero-digest variants still parse and
replay, because real firmware can include advisory `EV_NO_ACTION` records.
Their descriptions are not authenticated by RTMR replay and must not be used
as a source of workload identity in future release review.

Managed-container validation: `cargo test --locked -p zrpc-verifier` passed
(33 unit tests and two compile-fail doctests), including the pinned Google
CCEL replay fixture. Source-only `rustfmt --edition 2024 --check` and
`git diff --check` passed for the verifier files. Workspace-wide formatting
was temporarily blocked by another agent's in-progress lifecycle edit; this
record does not claim the combined tree passed formatting.

The existing GCP review remains open: independently reconstruct firmware and
boot measurements from exact signed artifacts, validate event semantics and
mutable-input exclusions on the exact production guest, test real TDX quote
and CCEL behavior, and package a release only after those checks pass. The
distributed approved-release catalog remains empty.
