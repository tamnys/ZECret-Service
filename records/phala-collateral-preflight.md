# Phala collateral fetcher local preflight — 2026-09-30

This is an internal, local readiness record for the separate
`deploy/phala/collateral-fetcher` operator tool. It is not a live attestation,
private-mode approval, or deployment authorization. No quote was submitted to
Phala's PCCS, no Phala resource was created, and no account credit was spent.

In the managed untrusted ARM64 Linux container, the committed Cargo lock
(`SHA-256 6b6b7c356f67b3acd825f249b42b4cd6e720e8f20e8cb0e2abb244000258f065`)
passed `cargo test --locked --manifest-path
deploy/phala/collateral-fetcher/Cargo.toml` (one offline argument-boundary test)
and `cargo build --locked --manifest-path
deploy/phala/collateral-fetcher/Cargo.toml`. The resulting debug binary is a
Linux AArch64 ELF with SHA-256
`6317085b1f78c42454cbbdf03018d1371a5668c6184a97558c0c0017e1bf1e9f`.
Its generated build tree is retained only in ignored workspace scratch at
`.codex-tmp/collateral-fetcher-target-20260930`; the review worktree is clean.
This tool runs on the local operator machine, not in the x86_64 Phala guest.

At the readback, GitHub's repository dependency SBOM was created at
`2026-09-30T05:55:12Z` (download SHA-256
`f32f6dc1c0adb17ccd07d35fe0ff58544ae6cdaa6c10bce5db077d7f80b10f3a`).
After decoding package-URL version escapes, all **274** exact crates.io
name/version pairs in this lock appeared in that SBOM. The lock had no diff
from `origin/main`. GitHub's vulnerability-alerts endpoint returned 204
(enabled), and its Dependabot alert endpoint returned zero open and zero
dismissed alerts. This establishes the observed GitHub advisory state for the
covered dependency set; it does not prove that no vulnerability exists.

A direct OSV batch query from the managed container timed out before returning
any advisory result. That source remains unverified. No live PCCS response,
collateral serialization, or end-to-end quote verification was exercised in
this preflight. Recheck current advisories and run the tool on an actual quote
only after a separately approved CVM exists; the native verifier must still
independently validate the returned collateral and quote.
