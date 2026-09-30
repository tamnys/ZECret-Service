# Zebra v6.4.2 x86_64 local staging — 2026-09-30

This is an internal local-staging record, not image-build, deployment, or
private-mode acceptance. The default seven-day Zebra hold remains until
2026-10-02T19:59:10Z. The exact-asset exception permits only local staging
and Phala image-context preparation; GCP image execution and Phala
launch-document rendering retain their age gates.

The [official release](https://api.github.com/repos/ZcashFoundation/zebra/releases/tags/v6.4.2)
identifies release ID `396882484`, source commit
`e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291`, annotated tag object
`40bf166415fa8900f05df766f12ede91c2f7f4e5`, and Linux x86_64 archive
asset ID `589132406`. The downloaded official archive
`zebrad-6.4.2-x86_64-unknown-linux-gnu.tar.gz` was 67,178,756 bytes with
SHA-256 `505cab2c616dac1a5bc1c414716206a775f38f41ca6f70a60729df40c29e7b8b`.
Safe member inspection extracted the actual `zebrad` ELF as data, without
executing it: 89,613,680 bytes, SHA-256
`ccf1d3c82a1c23deb1dd535cfb442c5507107a16a23f6da2531be4132e95f517`.
These identities are pinned in `deploy/gcp/zebra-release.lock.json`.

The public [GitHub attestation API](https://api.github.com/repos/ZcashFoundation/zebra/attestations/sha256:505cab2c616dac1a5bc1c414716206a775f38f41ca6f70a60729df40c29e7b8b)
returned the signed bundle committed as `records/zebra-v642-attestation-bundle.json`
(10,824 bytes; SHA-256
`db9668a46cd12317f1623c54b787519ffd9e54c176dc823804eb5aedbb8fb000`).
The pinned GitHub CLI v2.100.0 Linux arm64 executable verified the exact
archive, repository, `zfnd-release-binaries.yml` signer workflow, source
commit, tag ref, and GitHub-hosted runner requirement. Verification returned
one matching attestation. The [official CLI release](https://api.github.com/repos/cli/cli/releases/tags/v2.100.0)
arm64 archive was 13,783,869 bytes with SHA-256
`ea4e7a581a32ccad6cc7923cb1576ac5859ba4b9a16ab22eb8f8a96e78e2e961`;
the extracted executable was 39,190,690 bytes with SHA-256
`28a037b967065aa314cb6d539943b55d27ef2f97c523ab2b6023ccf284e1828d`.
It ran from a sealed Linux memory file in the native arm64 managed container
and treated the Zebra x86_64 archive as opaque input. The CLI release was
checked against official metadata and digest, but its own provenance was
not independently verified. Linux amd64 CLI v2.101.0 and v2.100.0 did not
complete verification under managed x86_64 emulation.

The live published-advisory snapshot matched the 45 reviewed identities
and affected-package ranges pinned in the lock. The latest
[V6 advisory](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h5rr-8pqv-grp9)
lists 6.4.2 as patched. This checks direct upstream advisories, not the
full dependency graph or runtime behavior. A changed snapshot fails closed.

Local staging completed at 2026-09-30T02:06:26Z with committed receipt
`records/zebra-v642-local-staging-receipt.json` (SHA-256
`ad74233d1a88c047b5c67322164b9d60928d2373f683b045c90cdbcf706fa4b8`).
It binds the exact Zebra lock (SHA-256
`cf3f96dec3c0f1374813373e24008a8a3444e23656442905e929b51e52a65445`),
archive, ELF, verifier, one verified attestation, and the named local-only
exception. The Phala stock lock pins this exact receipt; a caller-written
receipt cannot authorize a held image context. The staging tool downloaded
no archive itself. No image was built or deployed, testnet sync was not
run, and private mode remains unapproved.
