# GCP Zebra x86_64 artifact preflight — 2026-09-27

This is internal staging evidence, not a private-mode or image acceptance
record. The native GCP guest recipe still has no pinned `zebrad` ELF digest.

The reviewed metadata lock selects upstream Zebra `v6.4.2`, source commit
`e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291`, annotated tag object
`40bf166415fa8900f05df766f12ede91c2f7f4e5`, and the Linux x86_64
archive's GitHub asset ID, byte count and SHA-256. The [official release
metadata](https://api.github.com/repos/ZcashFoundation/zebra/releases/tags/v6.4.2),
[tag object](https://api.github.com/repos/ZcashFoundation/zebra/git/tags/40bf166415fa8900f05df766f12ede91c2f7f4e5),
and [SLSA attestation metadata](https://api.github.com/repos/ZcashFoundation/zebra/attestations/sha256:505cab2c616dac1a5bc1c414716206a775f38f41ca6f70a60729df40c29e7b8b)
were inspected. The latter's unverified statement names the pinned archive
digest and source commit; its certificate identifies the reusable
`zfnd-release-binaries.yml` workflow and a GitHub-hosted runner. The
[upstream workflow](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/.github/workflows/zfnd-release-binaries.yml)
uses GitHub's maintained attestation action in the build job and verifies
archives with `gh attestation verify` before release attachment. This metadata
inspection is not a cryptographic verification of the archive.

The current published-advisory API returned 42 entries. Their reviewed
identity, update times and affected-package ranges are committed as a
canonical digest in the lock; the script blocks if that live snapshot changes.
The latest [V6 advisory](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-h5rr-8pqv-grp9)
affects `>= 6.4.0, < 6.4.2` and lists 6.4.2 as patched. The other current
`zebrad` ranges end below 6.4.2; this is a direct-upstream-advisory check, not
a complete dependency or runtime vulnerability audit. No automatic trust update
is allowed when the snapshot changes.

The tool's explicit `preflight` command fetches only release, tag and advisory
JSON from GitHub. It uses the response server time and the asset's creation
time for the project's seven-day release hold. At 2026-09-27T20:53:28Z it
returned `held-metadata-only-unapproved` with earliest eligibility
2026-10-02T19:59:10Z; no Zebra archive bytes were fetched. Future `stage`
requires the archived asset already present locally, exact size/SHA-256,
an independently pinned Linux x86_64 `gh` executable, the upstream signer
workflow/source/ref checks, a safe archive shape and a reviewed ELF size/hash.
It emits a diagnostic receipt only.

The maintained verifier candidate is GitHub CLI `v2.101.0`, released
2026-09-15. Its official Linux amd64 tarball is 15,282,175 bytes with
SHA-256 `9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8`.
It was fetched inside the managed container after its age hold, hash-checked
against [official release metadata](https://api.github.com/repos/cli/cli/releases/tags/v2.101.0),
and the `bin/gh` member was inspected as a static x86_64 ELF with SHA-256
`ea857a3f0f7d4276cf5848b236542c5048e2eaa7bdd1b6ddec238f8793e74bff`.
The executable was not run or independently provenance-verified; the staged
copy is ignored local data, not committed. A final native-builder check must
exercise this exact verifier and its trust root. The release metadata lock
pins its provenance inputs and executable digest.

Five synthetic negative tests passed in the managed container. They exercise
the age boundary before local archive access, changed release/tag/advisory
identities, required `gh` verification flags and subject matching, and archive
member/architecture rejection. No test used the real Zebra archive or a real
attestation verification. The guest input lock, image build, testnet sync and
private approval remain blocked.
