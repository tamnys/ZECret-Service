# Internal record: Phala feasibility research

Checked: **2026-09-25**. Scope: official public documentation and upstream release records, read without cloud credentials or resource creation. This record distinguishes upstream statements from demonstrated behavior. **No live Gate A–E has passed.** No genuine quote, hardware test, authenticated resource quote or deployed deletion exercise was available.

## A — local platform and workload verification: unresolved

Phala describes local `dcap-qvl` verification as an alternative to its hosted verification API. Its guide's example comparison against a supplied event-log field does not, by itself, establish this project's independently approved workload policy. This is an assessment of the example, not a claim that its full platform cannot provide the necessary evidence. [Phala verification guide](https://docs.phala.com/phala-cloud/attestation/verification-guide).

dstack describes a TDX path using MRTD/RTMR0–2 for boot and RTMR3 replay for application identity. [dstack verification](https://raw.githubusercontent.com/Dstack-TEE/dstack/next/docs/verification.md). Its TDX guide explains the kernel command-line/rootfs commitment and application launch measurements. [TDX attestation guide](https://raw.githubusercontent.com/Dstack-TEE/dstack/next/docs/attestation-tdx.md).

Missing: exact production OS artifacts, reproducible expected boot measurements, image/configuration digest policy, authentic quote/collateral, local replay/appraisal results and adversarial vectors for that exact version tuple. Do not copy an upstream example's hash into the approved policy.

## B — freshness and live TLS-key ownership: unresolved

Phala documents passthrough routing to service-terminated TLS. Discover the hostname for the actual deployment; the documented region hostname is an example. [TLS passthrough](https://docs.phala.com/phala-cloud/networking/tls-passthrough).

Upstream explicitly warns that a container can request report data for a key it does not possess; its RA-TLS consumers also verify live key use. The same document leaves acceptable TCB status to downstream policy, and describes authenticated boot reconstruction plus RTMR3 replay. It also warns that persistent encrypted disks do not establish freshness or universal integrity. These are upstream descriptions on a **moving branch**, not project deployment evidence. [dstack security model](https://raw.githubusercontent.com/Dstack-TEE/dstack/next/docs/security/security-model.md).

Missing: reviewed binding bytes/vectors, approved code generating its own ephemeral key, fresh challenge verification against signed evidence, key possession on the same TLS connection, and rejection tests for substitutions, replay and reconnects. No bespoke binding is implemented in M0.

## C — no guest administrative access: unresolved

Phala distinguishes production `dstack-<version>` images without remote access from development `dstack-dev-<version>` images with SSH. This provider statement does not prove absence of all administrative plaintext paths in a selected deployment. [Debug application](https://docs.phala.com/phala-cloud/troubleshooting/debug-your-application).

Missing: measured production build/configuration selection; source/runtime evidence covering console, SSH, operator exec, startup mutation, privileged mounts and debug settings; negative access tests. Development images cannot satisfy the private policy.

## D — KMS and persistent storage: unresolved

Cloud KMS authorization is managed by Phala and can change; it is not provider-independent governance. [Cloud versus Onchain KMS](https://docs.phala.com/phala-cloud/key-management/cloud-vs-onchain-kms).

Missing: a source-to-runtime account of the selected KMS's key-release and boot rules, rootfs authentication, container-image verification, writable volume keys and executable/configuration paths. Test that policy changes or replaced/rolled-back disks cannot preserve an accepted identity while exposing current plaintext. Public chain-state persistence and ephemeral channel keys are project requirements, not proven upstream guarantees. If this invariant fails, the privacy claim is blocked.

## E — quoted resources, cost and lifecycle: unresolved

The pricing page, updated July 3, 2026, lists `tdx.large` at 4 vCPU/8 GB and $0.232/hour; storage is $0.000139/GB/hour. Tier 1 starts with an 80 GB per-CVM disk limit. Compute stops billing when stopped; storage continues until deletion. [Phala detailed pricing](https://cloud.phala.com/about/pricing).

For the design's 168-hour window and 80 GB disk:

| Component | USD |
| --- | ---: |
| Compute: 168 × 0.232 | 38.976 |
| Storage: 168 × 80 × 0.000139 | 1.86816 |
| Published-rate baseline | **40.84416** |
| Difference from $60 | 19.15584 |

This is arithmetic over public inputs, not a quote or spending authorization. Current checkout availability, fees/tax, bandwidth allowance/overage, account funding/preauthorization, accrued resources and any provider-enforced hard cap still require authenticated confirmation. Do not assume credits or auto-upgrade.

Zebra documents 16 GB recommended RAM, 4 GB minimum RAM and approximately 10 GB cached testnet state. Those figures do not prove that the 8 GB VM sustains this wrapper's workload without swap. [Zebra requirements](https://zebra.zfnd.org/user/requirements.html).

The source design supplies the $50 projected preflight ceiling, $45 deletion trigger, 168-hour deadline and approximately $60 total ceiling. An external watchdog and absolute deadline job, tested deletion including residual storage, and a manual backstop remain prerequisites. A fake-provider cleanup result cannot satisfy this live requirement.

## Upstream version observations, not an approved tuple

| Component | Public observation | Project use |
| --- | --- | --- |
| `dcap-qvl` | Release `v0.6.3`, August 31, 2026. [Release](https://github.com/Phala-Network/dcap-qvl/releases/tag/v0.6.3). | Candidate for later local quote verification; not integrated in M0. |
| dstack guest / KMS / verifier | `0.6.0-rc5` is a prerelease. Its release requires matching guest/KMS versions due a wire-format break. [Release](https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.0-rc5). | Reference only; neither production approval nor cloud availability established. |
| Rust TLS / dstack SDK | No end-to-end compatible production tuple selected. | Defer exact integration pins until compatibility is established; M0 does not add unused network/cryptographic dependencies. |

`dcap-qvl` supports offline collateral verification, but its convenient fetch path defaults to Phala PCCS. Future integration must keep that HTTP client disabled or contain every fetch within the approved Tor transport. [Official verifier repository](https://github.com/Phala-Network/dcap-qvl).

## Evidence needed to change this record

Attach exact immutable versions and artifacts, independent release-policy inputs, genuine signed evidence, local negative/positive test results, the authenticated resource quote and external deletion/deadline exercise. Update each gate individually. Documentation, provider dashboard badges and synthetic fixture success do not close a live gate.
