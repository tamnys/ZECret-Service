# Phala public Testnet preview operator packet — incomplete, 2026-09-30

This collects the presently reviewable inputs for a **public, unverified-for-private-use** TDX-hosted demo. It is not a deployment instruction or spending request. A public application image has been published, but no Phala resource was created, deletion scheduler activated, or Phala credit used. The distributed approved-release list remains empty; the stock Phala image does not meet the genuine private-mode disk and administration policy.

The operator subsequently [authorized deployment within the existing budget
and cleanup limits](phala-operator-authorization-2026-09-30.md). That
authorization does not by itself close the readiness gaps below or establish
that any billable action has occurred.

## Pinned local inputs

| Input | Reviewed identity and evidence |
| --- | --- |
| Candidate stock guest | `dstack-0.5.9-bd369a8c`, catalog OS digest `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033`; observed on account node `prod9` on September 25 in [account preflight](phala-account-preflight.md). Current availability and effective image selection require fresh readback. |
| Candidate KMS | Catalog ID `kms_opjg1KBD`, name `phala-prod9`, reported version `v0.6.0-rc0 (git:cb4c3736c5f9323440a3)` at that observation. The effective production authorization policy is unknown. |
| Base application image | Official Linux amd64 `python:3.13.15-slim-trixie` manifest `sha256:37134a49d21d2120e4c4d73bb76f8a4ab9aef31f096f7ec2ead48c2feead4332`. |
| Zebra | v6.4.2 x86_64 archive SHA-256 `505cab2c616dac1a5bc1c414716206a775f38f41ca6f70a60729df40c29e7b8b`; ELF SHA-256 `ccf1d3c82a1c23deb1dd535cfb442c5507107a16a23f6da2531be4132e95f517`. [Staging evidence](zebra-x86-asset-preflight.md) verifies the upstream signed attestation; the operator explicitly allowed the local hold exception. |
| Public Testnet snapshot | Unsigned archive, 11,137,971,554 bytes, SHA-256 `e1702bb220a337f94496e1f65b683b63f22334fdc500c5421dd118e593358636`; the operator accepted this for the public preview. [Lock](../deploy/phala/snapshot.lock.json) and [full archive scan](phala-snapshot-size-verification.md). |
| Native Rust image inputs | [Matched native build](https://github.com/tamnys/ZECret-service/actions/runs/36721090690) at source `f0c8709e073575296a17925851589f7c3a81337b`, artifact ID `11101841679`, artifact digest `sha256:650af5e939480aa8b997561e453368fd8f7301c45c3e9b094b3b3dcbb8f55cbd`; `zrpc-node-wrapper` SHA-256 `65dfeb3c43c403e71e4c4e635ee78decf73661bdf4fb020fa417905145fe4762`; `zrpc-quote-proxy` SHA-256 `6e0a33f7a2aeadb3102c7af89135f0a5e13dea09641c6a86c65727f635308186`. The local tar checksum and both binary hashes were checked against the matched-build manifest. The current image-context SHA-256 is `f9144a533c9ad5d8b943b241b8b912ab0ccde14648137643b3dc5194d70389ff`. |
| Local image and publication checks | The [native x86_64 image smoke and explicit publication](https://github.com/tamnys/ZECret-service/actions/runs/36740557921) passed at source `dbc233f7b26f92f4a533fa68a923cfbc013211bd`. Two Docker archives matched SHA-256 `026c4dc1d3756079a7ebeaff4e4cb28ac5cdb25d59f10fe3cc064e85370909de` and image config ID `sha256:db5640e760fc8c69acf2fe1637f71b56100469fc58e437fc68646f2679dfaed2`. It checked quote-backend mount isolation, synthetic quote exchange, cold Zebra public RPC on retained TLS, write-method refusal, and existing-session closure after quote loss. The workflow checked both identities again before pushing; GitHub's package API reports one public repository-linked version, `ghcr.io/tamnys/zecret-service-preview@sha256:780e8e60c812ccc7946dd346bc2b52b4ef4b61c225298063fa1f30b153b87c58`, and the workflow read its manifest anonymously with the expected config ID. These tests skip quote and certificate verification and do not boot Phala or attest TDX. |

## Public catalog recheck — 2026-09-30 14:56 UTC

Unauthenticated, read-only [KMS info](https://cloud-api.phala.com/api/v1/kms/kms_opjg1KBD/info)
still associated `kms_opjg1KBD` with `phala-prod9` and `prod9`. It reported
KMS database/RPC version `v0.6.0 (git:4699c48ea3a7e568dff4)`, with
`version_synced: true` and `is_dev: false`, and teepod database/real version
`v0.6.0 (git:96583b6d6a5116c86be9)`. It still listed
`dstack-0.5.9-bd369a8c` with `is_dev: false`. This differs from the
September 25 KMS version recorded in the pinned stock-candidate lock. The
public response supplies neither that OS image's full digest nor the effective
KMS disk-key authorization policy; it is provider metadata, not independent
attestation.

The public [node list](https://cloud-api.phala.com/api/v1/attestations/nodes)
still listed `prod9` in `US-WEST-1`, with no reported status. The public
[instance catalog](https://cloud-api.phala.com/api/v1/instance-types) still
reported `tdx.large` as 4 vCPU/8192 MB at `$0.232000/hour` and `tdx.xlarge`
as 8 vCPU/16384 MB at `$0.464000/hour`. These GET responses do not establish
current account capacity, credit balance, complete storage/fee terms, or the
configuration Phala would actually launch. The September 25 lock remains a
dated, unapproved observation; do not silently replace its values or treat this
public recheck as the required signed-in quote.

## Signed-in form recheck — 2026-09-30

After the operator authorized deployment, a read-only signed-in Chrome check
found an empty Compute inventory and no CVM usage this month. The account's
credits are shared with other Phala services, including model usage, so the
balance is not a budget-control substitute. Compute is prepaid with auto-topup
off. The unsubmitted deployment form offered `prod9`, displayed
`dstack-0.5.9` and Phala KMS, and reported eight available Large TDX instances
(4 vCPU, 8 GB) at `$0.232/hour`. With 80 GB entered and ext4 selected, it
displayed `$0.242959/hour` total and `$177.36` monthly, equivalent to
`$40.817112` for 168 hours before any unshown fees or billing rounding. The
form was not submitted; these are transient UI observations, not a price lock,
image digest, capacity reservation or final cost ceiling. The form's default
gateway says it terminates TLS; the exact production TLS-passthrough route
still needs confirmation and a live test. The form exposed no explicit swap
setting, and its short OS label did not establish the catalog digest.

The newly listed upstream `dstack-0.6.0` source was also [reviewed for runtime
persistence](phala-v060-runtime-source-review.md). Its early memory-backed
`/var` is followed by persistent binds for five container-runtime roots, so
that source does not resolve the genuine private-mode disk gate. The public
KMS response supplied no full digest linking its entry to the upstream release;
no new image was selected, staged or approved.

## Resource and lifecycle boundary

The provisional size is `tdx.large` (4 vCPU, 8 GB) with 80 GB storage. [Local ARM64 node measurements](phala-resource-sizing.md) show a synced public Testnet state around 13.7 GB and roughly 4.1 GB total container memory at one observation, but do not prove whole-guest x86_64 fit or import peak. The [published instance](https://cloud.phala.com/about/instance-types) and [storage](https://cloud.phala.com/about/pricing) rates imply `$40.84416` for **168 hours** at this provisional size before fees, rounding, or account-specific terms. Storage continues billing while stopped. The September 25 signed-in form estimate is stale and not a binding quote; the public page's region description also differs from that observed account node. Keep the existing **$50 total ceiling, $45 deletion trigger, and 168-hour maximum including synchronization**. The larger 16 GB `tdx.xlarge` would cost `$79.82016` over 168 hours at the same published storage rate, so it is not an automatic fallback within the current ceiling.

The Mac mini's Colima VM is the selected candidate external Linux/systemd watchdog host. Its clock, mount and uninstalled unit syntax passed the [host preflight](phala-watchdog-host-preflight.md). A later volatile rehearsal observed the synthetic mount gate start and one periodic timer firing on Colima's systemd 255; those units were removed afterward. The operator then explicitly authorized a workspace-scoped token with no expiry and revocation after cleanup. The [credential preflight](phala-watchdog-credential-preflight.md) records owner-private storage, a successful native Rust read-only authentication, an explicit TLS root, and a runnable ARM64 watchdog binary. Colima's preferred route survived one authorized VM restart, and the managed-container egress rules were restored. Effective mount-loss and Mac reboot recovery, timing allowances, and an independent deadline/manual backstop remain unresolved. No deletion timer is armed. The lifecycle ledger must be initialized **once before any resource call**, preserving the original start and deadline; `zrpc lifecycle ledger record-attempt` commits intent before creation, and `record-cvm` stores each returned canonical CVM/app/instance identity and conservative rate immediately afterward. The [CLI usage in `ledger.rs`](../crates/cli/src/ledger.rs) is the command contract. On uncertain outcomes, inspect retained state and authenticated inventory; never reinitialize it. `export-watchdog` only writes uninstalled units. Installing provider-capable units is within the operator's deployment authorization only after its effective configuration is reviewed. A DELETE response or missing CVM cannot establish storage deletion or billing finality; inventory and later billing reconciliation are separate evidence.

## Required completion before billable deployment

1. Confirm the account's current node, production image, KMS, capacity, 80 GB allowance, credit balance and complete price for the selected duration. Resolve any mismatch with the September 25 observation.
2. Select reviewed runtime limits from measured startup/load behavior. Render `prepare.py launch-documents` using the immutable image digest above and the checked context; compare the emitted Compose bytes with Phala's post-creation readback before interpreting an attestation measurement.
3. Prepare the original ledger, owner-private provider credential and trust-root files, effective watchdog units and restart test on the always-on host. Establish timing/fee allowances from the selected quote and measured deletion path. Arrange a deadline backstop independent of the Mac mini. Arm no scheduler until separately authorized.
4. Compare the resulting exact artifact digest, launch bytes, account quote, ledger registration path, cleanup controls and maximum evaluation duration with the [operator's authorization](phala-operator-authorization-2026-09-30.md). Do not create a resource if the configuration exceeds its scope.
5. After an approved launch, begin with synthetic inputs. Check actual guest resource fit, quote/collateral, retained TLS key binding, Tor-only client route, typed RPC behavior and the provider's effective Compose/KMS readback. Keep private mode blocked. Delete all experiment-owned resources and reconcile storage and billing evidence before closing the ledger.

The local, no-spend inspection command is `python3 -I deploy/phala/prepare.py status` **inside the managed container from the repository root**. It reports artifact eligibility only; it cannot create or approve a CVM. There is no ready deployment command in this packet.
