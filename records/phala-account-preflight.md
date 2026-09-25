# Read-only Phala preflight observations

Observed 2026-09-25 through the operator-authorized signed-in Chrome session. The deployment form was inspected and its unsubmitted size/storage fields set to the design baseline solely to obtain an estimate. Only GET metadata requests were made directly, to the same resource and instance catalogs already requested by the page. No deployment, payment, resource mutation or support message was submitted. The final Compute inventory still showed no deployed CVMs. Account identifiers, receipts, payment details and credentials are intentionally omitted.

## Candidate offered by the account

| Field | Observed provider catalog value |
| --- | --- |
| Node / region | `prod9` / `US-WEST-1` |
| Production OS | `dstack-0.5.9-bd369a8c` |
| Full OS image digest | `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033` |
| Image flags | enabled, `is_dev: false`, CPU compatible |
| Image publication field | `2026-04-21T04:05:12Z` |
| Default Cloud KMS | `phala-prod9`, catalog ID `kms_opjg1KBD` |
| KMS endpoint | `https://kms.dstack-pha-prod9.phala.network` |
| Reported KMS version | `v0.6.0-rc0 (git:cb4c3736c5f9323440a3)` |
| Size | `tdx.large`, 4 vCPU, 8192 MB RAM |
| Size availability | Eight at observation time; not a reservation |
| Workspace storage capacity | 1024 GB total; 256 GB per instance |

The other visible node was `prod5`, also US West. The selected node's CPU OS menu offered production 0.5.9 and 0.5.8 alongside explicitly marked development variants. Provider compatibility metadata lists 0.5.9 for the selected KMS. These are provider assertions, not approved measurements, live quote evidence or a verified KMS configuration.

## Pricing and shared funding

The authenticated instance-price record reports compute at exactly `$0.232000/hour`. For 80 GB, the expanded form shows `$169.36/month` compute, `$8.00/month` storage, `$177.36/month` total, and approximately `$0.242959/hour`. Multiplying the displayed hourly estimate by 168 gives approximately **$40.817112**. This is close to the design's $40.84416 baseline; no provider resource was reserved.

The storage selector separately displays rounded `$0.012/hour`. A precise billable disk rate, time basis, rounding, network allowance, taxes, fees, and any other charges are not established by that estimate. Do not treat it as an all-inclusive binding quote or replace the exact baseline fixture with inferred rate values. Gate E remains open.

Compute is prepaid and auto-topup is off. Credits are shared with other services, and model-credit auto-transfer is enabled. The operator's $50 is therefore not isolated from unrelated service usage. No settings were changed. The experiment remains capped at $50 regardless of other balances or grants; recheck available credits before any future billable action.

## Defaults requiring a reviewed configuration

The draft form enables a gateway described as terminating TLS, public system information, and public logs. Those defaults are not a private-service configuration. The UI directs application-managed TLS users to dstack-ingress; the appropriate end-to-end transport still needs exact-version verification. The production-image SSH panel states that non-development images lack a built-in SSH server; this UI statement does not prove absence of every guest administration path. The draft remained unsubmitted and was left for the empty Compute inventory.

## Archive-to-catalog mapping verified locally

Downloaded the public [v0.5.9 release archive](https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.9/dstack-0.5.9.tar.gz) into ignored workspace storage without executing it. Its SHA-256 matches the [published asset metadata](https://api.github.com/repos/Dstack-TEE/meta-dstack/releases/assets/401364871):

```text
f3888f64e215bc1e1af53a1f3d13b4df48fe40d4a3059049bb87d4c7c06aff97
```

The offline probe `records/probes/verify-v059-archive.py` recomputed the firmware, kernel, initramfs and metadata hashes in the [build algorithm's exact order and format](https://github.com/Dstack-TEE/meta-dstack/blob/e3655d1390feee3736476f4bda35c4354b4a12fc/mkimage.sh#L70). The literal manifest hash matches both archived `digest.txt` and the full catalog OS digest above. Metadata identifies OS source `e3655d1390feee3736476f4bda35c4354b4a12fc`, version 0.5.9, `is_dev: false` and `shared_ro: true`. The archive's kernel arguments contain:

```text
dstack.rootfs_hash=a2d0a2af747ac763d56745f81d6aba93c04112076a6c502a3a5e2b45dd8b7c96
dstack.rootfs_size=156594176
```

These are observed artifact values, not newly invented attestation measurements. The rootfs hash is a dm-verity commitment; ordinary file SHA-256 is not a substitute for verity verification. Build reproduction, independent verity validation, measured-boot reconstruction and live TDX evidence were not performed. The probe always reports `private_accepted: false`.

## Startup and KMS gates remain open

The OS source pins dstack commit `282eeb27d22d8f091ad0fa5a90e638f85cf68751`. Its [preparation path](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/basefiles/dstack-prepare.sh#L262) and relevant startup units are byte-identical to the files examined in `ephemeral-runtime-investigation.md`: persistent runtime roots and the unchecked hook invocation remain. The local failure reproduction therefore applies to this source. Matching an archive digest does not remedy that startup issue or prove guest execution behavior.

The reported KMS commit resolves to `cb4c3736c5f9323440a3fb04172a4d2902c54db0`, upstream v0.6.0-rc0. Its [disk-key derivation](https://github.com/Dstack-TEE/dstack/blob/cb4c3736c5f9323440a3fb04172a4d2902c54db0/dstack/kms/src/main_service.rs#L355) uses the root key with app and instance identities, without the compose or OS hash in that derivation. Authorization is separately [delegated to configured policy](https://github.com/Dstack-TEE/dstack/blob/cb4c3736c5f9323440a3fb04172a4d2902c54db0/dstack/kms/src/main_service/upgrade_authority.rs#L120). Conditional on changed code being authorized under the same identities/root, the disk key remains the same. The actual production root, authorization policy, configuration and attestation remain unverified. A catalog version string alone cannot settle them.

No tuple or live gate is approved. Next security work requires a supported, measured correction or pre-existing barrier that makes ephemeral runtime preparation fail closed, followed by the exact-image tests already specified. This inspection supplies the missing account metadata; it does not authorize deployment or spending.
