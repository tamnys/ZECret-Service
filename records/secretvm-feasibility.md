# SecretVM feasibility investigation — 2026-09-26

## Decision and scope

SecretVM is a plausible alternative, but the inspected stock verification flow
does not satisfy this project's private-mode policy. No currently supported
production configuration has been established that passes all gates. This is
an evidence assessment, not a demonstrated SecretVM data leak or a claim that
the platform cannot be adapted.

The operator requested investigation, not migration, deployment or spending.
The acceptance criteria remain independent hardware/workload verification,
fresh challenge and live TLS-key ownership before private RPC, mandatory Tor,
no guest administrative access, and persistent writable storage containing only
public chain state. Rust remains the shared CLI/local-UI core; the public site
remains fixture-only. Intel TDX is the candidate path. No AMD migration or
change to the accepted architecture was made.

Only public documentation, source and unauthenticated read APIs were inspected.
No account was accessed, dependency installed, guest booted, live quote accepted,
private query sent, resource created, support message sent or money spent.
No application code or release policy changed. Existing simulation still cannot
authorize private mode.

## Source identities

- Official documentation: `SecretFoundation/docs`
  [`6ed4f467c782078370466610487c4b6ee58e1eb8`](https://github.com/SecretFoundation/docs/commit/6ed4f467c782078370466610487c4b6ee58e1eb8).
- Verification SDK: `scrtlabs/secretvm-verify`
  [`a5d0d7c21cceef8305dbbb0589cf10dabe7a2047`](https://github.com/scrtlabs/secretvm-verify/commit/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047).
- Operator CLI: `scrtlabs/secretvm-cli`
  [`1fa6fd95257a9bd8203ccc4e30fc2f8c7fd1cbb2`](https://github.com/scrtlabs/secretvm-cli/commit/1fa6fd95257a9bd8203ccc4e30fc2f8c7fd1cbb2).

Direct unauthenticated GitHub API reads returned HTTP 404 for the documented
`scrtlabs/secret-vm-build`, `secret-vm-kms`, `secret-vm-ops`, and
`secret-vm-attest-rest-server` repositories. The verifier repository was
accessible. A 404 establishes current public inaccessibility at those URLs;
it does not establish deletion, renaming or private-repository status.

## Gate assessment

| Gate | Finding | Acceptance status |
| --- | --- | --- |
| A: local hardware and approved workload | Local DCAP verification and workload measurement replay exist. Exact production artifacts and an independently reviewed release policy remain necessary. | Unresolved; useful components exist. |
| B: freshness and live channel key | SDK checks a TLS certificate against quote REPORTDATA, then returns a result rather than the verified connection. Its quote request has no client challenge. | Inspected stock flow is insufficient. |
| C: no guest administration | Documentation distinguishes development access, but exact production SSH/console/debug/exec/recovery controls cannot be established from available runtime source. | Unresolved. |
| D: disk and KMS | Persistence and upgradeability are configurable. Their labels do not establish memory-only runtime writes or exact key authorization. | Unresolved. |
| E: resources, cost and deletion | Published base prices fit the planning envelope. Capacity, all fees, node fit and disk/billing finality are unconfirmed. | Unresolved. |

### Independent verification and the connection

The [TDX verifier](https://github.com/scrtlabs/secretvm-verify/blob/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047/node/src/tdx.ts)
uses maintained DCAP verification, current-time collateral checks and a debug
check. Its success does not require the project's strict `UpToDate` policy;
the reported TCB result still needs explicit appraisal. Our existing pinned
Rust QVL can remain the cryptographic verifier.

The [SDK session flow](https://github.com/scrtlabs/secretvm-verify/blob/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047/node/src/vm.ts)
fetches Compose from the VM and checks its measurement consistency. This does
not establish that the supplied workload is our approved RPC release. It fetches
`GET /cpu` without a client nonce, compares REPORTDATA against TLS SPKI or legacy
certificate hashes, and uses a GPU nonce for the second half when applicable.
That GPU nonce is not our client's freshness challenge.

The [TLS helper](https://github.com/scrtlabs/secretvm-verify/blob/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047/node/src/url.ts#L213)
completes a handshake and then destroys the socket. This provides key-possession
evidence for that handshake, but does not provide a retained, approved RPC
channel. A fresh TLS handshake alone does not make the quote fresh. Default
networking uses ordinary TLS and HTTP calls, so the SDK is not a Tor-only native
client implementation.

The [artifact registry refresh](https://github.com/scrtlabs/secretvm-verify/blob/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047/node/src/artifacts.ts#L158)
downloads mutable GitHub `main` registry data without a signature check in that
path. The [matcher](https://github.com/scrtlabs/secretvm-verify/blob/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047/node/src/workload.ts)
also recognizes development entries. Neither mechanism may silently expand our
approved production release set.

A viable integration would retain Rustls, the existing explicit release/TCB
policy, and Tor with remote hostname resolution. All private-mode evidence
retrieval must use that transport or validated local collateral. The guest must
provide a supported quote mechanism binding our fresh challenge to its own live
key/channel. No such interface was established from the accessible SDK and
unavailable guest implementation. No API or measurement was invented.

### Runtime, administration and retained state

The [boot description](https://docs.scrt.network/secret-network-documentation/secretvm-confidential-virtual-machines/attestation/chain-of-trust)
describes TDX measurements of the OS and Compose, and generating or restoring a
machine TLS certificate. Restoration is not evidence of the process-ephemeral
key required here. Exact source/artifact inspection must establish boot ordering
and fail-closed enforcement, not just measurement labels.

[Launch documentation](https://github.com/SecretFoundation/docs/blob/6ed4f467c782078370466610487c4b6ee58e1eb8/secretvm-confidential-virtual-machines/launching-a-secretvm/README.md)
allows SSH and serial console in development. Production must be selected, but
that distinction alone does not prove absence of guest administrative routes.

The [persistence option](https://docs.scrt.network/secret-network-documentation/secretvm-confidential-virtual-machines/secretvm-cli/virtual-machine-commands)
concerns retaining state across reboots. Disabling it does not establish RAM-only
Docker/containerd state, logs, temporary files, writable layers, swap or crash
dumps during uptime. Conversely, this review did not confirm that SecretVM has
the same persistent-runtime layout previously found in Phala. That remains an
unknown, not a transferred finding.

[Upgradeability documentation](https://github.com/SecretFoundation/docs/blob/6ed4f467c782078370466610487c4b6ee58e1eb8/secretvm-confidential-virtual-machines/managing-secretvm-lifecycle/secretvm-upgradeability.md)
explicitly permits upgraded workloads to recover old encrypted state when
enabled. Disabled mode is described as image-bound key authorization. The
inspected CLI defaults upgrades on, so any candidate must explicitly disable
them and independently verify enforcement. This does not replace the no-private-
disk policy.

[KMS documentation](https://github.com/SecretFoundation/docs/blob/6ed4f467c782078370466610487c4b6ee58e1eb8/secretvm-confidential-virtual-machines/launching-a-secretvm/choosing-the-kms-provider.md)
offers Secret Network, Google and dstack providers. We still need the deployed
KMS version/configuration, key-root custody, authorization and administrator
powers. On-chain authorization alone does not establish those properties.

### Cost, networking and teardown

The [pricing page](https://secretai.scrtlabs.com/pricing) and public
[`GET /api/vm/types`](https://secretai.scrtlabs.com/api/vm/types) reported:

| Exact type ID | vCPU | RAM | Disk | USD/hour | USD for 168 hours |
| --- | ---: | ---: | ---: | ---: | ---: |
| `large` | 4 | 8 GB | 80 GB | 0.12 | 20.16 |
| `xlarge` | 8 | 16 GB | 160 GB | 0.24 | 40.32 |
| `large-gcp-tdx` | 4 | 16 GB | 80 GB | 0.263 | 44.184 |

These are arithmetic projections from public rate records, not reservations or
all-inclusive checkout quotes. The API's `traffic: 0` on `large` has no confirmed
allowance/price meaning; do not interpret it as unlimited free traffic. BYO-GCP
prices exclude separately billed cloud infrastructure. Current free capacity,
network/storage extras, taxes, rounding and stopped-resource billing require
confirmation. Zebra sync and steady-state memory/disk fit have not been tested.

The [REST reference](https://github.com/SecretFoundation/docs/blob/6ed4f467c782078370466610487c4b6ee58e1eb8/secretvm-confidential-virtual-machines/secretvm-rest-api.md)
documents authenticated instance inventory/detail reads and
`DELETE /api/vm/:id/terminate`, distinct from stop. The documented delete response
does not establish disk-object removal or final billing cessation. The inspected
reference did not supply a VM cumulative-cost/usage endpoint. Our existing Phala
adapter cannot simply be redirected to this API. A SecretVM adapter would need
scoped identity checks, conservative cost accounting, deletion confirmation,
and an installed external deadline/watchdog before deployment.

The [CLI TLS helper](https://github.com/scrtlabs/secretvm-cli/blob/1fa6fd95257a9bd8203ccc4e30fc2f8c7fd1cbb2/src/services/tlsProxy.ts)
adds in-guest Traefik with Docker-socket access and persistent ACME storage. That
helper is not our approved process-local TLS path. Direct guest TLS reachability,
Tor exit connectivity and outbound Zebra P2P need confirmation and later testing.
The provider does not need a Tor-specific SDK for a Tor exit to connect, but
ordinary TCP documentation is not a completed end-to-end test.

The existing [operator budget](operator-budget.md) remains $50 total, with the
$45 deletion trigger and 168-hour maximum. The $50 already credited to Phala is
not demonstrated funding at SecretVM. Investigation authorizes no new funding,
credit use or deployment; switching provider does not reset the experiment cap.

### Public repository compatibility

The current [verifier LICENSE](https://github.com/scrtlabs/secretvm-verify/blob/a5d0d7c21cceef8305dbbb0589cf10dabe7a2047/LICENSE)
and [CLI LICENSE](https://github.com/scrtlabs/secretvm-cli/blob/1fa6fd95257a9bd8203ccc4e30fc2f8c7fd1cbb2/LICENSE)
contain Gamma/non-commercial restrictions. Do not rely on a README's MIT label
or assume these versions can be copied into this public project. No code was
copied or dependency added. Resolve reuse permissions before integration;
retaining our maintained Rust TLS/QVL components avoids assuming SDK reuse.

## Evidence needed next

1. Obtain accessible immutable production guest/build/runtime and KMS sources,
   artifact provenance and a currently supported TDX configuration. Establish
   early-boot/restart memory-only runtime, public-chain-only persistent storage,
   no swap/private crash dumps, no administrative routes and non-upgradeable key
   authorization. Source review must precede any private deployment claim.
2. Establish the actual supported guest quote interface and review its live
   key/challenge binding. Then implement a synthetic-only integration using the
   retained Rust/Tor core, with replay, wrong-key, altered-workload, dev-image,
   unavailable-Tor and reconnect rejection tests. A test fixture cannot close
   the hardware gate.
3. Obtain a current all-in quote and precise termination/storage/billing
   semantics. Implement and locally validate a SecretVM lifecycle adapter and
   external deadline tooling before proposing any explicitly approved hosted
   experiment. Only then can authorized hardware/network/node-fit tests run.

No runtime test was warranted by this documentation-only change. Verification
for this record consisted of primary-source inspection at the pinned commits,
direct public API status/price reads and review against the project's unchanged
acceptance gates. There is no safe SecretVM deployment command to recommend yet.
