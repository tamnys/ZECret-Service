# Phala feasibility request — unsent draft

Prepared 2026-09-26 from the retained account and source evidence below. This is
an internal handoff, not a sent support message or an approval to deploy, alter
account settings, or spend credits. No recipient or channel has been selected.

## Message draft

Subject: Supported production TDX image for an ephemeral-runtime RPC evaluation

Hi Phala team — can you point us to a supported production OS/KMS configuration
for a Zcash testnet RPC evaluation where only public blockchain data persists?
Container runtime state, request data and the application's TLS private key must
stay in memory, with no swap or guest administrative access. The native client
will independently verify the workload and its live TLS key before sending a
query over Tor.

On September 25, our console offered `dstack-0.5.9-bd369a8c` on `prod9` with
`phala-prod9` KMS reporting `v0.6.0-rc0`. We checked the matching archive and
rootfs. The preparation script persists Docker/containerd/Sysbox state before
running `init_script`; we also reproduced an unchecked script-extraction failure
in the matching source. Container-level tmpfs settings do not cover those host
runtime roots.

Is there a currently supported image or supported custom-image route that puts
these runtime roots in memory and prevents every runtime startup/restart path
from proceeding if preparation fails? Please share the immutable image/source
references, compatible KMS configuration, and how that image is admitted on the
selected node. We have a local checked-extraction candidate, but it does not yet
establish the complete boot/restart barrier. The specific evidence and billing
questions for the evaluation are below.

We have not deployed. The entire experiment has a $50 ceiling, a $45 deletion
trigger and a maximum duration of 168 hours, including synchronization and
testing. Please keep this an information request; resource creation or billable
changes require separate approval.

## Technical questions accompanying the draft

1. **Measured boot and memory-only runtime.** For the supported image, provide
   artifact digests, source/build references and the measured configuration
   format. Which immutable units or equivalent controls cover Docker,
   containerd, Sysbox, any additional runtime roots, socket activation, orphan
   cleanup and restarts? How are preparation failure, retained disk state and
   active swap prevented from permitting execution? We need the exact artifact
   and configuration to test these properties independently.

2. **Administration, KMS and live-key evidence.** Which measured controls exclude
   SSH, console/rescue/debug access, guest exec APIs and mutable startup or
   privileged-workload paths? For the compatible production KMS, provide its
   attestation/configuration evidence and the applicable key-release policy,
   including who can change that policy and whether changed OS/workload code
   can receive the same disk key. Which supported TLS-passthrough and dstack
   interfaces let our application bind a fresh client challenge to its own
   process-local TLS key and prove possession on the same connection? Provider
   `verified: true` responses will not substitute for local quote, measurement
   and connection verification.

3. **Deletion and accounting contract.** For API version `2026-06-23`, how does
   metered usage `instance_id` map to CVM `id`, `instance_id` and `vm_uuid`?
   What evidence identifies every attached billable disk and confirms its
   deletion after `DELETE /api/v1/cvms/{cvm_id}` returns 204? How can we retrieve
   complete usage after CVM/app deletion and establish final charges, including
   ingestion delay and pagination consistency? An empty CVM list, 404 or
   deletion timestamp alone cannot establish disk deletion and billing finality.

4. **Quote and budget enforcement.** Please confirm current availability and
   the precise billable compute/storage rates for `tdx.large` (4 vCPU, 8 GB RAM)
   with 80 GB disk, including units, rounding, network allowance, taxes and other
   fees. Does the account support an enforceable total-spend limit or isolated
   compute credit balance? Our observed form estimate was about $40.817112 for
   168 hours; the design's published-rate baseline is $40.84416. Neither is an
   all-inclusive binding quote. Stopped storage continues billing until deletion,
   so we also need any contractual deletion-latency bound for our independently
   operated deadline/watchdog jobs.

## Internal evidence and response handling

The draft's offered tuple and estimate come from
[the September 25 account inspection](phala-account-preflight.md). The exact
archive/rootfs checks and their limits are recorded in
[the artifact inspection](rootfs-artifact-inspection.md). The failure and
remaining startup requirements are in
[the checked-hook candidate](ephemeral-runtime-candidate.md). The
[September 26 public-source refresh](phala-boot-support-refresh.md) found no
resolving supported tuple. The API identity, storage and finality gaps are in
[the source-contract analysis](live-lifecycle-adapter-plan.md); later local
adapter implementation does not supply missing provider semantics.

No account identifier, credential, private query or wallet material is included.
The candidate image label, node, KMS label and source versions identify the
technical question; account-specific details can be supplied privately by the
operator if needed.

Support answers identify inputs for review; they cannot themselves approve
private mode. Preserve the dated response and immutable references, then check
the exact offered artifact/KMS tuple, independent attestation and fresh TLS-key
ownership, administrative and disk controls, and real-node resource fit.
Authenticated pricing and tested external deletion/deadline jobs remain required
before any separately authorized deployment. Local simulation and generated,
uninstalled scheduler bundles supply none of those live receipts.
