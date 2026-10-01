# Phala feasibility request — unsent draft

Prepared 2026-09-26 and refreshed 2026-10-01 from the retained account, source
and live public-preview evidence below. This is an internal handoff, not a sent
support message or an approval to deploy another resource, alter account
settings, or spend more credits. No recipient or channel has been selected.

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

On September 30 we deployed one stock-image CVM, `cvm_MeD4o0eQ`, for public
Testnet preview only. Our client independently verified its live TDX quote and
TLS-key binding under a deliberately limited public-preview policy, then read
public chain data through Tor. We have sent no private query and have not
approved this workload for private mode. This live test does not resolve the
runtime-disk, KMS or administrative questions below.

Is there a currently supported image or supported custom-image route that puts
these runtime roots in memory and prevents every runtime startup/restart path
from proceeding if preparation fails? Please share the immutable image/source
references, compatible KMS configuration, and how that image is admitted on the
selected node. We have a local checked-extraction candidate, but it does not yet
establish the complete boot/restart barrier. The specific evidence and billing
questions for the evaluation are below.

The one-CVM experiment retains a $50 ceiling, a $45 deletion trigger and a
maximum duration of 168 hours, including synchronization and testing. We plan
to request deletion by October 7 at 19:23:35 UTC, leaving one hour before the
hard deadline. Please keep this an information request; do not create or change
billable resources in response.

## Technical questions accompanying the draft

1. **Measured boot and memory-only runtime.** For the supported image, provide
   artifact digests, source/build references and the measured configuration
   format. Does the host-supplied `sys-config.json` change across boots or node
   placement? We need its production schema and exact KMS, gateway and VM
   configuration values, or a supported immutable way to constrain them in
   the measured image. Which immutable units or equivalent controls cover Docker,
   containerd, Sysbox, any additional runtime roots, socket activation, orphan
   cleanup and restarts? How are preparation failure, retained disk state and
   active swap prevented from permitting execution? We need the exact artifact
   and configuration to test these properties independently.

2. **Administration, KMS and live-key evidence.** Which measured controls exclude
   SSH, console/rescue/debug access, guest exec APIs and mutable startup or
   privileged-workload paths? For the compatible production KMS, provide its
   attestation/configuration evidence and the applicable key-release policy,
   including who can change that policy and whether changed OS/workload code
   can receive the same disk key. Please provide the production
   `key_provider_id` and its encoding: the matching dstack source skips KMS
   identity comparison when that field is empty, so our measured profile will
   require a nonempty value. We have tested TLS passthrough and live-key
   binding for public preview; please confirm that this route and its policy
   are supported on production nodes. Provider `verified: true` responses will
   not substitute for local quote, measurement and connection verification.
   The matching gateway source lets an administrator override the CVM's port
   policy. Does that path exist on the production gateway, and can it be
   disabled or fixed for this deployment so
   that only the attested TLS wrapper port is reachable? We need to rule out an
   override that could expose Zebra's loopback RPC directly.

3. **Deletion and accounting contract.** For API version `2026-06-23`, the live
   CVM inventory and detail return `instance_id: null` but a nonempty `vm_uuid`.
   Eight usage rows returned `instance_id` equal to that `vm_uuid`. Is that the
   supported, stable mapping for billing, including replicas, restarts and
   deletion? The same response returned `project_id` and `team_id` as JSON
   strings, while the published schema specifies integers; which types should
   clients support for this API version? What evidence identifies every attached
   billable disk and confirms its
   deletion after `DELETE /api/v1/cvms/{cvm_id}` returns 204? How can we retrieve
   complete usage after CVM/app deletion and establish final charges, including
   ingestion delay and pagination consistency? An empty CVM list, 404 or
   deletion timestamp alone cannot establish disk deletion and billing finality.

4. **Cost and deletion timing.** The live detail quotes $0.243120/hour for
   `tdx.large` (4 vCPU, 8 GB RAM) with 80 GB storage, or $40.84416 over 168
   hours if unchanged. Please confirm rounding, network allowance, taxes and
   other fees, and whether the account has an enforceable total-spend limit or
   isolated compute credit balance. Stopped storage continues billing until
   deletion. What deletion-latency bound, if any, can the operator rely on?

## Internal evidence and response handling

The offered tuple came from
[the September 25 account inspection](phala-account-preflight.md); the live
rate, resource ID, quote check and cleanup deadline are in
[the September 30 launch record](phala-live-launch-2026-09-30.md). The exact
archive/rootfs checks and their limits are recorded in
[the artifact inspection](rootfs-artifact-inspection.md). The failure and
remaining startup requirements are in
[the checked-hook candidate](ephemeral-runtime-candidate.md). The
[September 26 public-source refresh](phala-boot-support-refresh.md) found no
resolving supported tuple. The API identity, storage and finality gaps are in
[the source-contract analysis](live-lifecycle-adapter-plan.md). The local
adapter now retains authenticated usage rows, but does not infer a billing join
or provider finality from matching identifier strings.

No account identifier, credential, private query or wallet material is included.
The CVM ID, image label, node, KMS label and source versions identify the
technical question; account-specific details can be supplied privately by the
operator if needed.

Support answers identify inputs for review; they cannot themselves approve
private mode. Preserve the dated response and immutable references, then check
the exact offered artifact/KMS tuple, independent attestation and fresh TLS-key
ownership, administrative and disk controls, and real-node resource fit.
Authenticated pricing and external cleanup evidence remain requirements for a
future private release. The current public-preview operator chose manual
deletion; that choice does not prove a reliable automated spending cap. Local
simulation and generated, uninstalled scheduler bundles supply none of the
missing live receipts.
