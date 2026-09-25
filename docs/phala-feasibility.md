# Phala compatibility boundary

M0 supports local synthetic fixtures only. It has no approved Phala production image, live attestation verifier, private transport, or deployment adapter. Every live feasibility gate is unresolved. Fixture acceptance never authorizes a private RPC request.

The intended platform is an Intel TDX production CVM with TLS terminating in the approved workload. Hardware authenticity, workload identity, security appraisal, connection-key ownership, transport, and chain readiness remain separate results. A provider response containing `verified: true` cannot authorize private mode.

Before a private release can be supported:

| Gate | Required compatibility contract |
| --- | --- |
| A — platform and workload | Pin a production OS, dstack integration, quote verifier, image artifacts and independent release policy together. Locally verify Intel collateral and TCB policy, reconstruct authenticated boot measurements, replay application events and compare the complete configuration identity. |
| B — fresh channel key | Review the exact nonce/context/key encoding and test vectors. The approved workload binds its own active key; the client checks a fresh challenge and possession of that key on the same TLS connection before RPC. Reconnects require new verification. |
| C — guest administration | Tie absence of SSH, debugging, operator exec and mutable startup paths to the measured production components and deployment configuration. A boolean supplied by the server is insufficient. |
| D — KMS and disk | Establish how the selected KMS controls boot authorization and storage keys. Approved code/configuration must remain authenticated despite KMS policy changes or writable-disk replacement. Persist only public chain data; channel keys stay in memory. |
| E — cost and resources | Obtain an authenticated quote for available resources, account limits, all charges and funding requirements. Demonstrate testnet operation without persistent swap and working deletion controls outside the CVM. |

Reuse maintained TLS, dstack and quote-verification implementations. No version tuple is approved for this project yet. A current upstream release or a passing quote signature alone does not establish that tuple.

The planning baseline is $40.84416 for 168 hours at $0.232/hour plus 80 GB at $0.000139/GB/hour. These are published inputs, not an authenticated checkout quote. Storage remains billable after stopping a CVM; deletion is required. The published new-account limit is 80 GB per CVM. [Phala pricing](https://cloud.phala.com/about/pricing).

Deployment requires a separate explicit operator action. The design sets a $50 projected-usage preflight ceiling, deletion at $45 conservative cumulative cost or 168 hours, and an approximately $60 overall infrastructure ceiling. External deadline and cleanup controls are prerequisites; polling cannot guarantee a billing hard cap.

The dated source review and precise missing evidence are in the [internal feasibility record](../records/feasibility-research.md).
