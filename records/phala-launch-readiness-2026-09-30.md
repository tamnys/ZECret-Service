# Phala public-preview launch candidate — 2026-09-30

This is a no-spend status record for the operator-authorized **public Testnet
TEE preview**. It is not private-mode approval. The distributed approved-release
catalog remains empty. No CVM has been created, no original experiment ledger
initialized, and no real deletion timer armed.

## Prepared launch inputs

- The published native Linux/amd64 application image is
  `ghcr.io/tamnys/zecret-service-preview@sha256:780e8e60c812ccc7946dd346bc2b52b4ef4b61c225298063fa1f30b153b87c58`.
  Its checked build and smoke evidence are in the
  [operator packet](phala-preview-operator-packet.md).
- The checked local image context is retained under the ignored worktree
  `.codex-tmp/image-context-current`; its source/input receipt was rechecked
  inside the managed container. The local candidate runtime file is
  `.codex-tmp/phala-preview-runtime-candidate.json`. Its values are provisional
  availability limits, not measured Phala startup or quote guarantees.
- `prepare.py launch-documents` rendered the exact candidate Compose from that
  context and the published digest, without any cloud call. Its
  `docker_compose_file` is 1,498 ASCII bytes with SHA-256
  `1e8f93e57803ea348cdf9fbbf9843d2851049ef9cec98d5c1237f71a4857058c`.
  The complete `app-compose.json` has SHA-256
  `d4c9b8490b3868fbd8d640c854385a5767e71b10ab0145007f4c57b3e03e65bf`.
  The unsubmitted signed-in Phala editor was read back byte-for-byte against
  the Compose hash. Its UI may still rewrite the complete launch document;
  post-creation readback must precede any measurement claim.
- The unsubmitted Phala form is named
  `zrpc-testnet-tdx-preview-20260930`. It selects `prod9`, displayed
  `dstack-0.5.9`, Phala KMS, Large TDX (4 vCPU, 8 GB; eight reported
  available), 80 GB ext4, and the 8443 wrapper port. Public system info and
  public logs are off; KMS is on. The signed-in form quoted **$0.242959/hour**
  total, or **$40.817112 for 168 hours** before any unshown fees or rounding.
  The form has not been submitted. The stock OS digest and effective KMS
  policy still require live readback; the public preview makes no private
  execution claim.
- Signed-in billing showed **$51.74 shared workspace credit**, with $20 grant
  credit applied first, CVM usage $0 this month, prepaid compute and auto-topup
  off. Other workspace services share the balance, so it is not a dedicated
  spending cap. The operator selected a **168-hour experiment window** measured
  from the original ledger start, including synchronization and cleanup. This
  supersedes the previously proposed close-of-Thursday cutoff. At the
  September 30 form quote, the full window projects **$40.817112** before
  unshown fees or rounding; recheck the complete account quote before launch.
  The start and absolute deadline are not set until the original ledger is
  initialized immediately before the first billable call.
- A fresh `HEAD` of the [pinned public Testnet archive](../deploy/phala/snapshot.lock.json)
  at 2026-09-30 19:07 UTC returned HTTP 200 at the locked URL with
  `Content-Length: 11137971554`, matching the lock's expected byte count, and
  `Accept-Ranges: bytes`. This is an availability check, not a repeat of the
  completed full-download SHA-256 verification or a guarantee that the archive
  will remain available during the Phala boot.

## Manual lifecycle status

The operator authorized one non-expiring, workspace-scoped Phala API token
for the Mac mini/Colima deletion watchdog and revocation after cleanup. Its
bytes and workspace identifier are absent here. The current native ARM64
`zrpc` is owner-private in the VM, with SHA-256
`3b58199bdb2975ed58c100d15770966313b2deb28f76d6deef80e87a7fb1c6ba`.
Its read-only Rust provider authentication succeeded against zero CVMs. The
VM has the explicit GTS Root R4 DER, synchronized clock, working `col0` route,
and a persistent `/Users/j` VirtioFS mount. Isolated mount-loss and
synchronized Colima VM restart rehearsals passed, then all synthetic units
were removed. An empty mode-0700 directory for the original ledger exists at
`/Users/j/Code/phala-zcash-rpc/.codex-tmp/phala-live-20260930` on that mount.
The operator has since chosen **manual deletion without activating this
watchdog** for the public preview. The credential and tested binary do not
create a scheduled cleanup job; revoke the unused token after the experiment.

The [pinned provider OpenAPI](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json)
lists `PATCH /api/v1/cvms/{cvm_id}/scheduled-delete`, while the ordinary create
request has no scheduled-delete field. It can therefore be set only **after**
creation. The documented PATCH 200 body is `VM`, which omits
`scheduled_delete_at`; `GET /api/v1/cvms/{cvm_id}` may return either
`CvmBasicInfo`, where that field is optional, or `CVMInfoDetail`, which omits
it. Thus a 200 PATCH alone does not prove the provider retained the deadline,
and the documented GET contract does not guarantee a readable confirmation.
The schedule cannot be treated as confirmed unless a live readback actually
exposes the exact time or Phala supplies another reliable confirmation path.
No provider schedule has been set. Neither a schedule nor a DELETE response
proves that attached storage and billing have ended.

The operator selected a **1 MiB (1,048,576-byte) per-response cap** for
optional management-API diagnostics and a **one-hour deletion-latency
allowance** inside the 168-hour window. With the automatic watchdog waived,
the manual operator must request CVM **deletion** no later than 167 hours after
the durable experiment start, and sooner if the demo is complete, projected
experiment cost reaches $45, or the $50 ceiling is at risk. Stopping alone
leaves storage billing active. The exact original ledger, manual teardown
deadline, responsible operator, and post-deletion storage/billing procedure
must be established before submitting the form. The one-hour allowance is not
a provider guarantee; a DELETE response does not prove billing finality.
