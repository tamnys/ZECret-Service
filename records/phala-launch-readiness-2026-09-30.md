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
  spending cap. At the quoted rate, a window ending at the close of Thursday
  in New York (`2026-10-02T04:00:00Z`) would cost about $8.05 from the
  September 30 readback time. That is a proposed earlier deadline within the
  authorized 168-hour maximum, not an initialized ledger or billing promise.

## External control status

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

The provider's current OpenAPI lists `PATCH
/api/v1/cvms/{cvm_id}/scheduled-delete`, while the ordinary create request
has no scheduled-delete field. A provider-side scheduled delete could therefore
be set only **after** creation and verified by CVM readback. It would be an
independent backstop, not a substitute for the external watchdog or proof that
attached storage and billing have ended. If setting or verifying it fails,
the new CVM must be deleted promptly using its retained ledger identity.

The remaining deployment input is an explicitly selected response-size and
deletion-latency allowance: Phala's OpenAPI has no guaranteed maximum body
size or deletion time. A question about using a 1 MiB body cap and one-hour
deletion allowance for this public experiment is pending with the operator.
Those would be assumptions subject to live verification, not provider
guarantees. The exact production ledger, effective provider-capable units,
deadline backstop, and post-deletion billing procedure are not yet activated.
Do not submit the form until the original binding and external jobs are
persisted, synchronized, and read back.
