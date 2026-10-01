# Phala public-preview launch observation — 2026-09-30

This is an operational evidence record, not private-mode approval. The operator
authorized one billable public Testnet TEE preview and chose manual deletion
without arming the external watchdog. The approved-release catalog remains
empty. No customer wallet data or private RPC body has been sent.

The original experiment ledger was initialized at **2026-09-30 20:23:35 UTC**
with the existing $50 total ceiling, $45 deletion trigger and 168-hour maximum.
Its first creation intent was durably recorded before submitting the Phala
form. Phala reported one CVM created at **20:24:44 UTC** on `prod9` using
`tdx.large` (4 vCPU, 8 GB), 80 GB ext4 and the pinned public-preview image.
Authenticated inventory later reported exactly one running CVM. The live CVM
detail quoted **$0.243120/hour**: $0.232000 compute plus $0.011120 storage.
That is $40.844160 over 168 hours if it remains running at this rate, before
any other account usage or unshown adjustment. The account's credits are shared
with other Phala services; this arithmetic is not an enforced spend cap.

Manual deletion must be **requested by 2026-10-07 19:23:35 UTC
(15:23:35 EDT)**, leaving the operator's one-hour deletion allowance before
the hard experiment deadline at **20:23:35 UTC (16:23:35 EDT)**. Delete sooner
when the preview is complete, the $45 trigger is reached, or the $50 ceiling
is at risk. Stopping only ends compute charges; the 80 GB disk continues to
cost $0.011120/hour until the CVM is deleted. A DELETE response or missing CVM
is not final storage or billing evidence. The separately issued workspace API
token must be revoked after cleanup. No watchdog unit or timer was armed.

Phala's authenticated inventory, detail and attestation responses all reported
`instance_id: null` even though the CVM was running. [PR #271](https://github.com/tamnys/ZECret-Service/pull/271)
added an explicit pending-instance ledger state, and the existing CVM was
recorded at ledger generation 2 without inventing an instance ID. Its canonical
ID is `cvm_MeD4o0eQ`, app ID is
`5af400d6c4fd5312a9b9693fe0988d5bdc0ee726`, and VM UUID is
`05decd53-6a57-4b1d-97f5-ecff44749040`. The private, fsynced original
binding and ledger remain under the ignored
`.codex-tmp/phala-live-20260930/` directory. A fresh authenticated read at
2026-09-30 23:40 UTC found exactly this one running, tracked CVM, zero
untracked CVMs, and an incomplete usage-identity match. The modeled cost floor
was $0.793450 at that read; provider usage rows were empty, so this is not a
billing reconciliation. Do not reinitialize the original ledger, fabricate an
instance ID, or create another CVM.

At 2026-10-01 00:37 UTC, Phala's versioned usage API returned eight rows with
`project_id` and `team_id` encoded as JSON strings; the prior decoder expected
integers and rejected the response. The corrected decoder preserves either
wire type, including compatibility with the earlier numeric record format.
A fresh authenticated,
read-only observation then completed under the operator-approved 1 MiB response
cap: one tracked CVM, no untracked CVMs, and eight unjoined usage rows. All
eight `usage.instance_id` values matched this CVM's `vm_uuid`, while the CVM's
own `instance_id` remained null. This observed equality is not a provider
guarantee of a stable billing join or a final usage cutoff. The ledger remained
at generation 3, and the modeled cost floor at the read was $1.022658; no
provider charge was added to it.

At 2026-10-01 00:40 UTC, `zrpc lifecycle reconcile` repeated the authenticated
read and committed its eight unjoined usage rows to the original ledger at
generation 4. The committed modeled cost floor was $1.036907. A subsequent
ledger readback found two retained observations and the same one tracked CVM.
No Phala mutation occurred, no usage row was accepted as a charge, and billing
finality remains unverified.

On 2026-10-01, authenticated API version `2026-06-23` reads of this
CVM's detail and `compose_file` used the existing workspace key, an
independently selected TLS trust root, and the operator-approved 1 MiB response
cap. Both responses reported `public_logs: true`, `public_sysinfo: true` and
`public_tcbinfo: true`; the prepared local launch document had explicitly set
the first two fields false. The returned 1,498-byte `docker_compose_file`
matched the prepared SHA-256
`1e8f93e57803ea348cdf9fbbf9843d2851049ef9cec98d5c1237f71a4857058c`.
The full 20,442-byte provider compose response had SHA-256
`8a4ff7d6c6df51d76497b4bdc4fc63d692725c5a158eb66553b3313aa06d9912`,
different from the prepared app-compose digest. It also reported
`no_instance_id: false` despite the detail's `instance_id: null`, and a
nonempty 17,569-byte `pre_launch_script` with SHA-256
`982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8`.
The prepared document did not supply that script. A limited static pattern
scan found active root-password, authorized-key and remote-fetch branches;
the SSH-server term appeared only in a comment. This does not prove what
executed, that an SSH listener is reachable, or the script's origin. The raw
response and script were not saved or printed. These readback mismatches
preclude using the prepared app-compose hash as the live workload identity and
reinforce the existing block on private mode. No resource update had been
attempted at that read.

After retaining a private, fsynced intent bound to the original CVM and ledger
generation 5, a field-only `PATCH /api/v1/cvms/cvm_MeD4o0eQ` requested
`public_logs: false` and `public_sysinfo: false`. Phala returned 202 with a
correlation ID; the exact outcome was durably recorded beside the intent under
the ignored original experiment directory. An authenticated operation readback
found that correlation in `completed` status, and `operation-status` later
reported `idle`. Detail and compose readbacks both reported the two visibility
fields false. The post-update compose response SHA-256 is
`5a13c76a80bfe1cc40ea4d3a181512dc1f74d1ab8520fe754e95f7819ceaa3f5`;
its inner Docker Compose and pre-launch script hashes remained unchanged. The
detail still reported `instance_id: null` and briefly reported CVM status
`updating`. Completion of the management operation and matching readback do
not alone prove that the application has resumed serving or that prior public
logs were withdrawn. The update created no new CVM or private-mode approval.
Subsequent authenticated detail returned to `running`, and a fresh public
preview through the pinned Tor executable passed live quote, freshness and
TLS-key checks before reading Testnet height **4,425,002** and the zero-balance
fixture address. `private_accepted` remained false. This confirms the demo
path resumed after the visibility update, not that historical public logs were
removed or that stock-image privacy gates passed.

On 2026-10-01, an authenticated read of the stored CVM SSH-key set
returned zero keys and `restart_required: false`; the live Teepod user config
also returned zero `ssh_authorized_keys`. These observations do not exclude
password, console, rescue, or remotely configurable future access. The live
script contains active root-password and authorized-key handling, but its
actual execution and resulting authentication state were not inspected.

On 2026-10-01, the live script's exact byte length and SHA-256 matched
[`phala-cloud-prelaunch-script/prelaunch.sh` at dstack-examples commit
`4b1819d7f2cca610b2478a7be354358b1cad5b97`](https://github.com/Dstack-TEE/dstack-examples/blob/4b1819d7f2cca610b2478a7be354358b1cad5b97/phala-cloud-prelaunch-script/prelaunch.sh):
17,569 bytes and
`982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8`.
This identifies the script's public source, not which Phala layer inserted it
into this CVM or which branches executed. The source unconditionally calls
Docker image/volume pruning and attempts `docker compose pull`; its root
password and authorized-key changes are conditional on writable files and
inputs. A fresh authenticated compose readback retained the same script hash,
reported `allowed_envs: []`, and showed `runner: docker-compose`; the CVM
remained `running`. Empty `allowed_envs` does not rule out encrypted variables,
mutable `user_config`, console access or provider-controlled updates. The
[Phala SSH guide](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/phala-cloud/networking/enable-ssh-access.mdx)
says production images disable SSH and dstack 0.5.6+ rejects SSH passwords,
but this documentation is not an effective test of the exact running guest.
We did not save or execute the live script or infer private-mode approval from
the source match.

On 2026-10-01, an authenticated, single-CVM dry run of Phala's
[`PATCH /cvms/{cvmId}/instance-id` SDK operation](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/actions/cvms/refresh_cvm_instance_id.ts)
used `dry_run: true` and `overwrite: false`. It returned HTTP 200 with
`status: skipped`, `reason: gateway_rpc_failed`, `source: teepod_state`,
`verified_with_gateway: false`, and null old/new instance IDs. A prior detail
read still had `instance_id: null`. Only the dry-run request was submitted.
We did not attempt a non-dry-run refresh, substitute `vm_uuid` into the CVM
field, or accept the observed usage-row equality as an authenticated billing
join. The canonical CVM remains tracked in the original ledger and the usage
rows remain retained as unjoined evidence. Phala must clarify the failed
gateway verification and supported billing mapping before final reconciliation.

The stock HTTPS gateway URL terminated TLS outside the guest and could not
carry the wrapper's retained TLS session. The documented `-8443s` gateway
hostname passed TLS through to the guest: a separate diagnostic reached its
self-signed TLS 1.3 certificate. The Tor Project 0.4.9.13 package is pinned in
`tools/tor/package.lock.json`; the corrected run below staged it with
`tools/tor/prepare.py`, which checked the repository signature, package hash
and release age without a hold exception.
The first live `zrpc preview` call reached the attestation exchange through Tor
and sent **zero** RPC requests because quote appraisal failed.

Phala's attestation response supplied a 7,247-byte quote field whose TDX
quote declares 4,940 bytes of signed quote data followed by 2,307 extra bytes.
The project's exact-format decoder rejected the entire field as malformed.
For a separate initial diagnostic, the declared prefix was checked with the
existing offline `dcap-qvl` 0.6.3 verifier and collateral fetched explicitly
from Phala PCCS. [PR #271](https://github.com/tamnys/ZECret-Service/pull/271)
then taught the native client to accept only the quote-declared signed prefix
when Phala supplies trailing bytes, while retaining strict local quote, TCB,
collateral, freshness and TLS-exporter checks. Subsequent live public-preview
calls through the managed local Tor process passed those checks and returned
Testnet status and the synthetic transparent-address balance. The local
dashboard used the same Rust client core and was checked at desktop and narrow
widths. [PR #272](https://github.com/tamnys/ZECret-Service/pull/272) labels this
as a public preview. Neither Phala's `verified: true` nor the preview proves
the approved workload, private storage policy, administration boundary or
genuine private-mode acceptance. The approved-release catalog remains empty,
and private queries remain blocked.

The command recorded in [PR #274](https://github.com/tamnys/ZECret-Service/pull/274)
at 23:50 UTC succeeded but pointed to a different, Ubuntu-packaged Tor
**0.4.9.11** binary under `tor-tool/extract/usr/bin/tor`. It did not establish
use of the pinned Tor Project 0.4.9.13 executable. At 23:57 UTC the package
preparer staged the pinned executable at the path below, and this corrected
command succeeded from the current managed browser-container checkout. The
hostname is the live `prod9` app ID's TLS-passthrough route, not the
gateway-terminated HTTPS route. The local collateral file is an explicitly
staged input; the verifier did not fetch it while handling the query.

```sh
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --command cargo run --locked --manifest-path /workspace/.worktrees/phala-snapshot-preview/Cargo.toml -p zrpc-cli -- preview --platform phala-dstack --endpoint-host 5af400d6c4fd5312a9b9693fe0988d5bdc0ee726-8443s.dstack-pha-prod9.phala.network --endpoint-port 443 --tor-executable /workspace/.codex-tmp/phala-live-20260930/tor-project-0.4.9.13/bin/tor --collateral /workspace/.codex-tmp/phala-live-20260930/collateral.json
```

The live result reported `public_preview_passed: true`, Intel-root TDX quote
and public-preview TCB policy verified, fresh challenge and retained TLS key
binding verified, Testnet height 4,424,566 and zero zatoshis for the synthetic
fixture address. It reported `workload_identity_verified: false`,
`private_accepted: false` and no private query. The height and balance are
node-reported at different instants; synchronization completeness was not
independently established. This command is a repeatable public demo, not a
release-approval test. The same pinned Tor executable also ran a successful
native public preview in the Colima VM using a local loader wrapper and the
Ubuntu `libevent-2.1-7t64` package whose SHA-256 matched that VM's APT
index. This wrapper and extracted library live only in ignored local work
state; they do not change the guest or client trust policy.

On October 1, a managed browser-container preview using the public testnet
fixture address `tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma` failed during Tor
SOCKS negotiation. It reported
`tor_unavailable`, `public_query_sent: false` and `private_accepted: false`;
there was no direct-network fallback. The same address then succeeded through
the pinned Tor executable in Colima: the live quote, freshness and TLS-key
checks passed before the public balance query, with Testnet height 4,424,935
and a node-reported balance of 658,181,206,889 zatoshis. A later managed
container run with the default fixture address also succeeded at height
4,424,938. The single SOCKS failure is unresolved; these observations do not
establish that every fresh Tor circuit will connect. The second address is
public testnet input, not customer wallet material or private-mode evidence.

At 2026-10-01 01:02 UTC, a fresh managed-container public preview through the
pinned Tor executable reported Testnet height **4,424,966** and best-block hash
`00001435ab2ea3da7a3f235e3d2471de13e14fcd629d7f059c0685c70f0cf897`.
The client again verified the live quote, freshness and TLS-key binding under
the public-preview policy; `private_accepted` remained false. The independent
[CipherScan Testnet API](https://api.testnet.cipherscan.app/api/block/4424966)
returned the **same hash at height 4,424,966**. Its separate
[`getblockchaininfo` view](https://api.testnet.cipherscan.app/api/blockchain-info)
reported height 4,424,965 just before the Phala request and 4,424,968 just
after it, with equal blocks and headers and `verificationprogress: 1` at those
two reads. This is point-in-time agreement with another Zebra node and evidence
that the Phala node was near its observed tip. It is not network-wide consensus,
proof of the Phala node's own verification progress at that instant, or
private-mode acceptance. No new Phala resource or management mutation occurred.

At 2026-10-01 02:02 UTC, a new read-only diagnostic requested fresh evidence
from the live TLS-passthrough endpoint through the pinned managed Tor child.
The native client verified the Intel-root TDX quote, current collateral, fresh
nonce and exporter binding on that retained connection. It replayed the peer's
event log against the signed RTMR values and compared the measured
`compose-hash` with the exact 20,444-byte `app_compose` returned by the current
Phala attestation API; all public-preview launch-consistency checks passed.
The older saved quote and current provider event log had failed RTMR replay,
which confirms that mixing evidence from different observations is invalid.
The diagnostic sent no RPC query, approved no release and did not establish
the script's provenance, administrative isolation, KMS/disk trust or private
mode. Its comparison policy was derived from provider readback and is not an
independent artifact approval. No resource mutation or additional spend was
triggered.

At 2026-10-01 00:05 UTC, a local probe started the dashboard inside Colima,
forwarded its assigned loopback port through SSH to the Mac, and retained its
one-time bootstrap token and local capability only in process memory. From
the Mac side, the page, bootstrap, status and preview routes each returned
HTTP 200. The preview reported `public_preview_passed: true`, Testnet height
4,424,577, `workload_identity_verified: false` and `private_accepted: false`.
The resulting local UI path is Mac loopback → SSH → Colima Rust client → local
Tor → Phala. The probe did not open a graphical Mac browser or send a private
request. It then closed the tunnel and dashboard. Its abrupt SSH teardown left
one Tor child, which was explicitly terminated with its exact temporary directory
removed. [PR #276](https://github.com/tamnys/ZECret-Service/pull/276)
subsequently added a Linux parent-death guard; an abrupt client exit can still
leave its temporary Tor directory, so it is not crash-time storage cleanup.

For the operator's manual Mac dashboard, start this command in one terminal.
It prints a one-time local URL to that terminal; keep the link out of logs and
public reports.

```sh
ssh -F /Users/j/.colima/ssh_config -tt colima /Users/j/Code/phala-zcash-rpc/.worktrees/phala-snapshot-preview/target/debug/zrpc dashboard --preview --platform phala-dstack --endpoint-host 5af400d6c4fd5312a9b9693fe0988d5bdc0ee726-8443s.dstack-pha-prod9.phala.network --endpoint-port 443 --tor-executable /Users/j/Code/phala-zcash-rpc/.codex-tmp/phala-live-20260930/tor-project-0.4.9.13/launch-colima.sh --collateral /Users/j/Code/phala-zcash-rpc/.codex-tmp/phala-live-20260930/collateral.json --no-open
```

In a second terminal, substitute the port printed in that URL for `PORT`:

```sh
ssh -F /Users/j/.colima/ssh_config -N -L 127.0.0.1:PORT:127.0.0.1:PORT colima
```

Open the one-time URL in the Mac browser. The local and remote ports must match
because the dashboard validates Host and Origin. If that port is already occupied on the Mac, stop the
dashboard and start it again for a new assigned port. Stop the dashboard with
Ctrl-C, then stop the tunnel. This local wrapper depends on the ignored staged
Tor and `libevent` artifacts on this Mac; the managed-container preview command
above is the verified container test path.

Phala's live stats reported zero swap and a running DStack 0.5.9 guest. The
stock dashboard's container-log view returned `configured logging driver does
not support reading`; the later end-to-end public RPC response, rather than
that log view, established Zebra readiness for the preview. No additional
billable resource has been authorized by this observation.

## Manual deletion and follow-up

The operator chose manual cleanup. Before requesting deletion, run the native
`zrpc lifecycle ledger inspect` against the original binding and read its
current generation, tracked CVM ID, deletion intents, modeled cost and deadline.
Then run `zrpc lifecycle observe` with the same original binding, workspace API
key file, pinned TLS trust root and the approved 1 MiB response cap. Confirm
that authenticated inventory contains the expected single CVM and no other
experiment-owned resource. Both commands are read-only. The original binding
is `/Users/j/Code/phala-zcash-rpc/.codex-tmp/phala-live-20260930/original.json`;
the credential and trust root are stored in the Colima VM, not in this repo.

Request deletion no later than the time above using `zrpc lifecycle
delete-tracked` with the **generation just inspected** and exact CVM ID
`cvm_MeD4o0eQ`. This command records a durable intent before making one
provider DELETE request. A 204 or 404 response records the outcome but does
not prove cleanup. If it fails or is interrupted, inspect the retained ledger
first; `retry-tracked` requires an explicit prior intent generation and must
not be replayed blindly. The signed-in Phala dashboard is the manual fallback
if the CLI cannot dispatch, with the provider result and time recorded beside
the original ledger. Do not stop the CVM as a substitute for deletion.

After deletion, inspect the ledger and repeat authenticated observation until
the CVM is absent from inventory and detail. Check for remaining attached
storage in the Phala console and preserve the provider's deletion or storage
evidence. Separately inspect subsequent usage/billing until charges through
the deletion time are accounted for; `instance_id: null` means the current
automated usage join remains incomplete. An empty usage page, DELETE response
or missing CVM alone is not a final billing or disk-deletion receipt. Revoke
the workspace API token after the cleanup evidence is retained. If provider
storage or billing evidence remains unavailable, record cleanup as unresolved
and contact Phala support with the CVM/app/VM UUID and deletion time.
