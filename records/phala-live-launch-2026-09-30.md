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

The stock HTTPS gateway URL terminated TLS outside the guest and could not
carry the wrapper's retained TLS session. The documented `-8443s` gateway
hostname passed TLS through to the guest: a separate diagnostic reached its
self-signed TLS 1.3 certificate. The native client used a freshly staged Tor
0.4.9.13 package whose Tor Project repository signature, package hash and
release age were checked by `tools/tor/prepare.py` without a hold exception.
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
