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
`instance_id: null` even though the CVM was running. The current ledger
`record-cvm` command requires that field, so the resource is **not yet in the
ledger's tracked-resource set**; its durable creation attempt is committed and
a private, fsynced observation receipt containing exact CVM/app/VM UUID IDs,
provider creation time, workspace match and rate is retained under the ignored
`.codex-tmp/phala-live-20260930/` directory. Do not fabricate an instance ID,
reinitialize the original ledger or create a second CVM. Manual deletion is
available in the signed-in Phala dashboard while this provider field remains
null. Any lifecycle adapter change must preserve the distinct CVM, VM UUID and
usage identifiers.

The stock HTTPS gateway URL terminated TLS outside the guest and could not
carry the wrapper's retained TLS session. The documented `-8443s` gateway
hostname passed TLS through to the guest: a separate diagnostic reached its
self-signed TLS 1.3 certificate. The native client used a freshly staged Tor
0.4.9.13 package whose Tor Project repository signature, package hash and
release age were checked by `tools/tor/prepare.py` without a hold exception.
The live `zrpc preview` call reached the attestation exchange through Tor and
sent **zero** public or private RPC requests because quote appraisal failed.

Phala's attestation response supplied a 7,247-byte quote field whose TDX
quote declares 4,940 bytes of signed quote data followed by 2,307 extra bytes.
The project's exact-format decoder rejected the entire field as malformed.
For a separate **diagnostic only**, the declared prefix was copied into a new
file and checked with the existing offline `dcap-qvl` 0.6.3 verifier and
collateral fetched explicitly from Phala PCCS. Intel-root cryptographic
verification passed, TDX TCB status was `UpToDate`, no advisory IDs were
reported, and the collateral expiration was in the future. The project's
strict security policy still rejected this quote; the specific rejected
condition has not been established. Neither that prefix check nor Phala's own
verification response proves the live session key, approved workload, private
storage policy or genuine private-mode acceptance. The native client continues
to fail closed.

Phala's live stats reported zero swap and a running DStack 0.5.9 guest. The
stock dashboard's container-log view returned `configured logging driver does
not support reading`; it did not establish Zebra readiness. A live Testnet RPC
response and dashboard behavior remain unverified. Keep this CVM's elapsed
time and manual teardown obligation visible while debugging; no additional
billable resource has been authorized by this observation.
