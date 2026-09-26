# Google lifecycle implementation record

Date: 2026-09-26. All tests in this checkpoint use synthetic resources. No
Google account, token, image upload, VM, API mutation, or scheduler activation
was used during implementation.

Implemented under `crates/lifecycle/src/gcp` with standalone
`zrpc-gcp-lifecycle` commands. Existing Phala lifecycle policy is unchanged.

The local package binds typed resource requests and artifact/quote identities.
The controller writes creation/deletion intents before dispatch, preserves
Google request IDs across recovery, records resource incarnation IDs and
Storage generations, polls operations, and removes resources in dependency
order. The journal holds an exclusive writer lock and publishes fsync-backed
immutable snapshots. The original start, deadline, package, request IDs, and
resource identities cannot be reset through the API. Local same-UID rollback
and an operator replacing the entire journal remain outside this storage
contract.

Runtime uses maintained rustls/hyper and operator-installed Google CLI OAuth
minting. Upload is streaming multipart Storage REST with
`ifGenerationMatch=0`; there is no image adaptation/import VM. Only fixed
Google API hosts and generated resource paths are used. No redirect, arbitrary
endpoint, guest credential injection, or RPC forwarding exists here.

External systemd artifacts are export-only. Live deployment admission checks
installed unit fragments and drop-ins, timer/startup enablement, synchronized
clock, file ownership, controller machine/executable identities, quote/artifact
hashes, and hash-bound operator rehearsal/backstop records. Such records are
operator evidence, not independent verification of cloud behavior.

## Unresolved live deployment contract

The reviewed Compute delete methods identify resources by name and provide
request deduplication but no documented incarnation precondition. Reading an
ID and then deleting the name leaves a replacement race. No primary source
found during this implementation establishes numeric-ID DELETE addressing for
every required resource type. Therefore `LIVE_DEPLOYMENT_BLOCKERS` prevents
creation before OAuth, and live Compute deletion refuses dispatch. Synthetic
replacement tests prove only detection when replacement is visible at GET;
they do not establish race-free live deletion. Resolving the provider contract
or implementing a reviewed exclusive-namespace admission mechanism is required
before enabling hosted creation.

Storage generation-conditional deletion is implemented. Retention/versioning/
soft-delete policies block creation, rather than treating a logical object
DELETE as proof that storage billing has ended. Final billing reconciliation
remains a separate operator review; no API balance or billing-export proof is
implemented.

Other required external inputs are an actual built/signed image, measured node
resource fit, complete current pricing, existing private staging bucket,
reviewed Google CLI distribution, credentials/TLS roots, effective independent
Linux controller, actual deletion rehearsal, and manual backstop. The package
cannot replace guest/hardware acceptance and never populates approved releases.

## Validation

The first focused managed-container run passed 10 synthetic tests covering
durable intent ordering, lost creation responses, operation recovery,
restart/overlap, immutable history, pending-publication recovery, expired
pricing/missing artifacts during cleanup, outages, visible replacement,
typed request tampering, and absence of inherited Phala cost limits.
Final managed-container workspace verification passed all 190 lifecycle tests,
including the 12 GCP cases and the added live-creation and watchdog deadline
tests. The standalone operator binary built and its help command passed.
These results do not establish provider behavior or effective host timers.

## Primary API contracts

- [Instance insertion and requestId](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/insert)
- [Instance deletion and asynchronous operations](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/delete)
- [Operation listing and filters](https://docs.cloud.google.com/compute/docs/reference/rest/v1/zoneOperations/list)
- [Raw image insertion and Secure Boot public keys](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/insert)
- [Storage multipart insertion and generation preconditions](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert)
- [Storage generation-conditional deletion](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/delete)

No undocumented SDK methods, TDX measurements, Google credentials, live prices,
or placeholder resource quotes were introduced.
