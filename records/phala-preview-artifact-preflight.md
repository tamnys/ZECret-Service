# Local Phala preview artifact preflight — 2026-09-30

This is an internal inventory of the existing local public-Testnet preview
image. It is not a registry publication, Phala boot result, TDX measurement,
private-mode approval or spending authorization. No image rebuild, registry
push, provider mutation or cloud resource creation occurred in this preflight.

The local `zrpc-phala-preview:snapshot-20260923` image inspected as
`linux/amd64` with image ID
`sha256:290f24afaa04d9b7a81c797b43b95ecdc0247976ddd306621b76a664802b39ff`.
An ignored workspace export at `.codex-tmp/phala-preview-image-20260930.tar`
is 124,314,112 bytes, SHA-256
`87036d79b39759be0d368fb3a385303cf325f95182dea7757fadc7c75a640472`.
Its OCI index digest is the local image ID. The single `linux/amd64` image
manifest inside that index is
`sha256:0f3b5ece5a8a806402fdb384d38e264b596b6c0f4621e38695c478ba41ec7c97`;
the index also contains a separate `unknown/unknown` Docker attestation
manifest. The amd64 image config selects user `10001:0` and entrypoint
`python3 /opt/zrpc/supervisor.py`. All 23 archive blobs matched their SHA-256
names. Eight application artifacts in the 17-layer image matched the tracked
Zebra and snapshot locks, fixed native-binary hashes, or exact source files:
`zebrad`, `zrpc-node-wrapper`, `zrpc-quote-proxy`, the `zstandard` wheel,
`supervisor.py`, `snapshot_import.py`, `snapshot.lock.json` and `zebra.toml`.
The image's first four filesystem layer IDs matched the locally inspected,
pinned Linux amd64 `python:3.13.15-slim-trixie` base. This is an inventory of
the saved local bytes, not proof of a reproducible build or of what a remote
registry will later serve. The image contains no imported Zebra Testnet state;
that public database remains a first-boot volume/import concern.

The [current Phala OpenAPI `AppComposeV2` schema](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json)
was still at the previously reviewed commit at this readback. It declares all
fields emitted by `deploy/phala/prepare.py` for `app-compose.json`, including
`storage_fs`, `kms_enabled` and `tproxy_enabled`. It does not declare a
`swap_size` field. The newer [loose JavaScript compose schema](https://github.com/Phala-Network/phala-cloud/blob/ee941461e05004e4f80c26694f43c833bbc208b6/js/src/types/app_compose.ts)
does list `swap_size`, but that client-side schema does not establish server
acceptance or effective guest behavior. No submitted compose or provider
readback was checked here.

The [published Phala rate page](https://cloud.phala.com/about/pricing) still
lists $0.000139/GB-hour for storage, including while stopped; the
[instance list](https://cloud.phala.com/about/instance-types) still lists
`tdx.large` at $0.232/hour for 4 vCPU and 8 GB. At those public rates, 80 GB
for the 168-hour maximum is $40.84416 before other charges or credits. This
is **not** a current quote for the selected account or proof of capacity. The
public page describes CPU machines in US East, while the September 25
[account observation](phala-account-preflight.md) selected `prod9` in
`US-WEST-1`; the effective account region, image/KMS availability and total
price require fresh provider readback.

Before a billable launch, the exact image must be published by a separate
operator action and its remote immutable digest checked; a local archive or
image ID is not that digest. The remaining package also needs reviewed
runtime limits, a current account quote, selected storage and memory-fit
evidence, an active external deletion control and independent deadline
backstop. The stock guest's persistence and administrative gaps still block
genuine private-mode approval.
