# Package checkpoint notes

The Phala package reuses the reviewed Zebra v6.4.2 metadata lock at
`deploy/gcp/zebra-release.lock.json` and the stage-only verifier at
`tools/gcp-guest/verify_zebra_release.py`. This is generic Zebra artifact
provenance, not a GCP deploy dependency or permission to bypass the release
hold. `stock-candidate.lock.json` pins the exact release-lock SHA-256, and
`prepare.py` verifies it before rendering. A later move of those shared inputs
must preserve the reviewed bytes and staging receipt contract.

The emitted `app-compose.json` is a local candidate. Its raw hash cannot be
called an authenticated Phala measurement until the provider accepts those
exact bytes and a post-deploy GET `/api/v1/cvms/{id}/compose_file` readback
matches. The named tmpfs volume, nested `/run/dstack.sock` mount, and UID/GID
access to quote/watch sockets also need a stock-runtime test. Source-mode
analysis predicts access because both services use GID 0, the shared volume
uses mode 1775, and the bridge sockets use mode 0660; it does not establish
Docker/Phala behavior.

The operator-only collateral fetcher is an independent Cargo workspace with
its own lock. It alone enables `dcap-qvl`'s `report` feature; the native `zrpc`
workspace keeps offline verification. The manifest pins registry version
`dcap-qvl=0.6.3`, and its lock pins crate checksum
`384b16fc9cbca8ec2a1302205487f29c421c51cdf7351f91c41f5ccbd1d1d17d`;
the fetch/serialization API was checked against upstream source commit
`e61f4fba357e96d68fc7d7be71635049841824fb`. The official
`dcap-qvl-cli verify`
prints a verified report rather than `QuoteCollateralV3` JSON, so it cannot
directly produce the native client's `--collateral` input. The helper's
`--fetch-from-phala-pccs` flag makes that external read explicit. No live
collateral has been fetched for this checkpoint.
