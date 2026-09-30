# Package checkpoint notes

The Phala package reuses the reviewed Zebra v6.4.2 metadata lock at
`deploy/gcp/zebra-release.lock.json` and the stage-only verifier at
`tools/gcp-guest/verify_zebra_release.py`. This is generic Zebra artifact
provenance, not a GCP deploy dependency. The explicit v6.4.2 exception permits
only local staging, image-context preparation, and launch-document rendering
while the seven-day hold is active. It is bound to the exact release asset ID
and digest in the stage receipt and copied into the local image context. The
separately authorized [native image smoke](../../records/phala-native-image-smoke.md)
built and ran that exact candidate locally without publishing it; it did not
broaden the stage receipt into a deployment or private-mode approval. The
launch renderer rechecks that complete context and requires the pinned stage
receipt digest and exception identity; the GCP image runner retains its age
check. The verified stage receipt is
committed under `records/` and its exact SHA-256 is pinned in
`stock-candidate.lock.json`, so a caller-written receipt cannot exercise the
exception. The stock lock also pins the exact release-lock SHA-256, and
`prepare.py` verifies it before rendering. A later move of those shared inputs
must preserve the reviewed bytes and staging receipt contract.

The emitted `app-compose.json` is a local candidate. Its raw hash cannot be
called an authenticated Phala measurement until the provider accepts those
exact bytes and a post-deploy GET `/api/v1/cvms/{id}/compose_file` readback
matches. The [native Docker mount smoke](../../records/phala-native-mount-smoke.md)
confirmed the two nonroot identities can share the named tmpfs while both
containers remain running, the app cannot see a usable nested backend socket,
and its public-state volume has the expected ownership. It used a synthetic
socket and did not run dstack or the actual quote bridge. The stock Phala
runtime still needs a test of its effective named-volume mounts, root-owned
backend socket, quote/watch socket access, startup ordering and failure
handling. The shared volume uses mode 1775 and both services use GID 0;
source-mode reasoning alone cannot establish those provider behaviors.

The official Phala Cloud OpenAPI at commit
`7b36622c6eb4ff691b5818546c04c61b26e08809`, `AppComposeV2`, declares
`storage_fs` and `kms_enabled` but not `swap_size` or `key_provider`. The
renderer omits the latter two, which cannot be treated as supported Cloud
admission inputs without an updated schema or a provider-confirmed round trip.
This leaves no-swap and disk-key authorization unresolved. The OpenAPI may lag
the service, so this is a fail-closed packaging choice, not evidence that
Cloud rejects or strips those fields.

The pinned Python base is the official Docker Hub Linux amd64 manifest digest
`sha256:37134a49d21d2120e4c4d73bb76f8a4ab9aef31f096f7ec2ead48c2feead4332`;
its OCI manifest reports config digest
`sha256:b2bb53ac7b6fbe78a48c95b7c15130ea21de1674fc683fbc93158b0c23826823`
and created annotation `2026-09-19T00:58:14Z`. The two native hashes match the
unsigned, twice-matching Linux build receipt for source commit
`36822a65c96ae97213c491f2e084a5b1518df7c3`. `check-image-context`
recomputes all local build-input hashes and rejects extra paths; it does not
establish an OCI artifact or registry digest. Those identities only exist
after a separate local build and registry push respectively. A registry may
change OCI metadata on push, so compare the exact pushed digest with the
registry readback before using it in `launch-documents`.

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
