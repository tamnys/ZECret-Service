# Stock Phala public testnet preview package

This directory prepares local image inputs and an exact dstack launch document
for a public Zebra testnet preview. It makes no Phala API call, creates no CVM,
and never approves private requests. The Zebra v6.4.2 x86_64 asset normally
remains inside the repository's seven-day release hold until
`2026-10-02T19:59:10Z`. The approved exception applies only to exact-asset
local staging, image-context preparation, and launch-document rendering. Run
`python3 deploy/phala/prepare.py status` to inspect the normal age gate.

The candidate stock tuple is `dstack-0.5.9-bd369a8c` on `prod9` with
`phala-prod9` KMS, as observed in the account on September 25. The exact image
digest, KMS catalog identity, and source commits are in
`stock-candidate.lock.json`. Recheck account availability, KMS selection, image
identity, and pricing before any deployment decision. A passing local package
check cannot establish those live facts.

The image recipe pins the Linux amd64
`python:3.13.15-slim-trixie@sha256:37134a49d21d2120e4c4d73bb76f8a4ab9aef31f096f7ec2ead48c2feead4332`
manifest and the two native Rust binary hashes. It also requires a checked
Linux x86_64 `zebrad` and the Zebra staging receipt from
`tools/gcp-guest/verify_zebra_release.py stage`. During the Zebra hold, pass
`--allow-v642-local-hold-exception` to `stage`, `prepare.py image-context`,
and `prepare.py launch-documents`. The latter requires the checked image
context and its exact staged receipt. Image-context preparation still refuses
an unpinned ELF, different base manifest, or different native binaries. It
copies checked bytes and the Zebra receipt into a fresh local build context
and hashes every file in it. Before building, run
`python3 deploy/phala/prepare.py check-image-context --context ABSOLUTE_CONTEXT_PATH`.
The check detects changed or extra build inputs; it does not build, pull, or
publish an image. Use `--help` for the full preparation arguments. Build and
registry publication remain separate operator actions.

After an exact application image digest and reviewed runtime limits exist,
`prepare.py launch-documents` writes `compose.json`, `app-compose.json`, and a
receipt into a fresh local directory. During the hold, pass the
`image-inputs.json` path within the checked local context and the explicit
exception flag. The receipt hashes the exact candidate
bytes intended for dstack. The Phala Cloud form may rewrite the launch
document; after an approved deployment, compare the emitted bytes with the
provider's `GET /api/v1/cvms/{id}/compose_file` response before using the local
hash in any measurement claim. The launch document
uses a single published `8443` TCP port. The dstack gateway's
`<id>-8443s.<base_domain>` route passes TLS through to the wrapper in the CVM;
the native client supplies its local Tor SOCKS endpoint. The app never maps
Zebra's loopback RPC or P2P listener. See the
[pinned dstack v0.5.9 usage guide](https://raw.githubusercontent.com/Dstack-TEE/dstack/v0.5.9/docs/usage.md)
for the `s` route syntax.

The current Phala Cloud `AppComposeV2` schema declares `storage_fs` and
`kms_enabled`, but does not declare `swap_size` or `key_provider`. This public
preview does not assert a no-swap policy or disk-key authorization policy.
Verify the effective configuration through provider readback and live tests;
private-mode approval remains blocked.

The Compose design runs a quote bridge with the stock dstack socket mounted
only in its container, and a separate application container with Zebra and the
node wrapper. Both use the same supplied immutable image digest. A shared tmpfs volume
carries quote sockets and Zebra's cookie; `zebra_public_testnet` is the only
application data volume and holds public chain state. Docker, containerd, and
Sysbox still use the stock image's persistent data disk, so this configuration
does **not** meet the memory-only runtime requirement for private RPC. The
Phala support question about moving those roots before startup remains open.

The wrapper serves public chain status and a user-supplied valid testnet
transparent-address lookup only through the local preview path. The client
must label the result as public and unverified for private use. No private
release catalog entry exists. The local demo client requires a managed Tor
SOCKS endpoint; no Tor executable is currently prepared for the chosen Mac
mini/Colima client host. Direct network access is not a fallback.

For a live quote diagnostic, obtain an exact quote from the same deployed CVM
using the [Phala attestation command](https://github.com/Phala-Network/phala-cloud/blob/main/skills/usecase/verify-attestation.md),
`phala cvms attestation <name> --json`. Save its `app_certificates[0].quote`
hex bytes as `quote.bin` in a fresh local file. For a saved `attestation.json`,
the extraction is:

```sh
python3 - attestation.json quote.bin <<'PY'
import json, re, sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_bytes())
quote_hex = document["app_certificates"][0]["quote"]
if not isinstance(quote_hex, str):
    raise ValueError("quote must be hex text")
quote_hex = quote_hex.removeprefix("0x")
if not quote_hex or len(quote_hex) % 2 or re.fullmatch(r"[0-9a-fA-F]+", quote_hex) is None:
    raise ValueError("quote is not exact hex")
with open(sys.argv[2], "xb") as output:
    output.write(bytes.fromhex(quote_hex))
PY
```

After the separate
`collateral-fetcher` project's seven-day dependency audit and locked build
inside the managed container, explicitly invoke it with absolute paths:

```sh
phala-collateral-fetcher --quote /workspace/quote.bin \
  --output /workspace/collateral.json --fetch-from-phala-pccs
zrpc inspect-quote --quote /workspace/quote.bin \
  --collateral /workspace/collateral.json
```

The fetcher contacts only Phala's documented PCCS when invoked; it emits the
`dcap-qvl` `QuoteCollateralV3` JSON required by the offline verifier. Its
Cargo project and lock are separate from the native client so the PCCS HTTP
feature cannot be unified into that client. Treat the response as untrusted
until `zrpc inspect-quote` verifies Intel signatures and current validity.
The later per-session TLS quote still needs its own verification and nonce/key
binding; a provider `verified` field is not a substitute. Invoke the local
public diagnostic as `zrpc preview --platform phala-dstack --endpoint-host HOST
--endpoint-port GATEWAY_PORT --tor-executable ABSOLUTE_PATH --collateral
ABSOLUTE_JSON [--address TESTNET_TRANSPARENT_ADDRESS]`. It verifies the live
hardware quote and session binding, but does not establish the full workload
identity required for private RPC.

Before a billable public demo, the operator must
also select an age-eligible Zebra artifact and exact app image, test the
container mount/permission behavior and live quote/TLS route, measure node
resource fit, obtain a current quote from the selected CVM, and arm the external deletion
deadline on the chosen always-on host. A local render receipt is not a deploy
instruction or spending authorization.
