# Native amd64 Phala preview image smoke — 2026-09-30

This is a local-image runtime check on a public GitHub `ubuntu-24.04` x86_64
runner, not a Phala CVM or TDX boot. The manually dispatched
[run 36686217969](https://github.com/tamnys/ZECret-service/actions/runs/36686217969)
completed successfully at merged source commit
`366734ddf074ca8c9370f2fcfc6f2714ad75de83`. All four job steps passed.
The workflow is in [PR #245](https://github.com/tamnys/ZECret-service/pull/245).

The runner checked the immutable GitHub artifact identity from the prior
twice-matching native Rust build at source commit
`36822a65c96ae97213c491f2e084a5b1518df7c3`, verified its bundled tar
checksum and the pinned hashes of `zrpc-node-wrapper` and `zrpc-quote-proxy`.
It downloaded Zebra v6.4.2 and the x86_64 `zstandard` wheel and checked their
reviewed sizes and SHA-256 values. The Zebra release attestation was **not**
independently reverified on this runner; the packaging step reused the exact
previously reviewed staging receipt, which `prepare.py` pinned and checked.
The image context passed `check-image-context` with SHA-256
`9b18cfa2dbe72a39c0857878046b6b5a115f19209835a43c971b820d090a371c`,
matching the offline cached-input rehearsal.

The runner pulled only the pinned `linux/amd64` Python base and built the
complete application image with build-step networking disabled. Docker wrote
local image ID
`sha256:3d650d57c40ca686052a94d14c52a2465d9000f89ae801b14389cb4d70cde984`.
The job checked image architecture, nonroot user `10001:0`, and the Python
supervisor entrypoint. With runtime networking disabled and the filesystem
read-only, the image ran `zebrad --version` as v6.4.2 and the node wrapper's
help command. The quote bridge rejected an unsupported flag. Starting either
supervisor mode without its required memory-backed runtime mount exited 1
with an expected missing or non-tmpfs mount error. No image was uploaded or
pushed.

This native runner image is a separate build from the local OCI archive
inventoried in [the artifact preflight](phala-preview-artifact-preflight.md).
Matching checked context hashes do not establish bit-for-bit image
reproducibility. The smoke did not mount dstack, import the Testnet database,
start the complete service pair, measure resource fit, use Tor, inspect a live
quote, or approve private mode. It made no Phala API call, created no CVM,
activated no scheduler and spent no Phala credits. A real Phala boot and
provider readback remain necessary before any TEE-hosted demo claim.

## Reproducibility check on the current native candidate

At source commit `054aa11da2eb8cedfcb449b8c871fc9eba438474`, independent
[runner 36712817820](https://github.com/tamnys/ZECret-service/actions/runs/36712817820)
and [runner 36712958264](https://github.com/tamnys/ZECret-service/actions/runs/36712958264)
both passed the image and service smoke. Each runner made two uncached builds
from the same checked context and pinned `moby/buildkit:v0.33.0` index
`sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3`.
All four local Docker archives had SHA-256
`65b65737031256ba16c4d7194951282a1d5aa82def48844ef83cdafabfbb0099`;
all four local image config IDs were
`sha256:ba4bef9fce41866e8353dc8510b6c0ae6d39125864164b7643de9850915365cc`.
The exporter reported digest
`sha256:cac592db30e3587cc400f9a2a4ac0b7caa20a857eadb27505c5537f4d0c5d46b`
on each build. This is an exporter-reported digest, not a registry readback.

The first attempts with the runner's default Docker builder produced different
filesystem layer timestamps despite a fixed `SOURCE_DATE_EPOCH`. The pinned
`docker-container` builder and `rewrite-timestamp=true` tar export made the
complete local archive byte-identical across these two fresh runners. No image
was uploaded or pushed, so no immutable registry identity or production guest
measurement exists yet. Reproducibility is established for this local build
recipe and exact inputs; a later packaging, registry, or deployment step needs
its own identity readback.

The merged [main run 36714132961](https://github.com/tamnys/ZECret-service/actions/runs/36714132961)
passed the same smoke at commit `f5b7074e2c11f74a512fd9be618722c4ccf91144`.
Its checked context remained `019600c63c557870223a4ee67bfd1acb4576c98af08672f8477247d5168857e8`,
but its archive SHA-256 changed to
`e18024cc0f8149b365323d7928f8b7a57e938ff065a903b5b1044e2048ed5042`
because the workflow had used the Git commit time as `SOURCE_DATE_EPOCH`.
This made an evidence-only commit alter the local image identity. The revised
workflow derives that timestamp from the checked context's pinned base-image
Created annotation (`2026-09-19T00:58:14Z`). Its first
[run 36714625090](https://github.com/tamnys/ZECret-service/actions/runs/36714625090)
at source `4ee0891c2ed13c43820869fce2a9d4c39bb8d7df` produced twice-matching
archive SHA-256
`7666369a61754e2d5f2fa338674e4696cfe107cda238d342fc5f0496e896c6cb`
and local image config ID
`sha256:e126a22b330b47da87299cadef6ead7ee6e53a8008d2588bf9e90fb5739b3df2`.
The same-context, later-commit check is still needed before calling that
identity stable across evidence-only changes.

That check exposed a second archive-only input. At records-only source commit
`3949620041a2c7f86f910267bcefa74b20dc2ffc`,
[run 36714945133](https://github.com/tamnys/ZECret-service/actions/runs/36714945133)
kept the image config ID above but produced archive SHA-256
`aac4bafbe540932e5c644ede686ee8614b762c6537b4e4ef0e458742fbf302bb`:
the Docker archive's `manifest.json` contained the Git-SHA-derived local tag.
Its build comparison passed, but the service smoke failed on an invalid
`blocks == 0` assertion after the live Zebra testnet node had advanced. The
smoke now accepts a nonnegative integer block height with headers at least as
high. A later [run 36715240699](https://github.com/tamnys/ZECret-service/actions/runs/36715240699)
passed the complete service smoke and retained the same image config ID; its
archive still changed with the tag. The workflow now uses a fixed, local-only
tag. Its first [run 36715501053](https://github.com/tamnys/ZECret-service/actions/runs/36715501053)
passed with twice-matching archive SHA-256
`2bafc4b766d7ff71b36a04bd4a0581b0ccd875a0cc099db5a77014666cca22c8`
and the same image config ID. A fresh run after this records-only commit will
test complete-archive stability across commits.
