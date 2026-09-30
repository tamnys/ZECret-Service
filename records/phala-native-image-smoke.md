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
