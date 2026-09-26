# Unsigned local build reproduction

`scripts/reproduce-release.py` builds the M0 CLI (`zrpc`) and RPC wrapper
(`zrpc-wrapper`) from an exact committed source revision. It builds twice in
separate source and target directories and compares the resulting bytes. The
outputs are unsigned scaffold binaries. Their checksums do not approve a
release, identify an accepted attestation measurement, or enable private mode.

Use a reviewed Linux build environment with the Rust version in
`rust-toolchain.toml`, a native C compiler/linker, Python 3.11 or newer, Git, and
the existing locked Cargo dependencies already cached. The build uses the committed local
UI bundle; it does not download packages or rebuild TypeScript. Cargo runs with
`--locked --offline`. A missing cached input fails the build. Provision inputs
through the applicable dependency-review workflow before trying again.

On the operator's managed workspace, start a container shell from the checkout:

```bash
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --shell
```

Inside the container, select one immutable commit and an unused output directory
on the workspace volume:

```bash
revision=$(git rev-parse HEAD)
CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 python3 scripts/reproduce-release.py \
  --revision "$revision" \
  --output-directory "/workspace/.codex-tmp/release-$revision"
```

The script requires a full commit ID and exports its committed source; branch
names are refused and uncommitted source changes are excluded. Existing Cargo
configurations are separate inputs whose hashes are recorded. The script refuses
an existing output directory. Failed runs retain
their evidence rather than being overwritten; choose a new explicit directory
for another attempt. On other Linux checkouts, use an equivalent reviewed
toolchain and an absolute output directory within that checkout. The managed
build opt-in is specific to the operator's package policy.

After success, check the delivered files from the output directory:

```bash
sha256sum --check SHA256SUMS
```

`artifacts/zrpc` and `artifacts/zrpc-wrapper` are the compared binaries.
`manifest.json` records the source revision, build inputs, toolchain identities,
settings and hashes. It also records the invoking script separately, so a
workflow from a different revision is visible. Keep the manifest, checksums and
source identification with any copied artifacts. A checksum received from the
same untrusted source as a binary does not authenticate that source.

The comparison tests repeated native builds in the recorded environment. It
does not establish reproducibility across different architectures, compilers,
linkers, system libraries or container images. Rust's toolchain pin and Cargo's
lock do not pin the entire C build environment. The operator's managed image is
not a separately published project build image. Other environments must compare
their outputs and disclose differences; do not describe an untested target as
reproducible.

The frontend bundle is a committed input with its own source and lockfile; this
workflow does not prove that rebuilding TypeScript reproduces that bundle.
Provider images, guest runtime images, Intel attestation collateral and live
TLS keys are separate inputs to the privacy gates. No signing, publication,
deployment, approved-image selection or cloud operation is part of this command.
