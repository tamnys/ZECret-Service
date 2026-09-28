# Unsigned local build reproduction

`scripts/reproduce-release.py` builds all ten project Rust executables,
including the GCP early init (`zrpc-gcp-early-init`), lifecycle
(`zrpc-gcp-lifecycle`), and UKI digest (`zrpc-uki-digest`) tools, from the exact
checkout HEAD on native x86_64 Linux. It builds twice in separate source and
target directories and compares the resulting bytes. The outputs are unsigned
scaffold binaries.
Their checksums do not approve a
release, identify an accepted attestation measurement, or enable private mode.

Use a reviewed Linux build environment with the Rust version in
`rust-toolchain.toml`, a native C compiler/linker, Python 3.11 or newer, Git, and
the existing locked Cargo dependencies already cached. The build uses the committed local
UI bundle; it does not download packages or rebuild TypeScript. Cargo runs with
`--locked --offline`. A missing cached input fails the build. Provision inputs
through the applicable dependency-review workflow before trying again.

In a reviewed Linux build container, select one immutable commit and an unused
output directory on the checkout's workspace volume:

```bash
revision=$(git rev-parse HEAD)
mkdir -p .codex-tmp
CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 python3 scripts/reproduce-release.py \
  --revision "$revision" \
  --output-directory "$PWD/.codex-tmp/release-$revision"
```

The script requires a full commit ID and exports its committed source; branch
names are refused and uncommitted source changes are excluded. Existing Cargo
configurations are separate inputs whose hashes are recorded. The script refuses
an existing output directory. Failed runs retain
their evidence rather than being overwritten; choose a new explicit directory
for another attempt. On other Linux checkouts, use an equivalent reviewed
toolchain and an absolute output directory within that checkout. The
`CODEX_ALLOW_REVIEWED_PACKAGE_BUILD` setting is specific to the operator's
managed build policy.

After success, check the delivered files from the output directory:

```bash
sha256sum --check SHA256SUMS
```

`artifacts/` contains all ten compared binaries. The
`selected_binaries` and `artifact_sha256` entries identify the complete set.
`manifest.json` records the source revision, build inputs, toolchain identities,
settings and hashes. The invoking script must match the copy in that revision;
the build refuses a different workflow. Keep the manifest, checksums and
source identification with any copied artifacts. A checksum received from the
same untrusted source as a binary does not authenticate that source.

The comparison tests repeated native builds in the recorded environment. It
does not establish reproducibility across different architectures, compilers,
linkers, system libraries or container images. Rust's toolchain pin and Cargo's
lock do not pin the entire C build environment. The operator's managed image is
not a separately published project build image. Other environments must compare
their outputs and disclose differences; do not describe an untested target as
reproducible.

The manual `GCP native x86 Cargo dependency gate` workflow checks the locked
registry and Git sources against their seven-day release hold before fetching
dependencies. It then fetches with the pinned Rust image and runs the double
build without network access. On success, its `native-rust-<commit>` artifact
contains a tar bundle and SHA-256 file. The bundle holds the source archive,
manifest, checksums, both copies of every executable, dependency gate reports,
and the exported diagnostic guest inputs. Verify the tar digest before use,
then use `tools/gcp-guest/export_rust_inputs.py` against an extracted bundle in
the same exact-HEAD checkout. The workflow does not approve a release or guest
image.

The frontend bundle is a committed input with its own source and lockfile; this
workflow does not prove that rebuilding TypeScript reproduces that bundle.
Provider images, guest runtime images, Intel attestation collateral and live
TLS keys are separate inputs to the privacy gates. No signing, publication,
deployment, approved-image selection or cloud operation is part of this command.
