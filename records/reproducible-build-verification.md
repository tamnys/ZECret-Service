# Unsigned native build reproduction — 2026-09-26

Contract: fulfill design §15's local checksum/reproduction requirement for the
current scaffold. Export an exact committed source tree, build the CLI and
wrapper independently twice, compare bytes and retain checksums plus provenance.
Two clean builds are the minimum comparison needed to test repeated output; this
does not prove equality across arbitrary environments. Nothing is signed,
published, deployed or accepted as an approved private-mode release.

## Workflow

`scripts/reproduce-release.py` requires a full commit object ID and a new absolute
output directory inside the real checkout. The managed workspace root is also
enforced when supplied by the launcher. No existing output is reused, replaced
or deleted. Invalid inputs fail before a build; later failures retain source,
logs and an unsuccessful manifest. The source archive rejects links and other
nonregular entries, so supported inputs must be self-contained regular files.

The script uses the exact already-installed Rust release from the selected
commit and runs the existing guarded Cargo entrypoint with `--locked --offline
--release`. It does not install dependencies, mutate Rustup, or download a target
toolchain. Existing dependency execution reviews remain applicable; versions
and features were not changed. Native C dependencies use the selected installed
compiler and archiver. Rust/C source and output paths are remapped, the source
date comes from the commit, and incremental/compiler caches are disabled.
Managed package/network policy is preserved; inherited or configured compiler
wrappers requiring separate review are refused instead of bypassed.

The manifest records source commit/tree/archive hash, source manifests/lock/UI
hashes, Rust launcher and actual installed compiler hashes, native tool versions,
OS/libc identity, Cargo configuration hashes and build arguments. The invoking
script is a separate input, with an explicit comparison against its copy in the
selected source when one exists. Cargo configuration contents and inherited
environment values are not dumped. The two build roots do not discover the
original checkout's Git metadata. Existing Cargo configurations remain recorded
external inputs; this is not a fully hermetic toolchain/sysroot rebuild.

## Proof target

The initial source target is
`6ce98c32a812c8b5f9a5bf32b1a29bc1331cc3ea`, containing the completed explicit retry
implementation. Its compiled Rust/UI source did not change in this task. That
commit predates the reproduction script; the recipe is identified separately by
its hash in the output manifest. The build ran in the managed untrusted browser
Linux container, with no live credentials or provider calls.

The exact invocation was:

```sh
CODEX_ALLOW_REVIEWED_PACKAGE_BUILD=1 python3 scripts/reproduce-release.py \
  --revision 6ce98c32a812c8b5f9a5bf32b1a29bc1331cc3ea \
  --output-directory /workspace/.codex-tmp/reproduce-release-6ce98c3
```

Input refusal checks covered a symbolic revision, missing commit, existing output
with a preservation marker, relative output and output outside the checkout.
All were refused; no output was created and the existing marker was unchanged.

Both clean release builds completed successfully. SHA-256 comparison and direct
`cmp` confirmed equal CLI and wrapper bytes; `sha256sum --check SHA256SUMS`
validated the copied artifacts. The selected target was
`aarch64-unknown-linux-gnu`, Rust/Cargo 1.94.1, Rust LLVM 21.1.8, Debian GCC
14.2.0-19, GNU binutils 2.44 and glibc 2.41-12+deb13u2. No Cargo configuration
files were present in this build's searched paths.

| Input/artifact | SHA-256 |
| --- | --- |
| Invoking reproduction script | `34cbcc2facfd2ddf855d45c1082da8e745de81b3646561324e8b73e077044b49` |
| Immutable source archive | `fcb7246f72f4c740c1872f1d7755bbb50efc58bccb779b2892fb5eab876bb07c` |
| `zrpc` | `de0165c5a8fe4570f09d3167d75cff91037005f1ddbc7e1b143a53c01d2d0500` |
| `zrpc-wrapper` | `8b79d58f498c0f186b4ab7416c57cc7d83f5331c11e213c051221575fa5453c6` |

The copied release CLI passed doctor/private-refusal, successful simulation and
wrong-key rejection smoke checks. A synthetic stdin marker was absent from
stdout/stderr; private mode remained blocked and no query was sent. The release
wrapper's help path passed. A separate inherited-compiler-wrapper check refused
the build without creating an output directory. Manifest assertions confirmed
both compared outputs and the false approval/private/deployment flags.
Documentation boundary checks passed. No Rust, UI or dependency input changed;
the existing full source suite was not rerun for this workflow-only addition.

Artifacts, source archive, both clean source/target trees, build logs and the
complete manifest remain under `.codex-tmp/reproduce-release-6ce98c3/`. They are
local ignored outputs, not published artifacts or signatures. The script was
unchanged after the successful comparison.

## Limits and remaining work

Only the native Linux environment and selected source are covered. An equivalent
Rust pin does not independently reproduce the C compiler, linker, libc, sysroot,
Cargo configuration or operator's managed container image. The committed
TypeScript bundle is hashed as an input; a clean frontend rebuild is not part of
this comparison. No reproducible guest image or hardware measurement follows
from matching CLI/wrapper files. All Phala private-mode gates and live external
cleanup evidence remain unresolved; this work does not enable deployment.
