# Protocol dependency execution review — 2026-09-25

Source review supports a scoped managed-container build opt-in for the seven
execution targets below, at these exact versions and resolved features. No
unexpected network calls, credential discovery or writes outside Cargo build
outputs were found in their reviewed execution paths. This record neither
changes the shared execution policy nor reports a successful build.

The inputs are the final locked package/feature metadata and copied registry
source trees in `.codex-tmp/protocol-dependency-review/`. The 64 new packages
contain three custom build targets and four procedural macro targets. The root
task separately checked archive hashes against the lock and registry, non-yanked
status and the workspace's seven-day release hold. `thiserror` and
`thiserror-impl` 2.0.21 failed that hold and were replaced before compilation;
this review applies to 2.0.20.

| Target | Resolved features | Reviewed execution and effects |
| --- | --- | --- |
| `equihash` 0.3.0 build | None | Entire `build.rs`: `main` does nothing with `solver` disabled. The optional `cc` invocation for `tromp/equi_miner.c` is not enabled. |
| `secp256k1-sys` 0.10.1 build | `alloc` | Entire `build.rs` and manifest: existing `cc` compiles bundled `lax_der_parsing.c`, `precomputed_ecmult_gen.c`, `precomputed_ecmult.c` and `secp256k1.c` into a static archive. It probes compiler flags and may retry compilation with bundled WASM headers after a failure. It reads `CARGO_CFG_TARGET_ARCH`; the WASM source branch is not used for the native Linux build. No bundled configure, autogen, shell or download script is invoked. `lowmemory` and `recovery` are disabled. |
| `thiserror` 2.0.20 build | None | Entire `build.rs` and `build/probe.rs`: writes generated `private.rs` under `OUT_DIR`; invokes Cargo's compiler/wrappers on the bundled probe with `--emit=dep-info,metadata`; removes only its `OUT_DIR/probe` directory; runs `rustc --version`; emits Cargo cfg/rerun directives. It does not execute the probe. |
| `getset` 0.1.7 macro | None | All production code in `src/lib.rs`, `generate.rs`, `macros.rs`: parses derive input/attributes and emits accessor tokens or compiler diagnostics. Its thread-local diagnostic state and panic recovery remain in memory. |
| `thiserror-impl` 2.0.20 macro | None | `src/lib.rs` and every declared module (`ast`, `attr`, `expand`, `fallback`, `fmt`, `generics`, `prop`, `scan_expr`, `unraw`, `valid`): parses and validates tokens, then emits error/display/conversion implementations. `env!("CARGO_PKG_VERSION_PATCH")` names its generated private module. Formatting and backtrace capture in output templates are generated application code, not macro-time I/O. |
| `visibility` 0.1.1 macro | None | Entire `src/lib.rs`: parses an item and requested visibility, changes that AST field, emits tokens/diagnostics. The optional `nightly` documentation include is disabled. |
| `zeroize_derive` 1.5.0 macro | None | All production code in `src/lib.rs` before its test module: traverses attributes/types and emits field zeroization/drop implementations. No external I/O is performed by these macro entrypoints. This does not prove the generated application's erasure behavior. |

The four macro manifests introduce no additional build script. Source inspection
covered entrypoints, declared production modules, imports, conditional paths and
generated-token templates, with cross-checks for process, environment,
filesystem, network, include and unsafe/FFI operations. Existing locked helpers
(`cc` 1.5.1, `proc-macro2`, `quote`, and the already-present Syn versions) were
not re-audited. Cryptographic algorithm correctness, the C implementation's
runtime behavior, compiler security and dependency-owned test programs are
outside this execution review.

The native build necessarily executes the managed C compiler/archiver and Rust
compiler. The scripts trust Cargo's environment: `OUT_DIR`, compiler paths,
wrappers and flags. In particular, the `thiserror` probe uses `RUSTC_WRAPPER`,
`RUSTC_WORKSPACE_WRAPPER`, `TARGET`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTC_STAGE` and
`RUSTC_BOOTSTRAP`; these are build inputs, not a sandbox enforced by that crate.
The source result therefore supports only the managed container's scoped
opt-in, not unrestricted execution with attacker-controlled build environment.
Changed versions, features or toolchain wrappers are outside this record.

Archive SHA-256 values from the root task's registry/lock/archive cross-check:

| Package | SHA-256 |
| --- | --- |
| `equihash` 0.3.0 | `306286e8dcc39ab3dfceb74c792ce8baffdab90591321d3ffaae64829734c37f` |
| `getset` 0.1.7 | `6cf442baaabe4213ce7d1239afc26c039180b6456da2cededa316ae2c8a77a77` |
| `secp256k1-sys` 0.10.1 | `d4387882333d3aa8cb20530a17c69a3752e97837832f34f6dccc760e715001d9` |
| `thiserror` 2.0.20 | `ec86235f5fcc2a73650310756d2ac5b138a5780bbbdfae3eeccec992c435ba4f` |
| `thiserror-impl` 2.0.20 | `bc04cd3e1236dd4a98afca4569f2deb3f120e5422a4023be2cb683f8486292af` |
| `visibility` 0.1.1 | `d674d135b4a8c1d7e813e2f8d1c9a58308aee4a680323066025e53132218bd91` |
| `zeroize_derive` 1.5.0 | `3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328` |

Reviewed metadata snapshot SHA-256:

```text
7c320bc48fc45a5c777b9dd8bc441764c549eb48542b5856e0ca3b52da7f3565  .codex-tmp/protocol-metadata.json
baaeed5e1a0d4ae6d8295670158f7b30d295e1f71bce1f980a88976b12a2c602  .codex-tmp/protocol-new-packages.json
```

No build, install, container launch, cloud operation, credential access or shared
policy change was performed by this review. Root-managed compilation and parser
tests remain separate evidence.
