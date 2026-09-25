# Ephemeral TLS bootstrap source research — 2026-09-25

Scope: select a maintained certificate generator for the local public-attestation
diagnostic, with an in-memory server-generated key. This is dependency/API
research, not a certificate-authority, attestation, hardware, key-erasure, or
private-mode acceptance claim. No dependencies were installed and no code,
container, guest, or cloud operations were run by this research task.

## Selected dependency

`rcgen = { version = "=0.14.10", default-features = false, features = ["ring", "zeroize"] }`.
The `ring` feature implies `crypto`; it does not activate PEM, AWS-LC, FIPS,
or the optional X.509 parser. `zeroize` exposes the narrow explicit buffer-wipe
implementation described below and uses the already locked zeroize 1.9.0.
Official source requires Ring `^0.17` and
rustls-pki-types `^1.4.1`, compatible with the project's locked Ring 0.17.14
and rustls-pki-types 1.15.1 used by Rustls 0.23.45. Rcgen's declared Rust
minimum is 1.88, below the requested managed toolchain 1.94.1 and the current
workspace declaration 1.89. Actual locked compilation belongs to implementation
verification, not this source assessment.
[Feature manifest](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/Cargo.toml#L13),
[workspace dependencies/MSRV/license](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/Cargo.toml).

The crate is MIT OR Apache-2.0. Primary registry metadata reports non-yanked,
published **2026-08-28 21:30:01 UTC**, archive SHA-256
`8774e05a7d0de114588e6a28fe7e71694b82614ed569d86d8b389dfbc98b8ad8`.
It passes the existing seven-day workspace release hold as of 2026-09-25.
Official annotated tag `v0.14.10`, tag object
`21a47bba4e4b87710d45b79f2492296dd44d8bf2`, resolves to source commit
`f4a3b165c467c070d5c74b86acc2c3f0a0be10ab`. GitHub release publication is
2026-08-28 21:38:07 UTC; it is marked stable.
[Registry record](https://index.crates.io/rc/ge/rcgen),
[tag object](https://api.github.com/repos/rustls/rcgen/git/tags/21a47bba4e4b87710d45b79f2492296dd44d8bf2),
[official release](https://github.com/rustls/rcgen/releases/tag/v0.14.10).

## Actual API and intended handling

The source exposes the following operations; these are API references, not a
complete server configuration or a new verifier:

```rust
let key = zeroize::Zeroizing::new(
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?
);
let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])?;
let certificate = params.self_signed(&*key)?;
let private_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialized_der())
);
let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&private_key_der)?;
let certified_key = rustls::sign::CertifiedKey::new(
    vec![certificate.der().clone()], signing_key
);
certified_key.keys_match()?;
// Existing restricted TLS server builder installs SingleCertAndKey from this.
```

`KeyPair::generate()` also chooses P-256/SHA-256; the explicit algorithm call
documents that choice. Ring's `SystemRandom` and `EcdsaKeyPair::generate_pkcs8`
perform key generation; the application does not invent an RNG or signature
scheme. Rcgen signs the X.509 certificate with that same key. The selected
implementation borrows its PKCS#8 bytes into Rustls's maintained ECDSA loader,
then explicitly checks certificate/key consistency with `keys_match()` before
installing the resolver. Its Ring P-256 signing implementation exposes the
public key needed for this comparison. No key is supplied by an RPC caller,
persisted, PEM-encoded, logged,
or returned from the listener API. The server config retains the signing key
in process memory for its lifetime.
[Key generation](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/key_pair.rs#L83),
[self-signing](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/certificate.rs#L150),
[Rustls ECDSA loader](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/crypto/ring/sign.rs#L41),
[maintained key match check](https://github.com/rustls/rustls/blob/2976d90fd1c2db6b518700dd101b714069cfcb17/rustls/src/crypto/signer.rs#L155).

The fixed localhost SAN describes this local diagnostic. `IsCa::NoCa` is the
upstream default. Neither the self-signature, SAN, nor subject name establishes
an approved environment or independently trusted server identity. Keep the
existing restricted bootstrap verifier and session/exporter attestation policy;
do not install this certificate into a trust store or use it as private-query
authority.

## Validity decision

`CertificateParams::new` inherits upstream validity **1975-01-01 00:00:00 UTC
through 4096-01-01 00:00:00 UTC**. The implementation decision for this local
diagnostic retains those documented defaults, avoiding a new unapproved TTL,
clock-skew allowance, or caller option. They are untrusted diagnostic metadata,
not the ephemeral key's permitted lifetime, quote freshness, or VM deletion
deadline. Freshness and session lifetime remain in the existing attestation
policy, including its monotonic 300-second connection limit; certificate dates
do not replace those checks.
[Defaults](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/certificate.rs#L81).

If a future independently approved policy supplies explicit UTC calendar dates,
the actual API is assignment to public `params.not_before` / `params.not_after`
fields of type `time::OffsetDateTime`; `rcgen::date_time_ymd(year, month, day)`
constructs midnight UTC without a direct time-crate import. This helper panics
for invalid dates and is suitable only for validated/fixed dates, not unchecked
input. The certificate serializer writes those values; the caller must enforce
its policy and interval ordering. This research introduces no expiry duration.
[Fields](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/certificate.rs#L56),
[UTC helper](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/certificate.rs#L1034).

## Key-memory limits

Rcgen `KeyPair` stores both the backend key and a private PKCS#8 `Vec<u8>`.
`serialize_der()` clones that vector; `serialized_der()` returns a borrowed
slice. Even consuming conversion to `PrivatePkcs8KeyDer` internally calls the
cloning method. Its `Debug` implementation elides the serialized key, but the
application should avoid logging key-bearing objects or raw buffers entirely.
[Stored representation](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/key_pair.rs#L62),
[DER accessors](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/key_pair.rs#L431),
[consuming conversion](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/key_pair.rs#L604).

There is no automatic `KeyPair` drop-wipe in the inspected source. Optional
`zeroize` enables an explicit `Zeroize` implementation that wipes only
`serialized_der`; it does not wipe the backend key. Enabling that feature alone
does not call the method on drop. The locked rustls-pki-types 1.15.1 likewise
provides explicit zeroization of owned private DER buffers, not a `Drop` wipe
in the inspected source. Ordinary ownership/drop is therefore not evidence
that every private-key copy was erased. The selected implementation wraps the
rcgen key in `zeroize::Zeroizing` so its serialized vector's explicit wipe runs
when that wrapper drops, including ordinary error returns. It uses the borrowed
DER accessor rather than making an additional serialized-key clone for Rustls.
That narrow buffer cleanup does not erase Ring's signing key, temporary backend
representations, or every process-memory copy. No perfect-erasure claim is made;
the implementation retains maintained Ring/Rustls loading and signing methods.
[Rcgen zeroization scope](https://github.com/rustls/rcgen/blob/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab/rcgen/src/lib.rs#L862),
[PKCS#8 wrapper behavior](https://github.com/rustls/pki-types/blob/e29ad15465126acc089b39611bcec85e27ce0817/src/lib.rs#L450).

## Exact active dependency execution review

Root's managed dependency receipt
`records/listener-dependency-receipt.json` records 21 lock additions with matching
registry/archive/lock checksums, non-yanked status, and the existing seven-day
release hold. This research read that receipt, the saved active normal/build
tree, Cargo target metadata, and cached rcgen/yasna source; it did not execute
Cargo or compile dependencies.

Only these seven additions occur in the selected server's normal/build tree:

| Package | Active features | New build script / procedural macro |
|---|---|---|
| `rcgen 0.14.10` | `crypto, ring, zeroize` | None |
| `time 0.3.55` | `alloc, std` | None |
| `deranged 0.5.8` | `default` | None |
| `num-conv 0.2.2` | none | None |
| `powerfmt 0.2.0` | none | None |
| `time-core 0.1.9` | none | None |
| `yasna 0.6.0` | `default, std, time` | None |

The evidence is `.codex-tmp/listener-active-tree.txt`, produced by the managed
`cargo tree -p zrpc-server -e normal,build` selection, plus the target and build
dependency arrays in `.codex-tmp/listener-metadata.json`. Each of the seven has
no `custom-build` or `proc-macro` target and no build dependencies. Cached
normalized rcgen and yasna manifests both explicitly set `build = false` and
declare ordinary library targets. Neither source archive has a build script.
The cached rcgen VCS record matches the official release commit above.

The wider metadata/lock closure is not proof of active features. In particular,
`x509-parser`, `oid-registry`, the ASN.1 derive/implementation macros,
`displaydoc`, and `time-macros` do not occur in this selected active tree. Their
presence in the lockfile does not authorize executing them under an expanded
feature selection. Already locked Ring and zeroize are reused; this change adds
no new active build script or procedural macro. This is a build-surface check,
not an exhaustive runtime vulnerability audit or a successful compile/test.

Yasna 0.6.0 is non-yanked, published 2026-03-14 04:29:57 UTC, declares Rust 1.60,
and has archive SHA-256
`b5f6765e852b9b4dc8e2a76843e4d64d1cea8e79bcde0b6901aea8e7c7f08282`.
The downloaded archive's `.cargo_vcs_info.json` identifies commit
`3c7f2ba61cfb59c478137051a7e79ad8af0e2247`, with an empty repository subpath;
the official immutable manifest at that commit confirms version 0.6.0 and
MIT OR Apache-2.0 licensing. This supplies exact source mapping without assuming
that an absent release tag identifies its source.
[Rcgen immutable tree](https://api.github.com/repos/rustls/rcgen/git/trees/f4a3b165c467c070d5c74b86acc2c3f0a0be10ab?recursive=1),
[Yasna registry metadata](https://index.crates.io/ya/sn/yasna),
[Yasna immutable manifest](https://github.com/qnighy/yasna.rs/blob/3c7f2ba61cfb59c478137051a7e79ad8af0e2247/Cargo.toml).
