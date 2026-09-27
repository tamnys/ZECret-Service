# Signed UKI verifier startup ELF checkpoint, 2026-09-27 UTC

This is an offline diagnostic for a supplied UKI and supplied public X.509
certificate. It does not review the signer, establish Secure Boot variables,
authenticate a GCP boot measurement, approve a release, or enable private mode.

The exact `sbverify` executable is from Debian `sbsigntool`
`0.9.4-3.2+deb13u1` in the signed `20260918T000000Z` snapshot. The already
reviewed direct-package lock pins its `.deb` SHA-256
`b5390c50b1970a98bd5dab6a4a8bba124e41708792da9ea62bb75c0522dd714f`.
Read-only ELF inspection of that executable found an x86-64 interpreter
`/lib64/ld-linux-x86-64.so.2` and direct dependencies `libcrypto.so.3` and
`libc.so.6`. Recursive ELF inspection of the package objects found
`libcrypto.so.3` also needs `libz.so.1` and `libzstd.so.1`; those libraries
need only `libc.so.6`. The direct dependencies contain no RPATH or RUNPATH.

The five runtime objects were extracted as data, without package installation
or maintainer scripts, from exact SHA-256-matched archives in the existing
194-package signed builder closure. The source-reviewed object identities are
compiled into `zrpc-uki-digest`:

`stage_sbverify_runtime.py` rechecks the source-reviewed closure-lock digest,
selected archive hashes, and exact member hashes before creating a new output
directory with no-follow, exclusive file writes. It relies on the separate
earlier signed-index authentication receipt; staging alone does not reverify
InRelease or Packages.xz.

| Object | Debian package | Object bytes | Object SHA-256 |
| --- | --- | ---: | --- |
| `ld-linux-x86-64.so.2` | `libc6` `2.41-12+deb13u4` | 225672 | `c8438e4fde1934e61c88311633f00949ff645d5c04cdb8671fa3d78164d2f307` |
| `libc.so.6` | `libc6` `2.41-12+deb13u4` | 1995216 | `9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92` |
| `libz.so.1` | `zlib1g` `1:1.3.dfsg+really1.3.1-1+b1` | 125376 | `85590dd58edf5445e18bc7193e5ebc01ac5841f1ae187e97705a662e90c6421e` |
| `libzstd.so.1` | `libzstd1` `1.5.7+dfsg-1` | 825336 | `27f07c9a49c2c956bcfb64cd4712976586a66facbf15fc7f09bc37413b5f2b21` |
| `libcrypto.so.3` | `libssl3t64` `3.5.7-1~deb13u2` | 6517312 | `8bb5f3fdffe280d4453eb79a4663c2c47af70b7c247fe2e94e2da703cee1fd3d` |

The signature command now requires all five exact objects. It checks their
sizes and hashes, seals them in Linux memfds, then uses the sealed interpreter
with explicit preloads for both loader inspection and signature verification.
The loader's initial object list must contain exactly those sealed fds.
OpenSSL configuration is directed to `/dev/null` and provider modules to a
nonexistent path. The old command shape without runtime objects fails closed.

The resulting `verifier_initial_elf_objects_pinned` field describes only the
loader-reported startup objects. The separate
`verifier_runtime_closure_checked` field stays `false`: loader inspection
cannot rule out later file opens or dynamic loads, and this diagnostic is not
an isolated guest runtime or a release approval. That remains a release
review item along with the actual Secure Boot and hardware evidence.

Managed-container checks: the crate's default locked test suite passed
(eight tests, one explicit pinned-runtime test ignored). The default tests
include rejection of the former command shape that used ambient libraries.
The ignored test was
then run with the six exact staged objects and passed. It exercised the Rust
API and CLI, the public signed EFI fixture, a changed PKCS7 signature, and
each of the five changed runtime objects. This run used a native arm64 Rust
test harness whose x86-64 loader and `sbverify` subprocesses ran through the
container's binary-format emulation; it is not a hardware boot. A direct
managed amd64 loader inspection separately returned only the five sealed fd
objects, no vDSO line or ambient file-backed object, exit 0, empty stderr.
The staging tool accepted the exact archives, rejected reuse of an existing
output directory, and rejected a byte-changed package before creating output.
Formatting and focused Clippy passed with the pre-existing
`manual_is_multiple_of` lint allowed; unmodified code in `lib.rs` triggers
that lint under the current Rust 1.94 toolchain. The separate managed amd64
Cargo build twice hit a QEMU `cc` linker SIGSEGV, once with a single build job;
that build result is not claimed as passing.
