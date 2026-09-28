# Managed Tor local diagnostic, 2026-09-27

This is partial transport evidence. The Rust `ManagedTor` test has now run
with the authenticated Tor executable on native Linux. It does not establish
that a Tor circuit carried traffic or that private mode is approved. The
packaged approved-release catalog remains empty.

## Authenticated executable

Inside the managed `linux/amd64` container, the project's pinned
`debian_snapshot.authenticated_index_bytes` path checked the reviewed Debian
trixie `20260918T000000Z` `InRelease` signature with the pinned signer
keyring and gpgv binary, then checked the SHA-256 of its
`main/binary-amd64/Packages.xz` index. The index record selected:

| Input | Identity |
| --- | --- |
| `InRelease` SHA-256 | `0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675` |
| `Packages.xz` SHA-256 | `7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498` |
| Package | `tor 0.4.9.11-0+deb13u1 amd64` |
| Archive | `pool/main/t/tor/tor_0.4.9.11-0+deb13u1_amd64.deb`, 2,087,008 bytes |
| Archive SHA-256 | `2381888dc083316fa59a675434decdf94e3869c34eb1e17a6b54fc9d5a041b98` |
| Extracted `usr/bin/tor` SHA-256 | `2e0a57ea04c80865fd38e9bbde7219ed19d1b5c34cc5ed5b3f98cc3a6adf19ef` |

The archive was fetched from that exact snapshot and rechecked against the
signed record. `dpkg-deb --fsys-tarfile` and `tar -xOf - ./usr/bin/tor`
yielded the executable bytes; no Debian package scripts ran. Full
`dpkg-deb -x` hit host-mounted-workspace permissions on other archive
members, so it was not treated as a complete package installation. The
extracted executable reported Tor 0.4.9.11 and linked against the managed
container's Debian 13 libraries. The seven-day snapshot hold had passed;
this check did not appraise Tor's entire runtime dependency closure or current
security advisories.

## Real Tor socket/protocol observation

A local Python diagnostic started that executable with the exact torrc
directives and command-line form used by `ManagedTor::launch`: empty
`--defaults-torrc`, private `DataDirectory`, one
`SocksPort unix:<private socket> IsolateSOCKSAuth`, disabled control/DNS/
transparent/HTTP-tunnel ports, `ClientOnly 1`, `RunAsDaemon 0`,
`NoExec 1`, and `SafeLogging 1`. Its only destination was a local
127.0.0.1 TCP listener. The observed Unix SOCKS exchange was:

- Tor created a Unix socket and remained alive.
- Tor selected SOCKS5 username/password method `0x02` and accepted the
  fresh isolation credential.
- A CONNECT request to the local listener returned non-success code `0x01`.
- The local TCP listener accepted zero connections.

This proves the observed Tor configuration and local rejection behavior in
the managed x86_64 QEMU container. It does not prove a Tor circuit or remote
endpoint connectivity.

## Native Rust child test

[GitHub Actions run 36435626109](https://github.com/tamnys/ZECret-service/actions/runs/36435626109)
checked commit `611e44683be100008a161ad78d7733e150537fcf` on native x86_64
Linux. The job passed both live Cargo source policies, checked the reviewed
dstack Git object, authenticated the signed Debian snapshot, and staged the
same exact Tor and libevent ELF hashes listed above. It fetched locked Cargo
dependencies in the pinned Rust image, then built and ran the opt-in
`managed_child_rejects_loopback_destination_without_direct_fallback` Rust
test in that image with networking disabled. Tor reported version 0.4.9.11;
the test passed (one passed, zero failed, 45 filtered out). It asserted that
the Rust-managed Tor child rejected a loopback CONNECT without reaching the
local TCP listener and remained live afterward.

The local ARM managed container separately passed the 44 non-ignored
`zrpc-transport` unit tests and three Tor-staging source-pin tests; formatting
passed. The native run proves this one local fail-closed behavior, not a Tor
circuit, TDX boot, release approval, or a production private query.
