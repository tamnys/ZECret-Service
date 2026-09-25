# Native session inspection record

The shared native client now connects the existing SOCKS/TLS bootstrap and public
attestation exchange to the local hardware/workload inspector. The CLI exposes
`inspect-endpoint` with required endpoint hostname, endpoint port, numeric loopback
SOCKS address, supplied collateral, raw app-compose and explicit workload policy.
It parses options and local policy before dialing. A fresh OS-random isolation
credential is generated per invocation and never returned or logged.

Received evidence retains its original challenge, TLS exporter and connection
lifetime internally. Consuming inspection uses the current clock and calls the
maintained QVL with Intel's production root and the existing strict security
policy. Only that successful authentication/appraisal callback may compare the
signed TDX REPORTDATA with the retained exporter. Echoed report-data strings and
VM configuration are not authority inputs. The original session lifetime, observed
driver state and clock are checked before and after CPU work. The client also
applies the design §7 five-minute budget from before dialing; a post-CPU elapsed
check covers synchronous work that an async timeout cannot preempt.

The report's `authenticated_report_data_match` is a diagnostic comparison, not
proof of approved release ownership. Release-policy provenance, approved workload
ownership, freshness and live-key binding remain `not_checked`. No verified channel
or continuing query capability is returned, and consumption closes the connection.
Every output retains `private_accepted: false` and `query_sent: false`. The CLI
cannot attest to the identity of the local SOCKS process and reports that fact.
The UI is unchanged and still uses only the fixture client.

The fixture uses a local Python-stdlib SOCKS responder and real TLS 1.3, with
public test key material already in the repository. It is not Tor or a Phala
deployment. The served historical Intel quote/collateral are real upstream
fixtures; the workload policy, endpoint and other response fields are synthetic
rejection inputs. Current-clock verification rejects the expired evidence. Tests
assert nonce-only HTTP, SNI/ALPN, stream-isolation authentication, connection closure
without a second request, no environment-proxy fallback, pre-dial option/policy
rejection and unavailable-SOCKS failure. No customer input or cloud call is used.

The executable was also run under syscall tracing restricted to `socket,connect`.
That run observed exactly one connection to the configured IPv4 loopback SOCKS
listener and no UDP/IPv6 sockets or other connections. This proves the exercised
fixture path only, not a real Tor circuit, every possible runtime path or cloud
privacy. No payload, TLS secret, file read, trace of cookies or browser state was
captured. The temporary connect-only trace was removed with its test directory.

The trace binary came from signed managed Debian snapshot metadata for
`20260918T000000Z`, package `strace 6.13+ds-1`, arm64. The package SHA-256 was checked
against `d793af70a104eb0bd5be466c3043b512f549e7cb27971320a7c9b8f4c6165e55`
before `dpkg-deb -x` extraction under ignored workspace state. No package was
installed, no maintainer hook ran and no shared container policy changed.

No registry package version changed. The new direct references reuse pinned
getrandom, hex, Tokio, serde and chrono entries already in Cargo.lock. Chrono uses
only its `std` feature for the separate UTC schedule generator, without its clock
feature. The scoped offline lock update reported zero new package versions.

Focused tests initially exposed an incorrect expectation in two new historical
binding tests: the real fixture's signature verifies, but strict security appraisal
rejects it. The production policy was retained. Historical tests must demonstrate
that rejection prevents authenticated REPORTDATA comparison; isolated comparator
tests describe synthetic byte equality only. There is no authenticated positive
quote/event-log/approved-policy/session tuple available here.

Final managed-container `bash scripts/check.sh` passed: 123 workspace unit tests,
15 compile-fail documentation tests, 14 standalone runtime-guard tests, the
verifier feature/checksum checks, all CLI checks, formatting and CLI/example
builds. The additional connect-only syscall fixture run passed. The user-docs
boundary check passed. No UI assets or flows changed, so browser layout checks
were not repeated in this pass.

Live hardware, approved production boot configuration, no guest administration,
KMS/disk trust, live Tor, installed external deletion jobs and independently
confirmed billing cleanup remain unresolved. No resources or charges were created.
