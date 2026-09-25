# Offline quote inspection

The CLI can inspect an Intel quote and supplied signed collateral locally:

```sh
./target/debug/zrpc inspect-quote --quote quote.bin --collateral collateral.json
```

Use exact, unpadded binary quote bytes and the `dcap-qvl` `QuoteCollateralV3` JSON representation. Files are untrusted evidence, not release-policy inputs. The command performs no collateral fetch, endpoint connection, DNS lookup or RPC. It uses the customer's current system clock, Intel's production root and the pinned `dcap-qvl` 0.6.3 Ring backend. There is no runtime custom-root, historical-time, debug, grace-period or TCB override.

The report separates cryptographic verification from security appraisal. A valid signature chain does not imply acceptable platform status. Appraisal uses the upstream strict policy, requires TDX, and rejects advisory IDs because the project has approved no exceptions. The strict policy rejects non-UpToDate status and true dynamic-platform, cached-key and SMT flags. Passing this diagnostic policy is not approval of a workload or release.

`private_accepted` and `query_sent` remain false. Workload policy, challenge freshness and live TLS-key ownership remain `not_checked`. The diagnostic returns no channel capability and cannot enable `zrpc query`. Upstream errors, unique platform identifiers and raw report data are omitted from output.

The verifier is compiled without its `report` feature, which provides the PCCS HTTP client, and without the dangerous TCB-override feature. `scripts/check-verifier-features.py` checks the resolved dependency features, package checksum and upstream fixture hashes. New network transport integration must preserve this boundary. [Pinned upstream feature definitions](https://github.com/Phala-Network/dcap-qvl/blob/e61f4fba357e96d68fc7d7be71635049841824fb/Cargo.toml).

The bundled `tests/fixtures/dcap/` files contain historical upstream hardware evidence under its MIT license, not evidence from this project's deployment. Its earliest collateral expiry is July 19, 2025. Current-clock inspection therefore rejects the exact quote for expired collateral. The upstream file also has trailing padding: the derived `tdx_quote.exact.bin` contains only bytes consumed by the maintained quote decoder, with both hashes and the derivation recorded. The production command rejects padding instead of silently trimming it. Historical validity is exercised only inside unit tests using the fixture's documented reference time; there is no production clock override. A positive historical cryptographic test cannot satisfy the genuine private-mode acceptance policy.

The customer OS and clock remain trusted. Collateral expiry checks do not prove a fresh quote or prevent replay. Gates A–E still require the selected deployment, independent workload policy, channel binding, administration/storage evidence and operator lifecycle proof.
