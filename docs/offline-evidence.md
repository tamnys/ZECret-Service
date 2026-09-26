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

## Workload comparison

To compare supplied evidence with an explicit local policy:

```sh
./target/debug/zrpc inspect-workload --platform phala-dstack --quote quote.bin --collateral collateral.json --event-log event-log.json --app-compose app-compose.json --policy workload-policy.json
```

This command uses the same hardware and strict security checks before comparing workload evidence. It replays every runtime event with the maintained dstack `cc-eventlog` implementation pinned to commit `282eeb27d22d8f091ad0fa5a90e638f85cf68751`, including events after `system-ready`, and compares the result with authenticated RTMR3. It then checks the supported v0.5.9 KMS boot sequence and explicit expected measurements and configuration.

The event-log input is a JSON array of dstack `TdxEvent` objects. The app-compose input must contain the exact raw bytes measured by dstack, including whitespace. A Docker Compose YAML file or reserialized app-compose JSON does not substitute for those bytes.

The policy is a JSON object with every field below required. Hashes and identities use exact-length hexadecimal strings. There are no measurement defaults.

| Field | Representation |
| --- | --- |
| `schema_version` | Integer `1` |
| `mrtd`, `rtmr0`, `rtmr1`, `rtmr2` | 48-byte hashes |
| `os_image_hash`, `compose_hash`, `mr_kms` | 32-byte hashes |
| `app_id`, `instance_id` | 20-byte identities |
| `storage_fs` | `ext4` or `zfs` |
| `key_provider` | Object with `name: "kms"` and a nonempty expected `id` |

Supply expectations obtained independently from approved artifacts, launch settings and configuration. Copying presented quote or log values into the policy merely compares evidence with itself. The command does not calculate launch measurements or establish approval provenance. Matching `zfs` is supported as a diagnostic comparison; it does not make that storage configuration acceptable under this project's disk policy.

The output labels its policy source `explicit_local_input_not_release_approval`. Even when all comparisons match, freshness and live-key binding remain `not_checked`, and `private_accepted`, `query_sent` and `network_used` remain false. No result from this command enables a private query. The bundled dstack fixture supports replay compatibility tests only; it has no matching authenticated collateral tuple in this repository.
