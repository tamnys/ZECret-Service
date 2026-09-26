# Pure Phala lifecycle response projections — 2026-09-25

Implemented `crates/lifecycle/src/provider_wire.rs` as a pure decoding boundary.
The exported parsers take original response bytes and an explicitly supplied,
positive byte bound. They return only unauthenticated wire projections. They do
not connect to Phala, read credentials, construct requests, authorize deletion,
claim inventory completeness, create ledger usage records, join resource IDs, or
set cleanup/private-mode acceptance indicators.

The future caller must send `X-Phala-Version: 2026-06-23` and prove its request
scope independently. The version constant identifies the intended schema; bytes
alone cannot establish the actual request version or authenticated workspace.

## Exact source contract

The [OpenAPI at `5176d4c53fcee5aec3a8ccbbb05840a0a678c553`](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json)
provides inventory pagination constraints and `AppUsageResponse` /
`MeteredUsageResponse`. Its local reviewed copy has SHA-256
`9cad39ed1e415c9ab0c8a89eb5a0c19c797402453881faf6890aabbbe6f19e1e`.

The SDK at
[`ee941461e05004e4f80c26694f43c833bbc208b6`](https://github.com/Phala-Network/phala-cloud/tree/ee941461e05004e4f80c26694f43c833bbc208b6/js/src)
selects the 2026-05-22 CVM schemas for API 2026-06-23 and the three-layer current
user schema for `/auth/me`. Public immutable source was read, without using a
Phala account, API credential, or provider endpoint:

| SDK file under `js/src` | SHA-256 |
| --- | --- |
| `credentials/current_user_v20260121.ts` | `a1d95861e148957fea050b31f122739c7aa1763fd8ec29cb64af46bc0647657c` |
| `types/cvm_info_v20260121.ts` | `5b361ee29d32e9da22e4c90f0ed28cb69b69d467b2c3f3e3a7a28e4fa1b9902a` |
| `types/version-mappings.ts` | `f79e9f2a1bc7a96b6f13b5f1ed088636d3ff762110f5f924563618b785b0802e` |
| `actions/cvms/get_cvm_list.ts` | `77eabc6bd3f1764623a0ff011403f2540c1057de1ab5db31007c31faa0b142f3` |
| `actions/cvms/get_cvm_info.ts` | `c2aa6370946f08b9fa41ddcea9a6564267f55610825a070e61cb5ac35b312d46` |
| `actions/get_current_user.ts` | `0dffe3178297b5aebdca0b7aff410898f16ecfb0df4ce90d250c4777b3de0e09` |
| `types/cvm_id.ts` | `faf650078c06580746308cba862253aa00ef1142d34a4e52a44235a6391d6075` |

The parsers validate the subset of fields they retain, not every unused SDK
field. They consume unknown fields without retaining account/email/credit data,
deployment configuration, provider URLs, or unsupported optimistic indicators.
There is no `serde_json::Value` normalization step. Typed Serde fields reject
duplicate critical keys, including escaped equivalent spellings and duplicates
whose first value is null. A map-only visitor rejects positional arrays at every
projected object boundary. Invalid responses return static errors without the
provider body or its strings.

CVM `id` remains the exact returned string. There is no alias rewriting, UUID
normalization, synthetic `workspace_id` inventory envelope, or URL construction.
Missing/null per-CVM workspace stays unknown. The current-workspace identifier,
per-item workspace identifier, CVM `instance_id`, CVM `vm_uuid`, and usage
`instance_id` are not conflated. Numeric legacy CVM IDs are rejected. Identifier
strings are not proof of canonical target provenance or a billing join.

Usage `total` must equal the returned row count. It is not the number of rows
available across pages. Exact `cost` and `total_cost` numeric lexemes pass through
Serde `RawValue` to `ExactUsd`; quoted numbers, negative charges, invalid JSON,
and charges overflowing microUSD accounting are rejected. The retained exact
identity distinguishes different charges below one microUSD. `total_cost` stays
separate from row charges. Neither a short page, an empty page, a resource status,
nor `deleted_at` proves billing finality or disappearance of storage.

## Local proof scope

Four locally authored synthetic JSON fixtures and their hashes are recorded in
`tests/fixtures/phala-lifecycle/provenance.json`. They are shape examples, not
captured provider responses or genuine infrastructure evidence. Ten module tests
cover projection/minimization, distinct identities, exact exponent arithmetic,
duplicate keys, byte bounds, complete JSON consumption, object-only shapes,
critical type failures, sanitized errors, and returned-count semantics. Test
body bounds are the fixtures' actual byte lengths; they are not production
defaults. The documented inventory page-size range (1–100) comes from OpenAPI.

The implementation agent did not run builds or tests on the host. The root task
ran all ten module tests successfully in the managed container as part of the
62-test lifecycle suite and the full workspace suite; see
`durable-deletion-intent-verification.md`. No live HTTP/TLS client,
authentication, provider pagination sequence, usage mapping, or cleanup receipt
has been tested by this module.

The next layer still needs authenticated transport with an explicit body budget,
fixed request scope and original observation interval, complete pagination,
supported instance mapping, durable deletion intent, and separate operator
authorization. The unresolved live disk-deletion and billing-finality evidence
described in `records/live-lifecycle-adapter-plan.md` remains unresolved.
