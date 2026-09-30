# M0 retention policy

The local fixture application does not intentionally save query history or remote diagnostics. CLI output remains under the operator's control. The local UI keeps its capability in memory, removes the bootstrap fragment from browser history and serves API results with `Cache-Control: no-store`.

There is no cloud service or persistence layer in M0. The original free-service baseline permits only public chain state on a protected persistent disk; the separate testnet payment POC exception appears below. This policy is not proof that an operating system, browser, provider or compromised application retains nothing.

## Separate ticket-required testnet payment POC

An explicitly reviewed ticket-required testnet deployment may retain the following payment state in separate, owner-only SQLite stores and private transfer files outside the repository. This exception does not apply to M0 or a free demonstration deployment:

| Store | Permitted records | Retention |
|---|---|---|
| Customer's native client | Pending purchase identifiers, quantities, blinded requests and blinding state; finalized bearer tickets and their available, uncertain, or spent state. | Across ordinary restarts until the customer deliberately removes the local store. |
| Operator-controlled issuer | Purchase identifiers, authorized quantities, commitments to blinded requests, and the corresponding blind issuance responses. | Across ordinary restarts for idempotent issuance and recovery, until deliberate POC teardown. |
| Client/operator transfer files | Versioned blinded-request batches and blind-signature response batches, with their purchase identifier, issuer key identifier, and request commitment; never finalized tickets. | In explicitly selected owner-only directories until deliberate removal after collection or POC teardown. |
| Protected RPC redeemer | Issuer key identifier and spent-ticket marker pairs only. | Across ordinary restarts while the corresponding issuer key is trusted; removing markers earlier would permit replay. |

The issuer must not receive finalized tickets or private queries. The redeemer must not retain purchase references, request bodies, transaction selections, responses, IP addresses, or per-request timestamps. Neither profile authorizes application query histories, query-to-payment mappings, bearer-token logs, or customer accounts. Ordinary command output may show ticket counts but not ticket contents or issuer secrets.

The issuer private key is testnet-POC-only and remains outside the repository and redeemer. A production release must not trust it. The POC specifies no automatic expiry or secure-erasure claim and does not defend against malicious disk rollback or restoration of old backups. Provider and customer-device records remain outside this application policy.
