# Website implementation handoff

Copy the prompt below into the website chat. Inspect the current repository and payment work before treating any planned interface as implemented.

---

Build a simple public website for **ZECret service**, our experimental private Zcash testnet RPC project. Use **Cloudflare Workers Free with Workers Static Assets**, a TypeScript Worker, and Cloudflare's provided `workers.dev` address. I do not want to buy a domain or enable paid services. Keep the design simple; we will iterate later. Implement the backend needed for the features we actually demonstrate.

The repository is `/Users/j/Code/phala-zcash-rpc`. Follow its workspace instructions and coordinate with the separate payment implementation chat. Read `README.md`, `SECURITY.md`, `records/input-design.md`, `config/retention-policy.md`, the existing `ui/public/` and `ui/local/`, and the current CLI/client/transport interfaces. Check the active payment implementation and its verification report rather than assuming this prompt describes completed functionality.

## Product and privacy boundary

The primary goal is to help developers understand the service and use its native RPC client. Optional payment demonstrations support that goal.

The private path is:

`native Rust client → Tor → retained attested TLS connection → measured RPC wrapper → loopback Zebra testnet node`

The native client checks the approved release, hardware, measured workload, freshness, and TLS binding before sending a query. It uses one query per verified connection. The CLI and bundled local dashboard share the Rust core. A browser visiting the public website cannot establish this private path on its own.

The public website is outside the private path. It must not proxy private RPC calls, redeem tickets, collect transaction selections, or silently connect to localhost. A website badge cannot authorize a release. Website-delivered configuration cannot silently replace the native client's trusted release or issuer policy.

Do not add accounts, email/password signup, OAuth, API keys tied to customers, cookies for identity, analytics, or wallet connections. Do not accept wallet seeds, spending keys, viewing keys, bearer tickets, ticket stores, or client blinding state. Do not promise absolute anonymity, deletion, or privacy against all traffic analysis. Cloudflare handles ordinary website traffic and can observe visitor metadata; running the CLI through Tor does not anonymize the user's browser.

## What the first website should offer

- A clear landing page explaining what the service does, its testnet/experimental status, and the separate roles of Tor and attestation. Use “Try the demo,” “Run the native client,” and “Read the privacy model” as the main actions.
- A developer quickstart with commands verified against the current CLI, the supported read-only method list, installation/build instructions, and links to source and actual release artifacts/checksums when available. Do not invent downloads or call an unapproved build approved.
- A public interactive example using synthetic fixtures. Let visitors choose canned scenarios such as a successful example, a release or attestation rejection, and a simulated ticket replay rejection. Clearly label fixture results and payment simulations. Do not provide a transaction-ID field wired to a public RPC endpoint.
- Separate status indicators for release approval, transport/attestation verification, payment implementation, and chain-data provenance. Fixture data, an operator-reported status, and locally verified live results are different states. An unavailable approved deployment must produce an honest unavailable state, not a successful mock presented as live.
- A concise explanation of prepaid credits: buy a batch, keep tickets locally, spend one per admitted request without making an on-chain transaction for every query. Explain the local setup and demonstrate the journey with synthetic examples.
- A privacy page explaining the public-site boundary, the local dashboard, the payment model, retained records, and limitations. Link to the repository's authoritative design rather than overpromising.

## Payment integration contract

As of 2026-09-30, the isolated `codex/payment-tickets` branch implements the CLI-first payment POC using publicly verifiable Privacy Pass type-2 blind RSA tickets under RFC 9578 §6. It includes `zrpc payments prepare`, `prepare --resume`, `pending`, `mock-settle`, `collect`, `balance`, and `init-redeemer`, plus a ticket-store option on native `zrpc query`. The separate `codex/payment-integration-trial` branch combines this with current deployment work and stages a ticket-required GCP image candidate. Neither branch is merged into main, and no paid image has been built, approved, or accepted against live testnet data. Inspect the current branch, flags, and deployment state before publishing commands or marking paid RPC available.

The POC simulates settlement using private file exchange with an operator. It does **not** accept real ZEC or actual testnet ZEC payments yet, and it does not expose a public minting endpoint. `mock-settle` is an operator-side action; never make it an unauthenticated website operation. The browser may illustrate this workflow using fixtures and direct users to native instructions. It must not upload or hold real ticket material.

The local POC uses separate transactional SQLite databases:

- Client: pending purchases, blinding state, finalized tickets, and available/uncertain ticket state, in an explicitly selected private directory outside the repository.
- Issuer: authorized quantity, blinded-request commitments, and repeatable issuance responses. It never receives finalized tokens.
- Redeemer: issuer-scoped spent-ticket markers only, without purchase references, query content, IP addresses, or per-request timestamps.

Tickets use a common trusted testnet issuer configuration without per-customer metadata. A ticket is charged on admission before the node query; node errors or a lost response can consume it. The native client must not automatically retry uncertain tickets or spend a replacement. There are no refunds or persisted response replay in this POC. Cryptographic blinding does not eliminate timing, network, or small-crowd correlation. Ordinary restart safety does not establish protection against malicious disk rollback.

A future payment UI belongs in the bundled local dashboard, where the native core can own ticket state. If we later add actual shielded testnet ZEC settlement or online issuance, propose that as a separate extension with its privacy and recovery design. Do not quietly add it to this website or give Cloudflare the issuer private key.

## Suggested implementation

Start with the existing public-site assets and a small TypeScript frontend. Use Vite only if needed for interactive bundling; avoid introducing a large framework for this initial design. Bundle fonts, scripts, and styles locally. Preserve the bundled native dashboard as a separate application.

Serve assets with Workers Static Assets, with a small same-origin Worker API for public demo information. Suggested API responsibilities are public capabilities/configuration, fixture scenario results, and explicitly sourced deployment status. Choose exact routes and schemas after examining existing code. Public configuration is informational; it is never an approval authority.

Keep responses deterministic and fixture-backed until there is a reviewed source for live public status. Reject arbitrary upstream URLs and unsupported methods. Do not build a generic proxy. Do not infer hardware verification from an HTTP health response. Fail visibly when status is unavailable.

No database is necessary for a fixture-only site. If an agreed feature actually requires persistence, evaluate D1 or SQLite-backed Durable Objects within the currently documented free plan, and justify the data being stored. Do not move native ticket state, issuer state, or private redemption records into Cloudflare. Avoid adding a hosted service solely to make the diagram look complete.

Use a restrictive CSP, no third-party scripts, no background localhost probing, no cross-origin API access, and no request-body or credential logging. Document the distinction between application logging choices and provider visibility. Do not add user identifiers for rate limiting or analytics. Cite platform limits when configuring resource limits; do not invent purchase quotas, prices, or subscription periods.

## Completion

Build and test through the managed container with exact dependencies and committed lockfiles. Test API validation and error states, inspect browser network traffic, and check desktop and mobile layouts. Prove the fixture demo does not send private queries, contact localhost, or collect ticket/wallet data. Confirm missing backend/status data is represented honestly.

Prepare a working preview, deployment configuration, and concise free-plan instructions. Publish to the provided `workers.dev` URL using an explicitly selected Cloudflare account when available; never upgrade the plan or purchase a domain. If account access is missing, finish the reviewable local implementation and report the specific deployment dependency.

Resolve straightforward implementation choices yourself. Ask me about product choices only when they materially change the user journey or privacy model. Keep open questions about approved deployments, release distribution, actual testnet settlement, and future native-dashboard integration explicit.

Check current official platform documentation before choosing services or limits:

- [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/)
- [Workers pricing and free-plan allowances](https://developers.cloudflare.com/workers/platform/pricing/)
- [workers.dev deployments](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
- [Privacy Pass publicly verifiable issuance](https://www.rfc-editor.org/rfc/rfc9578.html#section-6)
