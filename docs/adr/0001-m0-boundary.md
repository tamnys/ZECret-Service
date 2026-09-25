# ADR 0001: local foundation without private-mode authority

Date: 2026-09-25  
Status: Accepted for M0

## Context

The project requires client verification of both the approved execution environment and its live encryption key before any private query. The local dashboard must use the native client core. M0 precedes access to a selected production TDX deployment and completion of the Phala feasibility gates.

## Decision

Keep the simulation path distinct from the private client state machine. A synthetic result can exercise rejection handling and fixture dispatch but cannot construct private-channel authority. Private bootstrap exposes no RPC operation, and the M0 genuine-verification path fails closed.

Use typed protocol, policy and result models with independent transport, hardware, application, key-binding and chain-readiness fields. The CLI and loopback dashboard call the same Rust fixture core. The public site consumes only bundled examples. No browser reaches a cloud RPC service or silently connects to a local client.

Do not implement a speculative attestation wire format, custom cryptography, guessed SDK method, sample measurement allowlist or generic endpoint that attests caller-supplied keys. A later ADR must choose a maintained integration, pin a compatible production tuple, define the nonce/context/active-key encoding and vectors, and establish actual TLS possession. M0 is not that encoding decision.

Live private mode will require Tor for all application traffic, including bootstrap and any collateral retrieval. It will have no direct fallback, automatic trust update, TLS early data or verification inheritance on reconnection. The design's five-minute maximum verified-connection lifetime is a future policy bound, not evidence that M0 establishes a TLS session.

Provide offline cost/lifecycle decisions and fake-provider cleanup exercises before a cloud adapter. M0 cannot create resources. Future deployment requires an authenticated resource quote and deletion/deadline controls outside the guest, followed by explicit operator action.

## Consequences

The local interfaces are useful for protocol, UI and lifecycle development while cloud security properties remain unresolved. A simulation success must be described as fixture behavior; it provides no TDX, Tor, TLS, Zebra readiness, billing or deletion guarantee.

Customer wallet keys, accounts, real payments, general-purpose RPC forwarding, mutable runtime trust and browser-to-cloud private queries remain outside the API.
