# M0 implementation contract

Provide a local, public-repository-compatible Rust workspace with a strict protocol, separated simulation and private-client types, CLI, bundled TypeScript dashboard, fixture-only public site, and offline lifecycle tools. CLI and dashboard share the Rust core. Simulation cannot authorize a private query. M0 creates no cloud resources and exposes no deployment implementation.

Implementation order:

1. Define bounded RPC input, release-policy and verification-result models; make private authorization unavailable until a reviewed genuine verifier exists.
2. Add synthetic node fixtures and rejection scenarios; exercise the same core from CLI and loopback UI.
3. Protect local APIs with per-launch capability, exact Host/Origin checks and bundled assets; keep the public site static.
4. Implement precise offline cost plans, deadline/cost deletion decisions and a fake-provider cleanup exercise before any deployment adapter.
5. Run negative protocol/client/UI/lifecycle checks and desktop/mobile browser checks in the managed container.

Live TLS, dstack, quote verification, Tor dialing, Zebra and cloud operations belong to later milestones. They require pinned maintained implementations and Gates A–E; M0 does not substitute mock outcomes for them.
