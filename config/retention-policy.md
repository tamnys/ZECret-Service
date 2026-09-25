# M0 retention policy

The local fixture application does not intentionally save query history or remote diagnostics. CLI output remains under the operator's control. The local UI keeps its capability in memory, removes the bootstrap fragment from browser history and serves API results with `Cache-Control: no-store`.

There is no cloud service or persistence layer in M0. Future protected services may persist public chain state only. This policy is not proof that an operating system, browser, provider or compromised application retains nothing.
