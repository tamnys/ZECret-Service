# Operator workflow

Start locally with `zrpc doctor`, a simulated CLI query and `zrpc demo`. M0 never creates billable resources. Run `bash scripts/check.sh --browser` inside the managed browser container to exercise the local interfaces. The browser harness uses that container's pinned Playwright installation and stores screenshots only under `$CODEX_TMP_DIR/playwright/`.

For cost arithmetic, copy `deploy/plan.fixture.json` and replace the quote source, rate, inventory, fee, funding and evidence fields with an independently obtained operator quote. `plan` does not authenticate those assertions. Its output remains `arithmetic_only: true` and `deployment_enabled: false` even with operator input. Existing resource cost is projected from evaluation through deletion, including any wait before the new VM starts.

No production image, verifier/SDK compatibility tuple, measurements or attestation-key encoding is approved. Complete [Gates A–E](phala-feasibility.md) before enabling a protected service. The public pricing baseline is $40.84416; actual inventory and checkout control the cost. The hosting clock includes synchronization and testing.

The operator has capped the whole experiment at **$50**, including setup tests and deletion costs. Account credits are funding, not permission to spend. Ask for explicit operator approval before any billable action, including temporary validation deployments. At the baseline, 168 hours leaves $9.15584 before the total cap, before additional costs. Keep the existing $45 deletion trigger; the modeled watchdog/deletion tail and fees must fit its $5 reserve. Inspect shared-account consumption and current available balance before requesting approval; other workloads may consume the same credits.

Before an explicit future deployment action:

1. Obtain and review an authenticated resource quote including disk, network, fees, taxes, minimum funding, preauthorization and any provider-enforced cap.
2. Demonstrate an external deletion adapter with deletion readback, residual-resource and charge inspection, retries and partial-creation cleanup. The M0 fake provider is not that demonstration.
3. Arm an operator-controlled absolute UTC deadline and periodic watchdog outside the CVM, with an independent backstop. The watch interval must be chosen from measured deletion latency and the cost margin, not copied from the synthetic fixture.
4. Persist each newly created resource ID immediately, before attempting the next resource. The deadline is at most 168 hours after creation; request deletion when conservative cumulative cost reaches $45. Do not auto-upgrade or extend runtime.
5. After deletion, inspect VM and disk inventory and remaining charges. A stopped resource is not deleted. A scheduled job is not a guaranteed billing cap.

`zrpc teardown --simulate` edits only an in-memory fixture and prints its result; it never changes the input file or any external resource. `zrpc watchdog` returns a decision and performs no deletion. No cloud credentials belong in the guest, fixtures, repository or public CI.
