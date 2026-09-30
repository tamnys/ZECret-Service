# Phala preview operator authorization — 2026-09-30

The operator asked whether it is time to launch on Phala and explicitly permitted
actions **including deployment through the signed-in Phala website in Chrome**.
The operator also directed us to conserve the budget, use no more resources than
necessary, stop the evaluation when its purpose is met, and preserve these
instructions across conversation compactions. This record preserves that
authorization; it does not assert that a resource has been created.

The authorization applies to the **public Testnet TEE preview**, not approval of
genuine private mode. The existing constraints remain: **$50 total Phala
infrastructure ceiling, $45 deletion trigger, and 168-hour maximum including
sync and evaluation**. Do not silently increase any of these limits, choose a
larger instance outside them, launch another resource, or spend on another
provider. The account's credit balance and complete selected-configuration
quote must be read before a billable call. Track actual spend conservatively;
stopping a CVM does not stop attached-storage billing.

This instruction authorizes the operator deployment action once the exact
candidate and effective cost/cleanup controls are reviewable. It does not
waive the existing fail-closed launch prerequisites: immutable application
image identity and launch bytes; current account image/KMS and capacity
readback; sufficient observed resource fit; original durable ledger written
before resource creation; an effective external deletion watchdog plus an
independent deadline backstop; and a way to verify attached-storage deletion
and reconcile billing. If any prerequisite remains unresolved, continue
non-billable preparation and report the specific gap. No scheduler, image
publication, or cloud resource should be activated merely because this record
exists.

At launch, use synthetic or public Testnet inputs first. Preserve the empty
approved-release catalog and the blocked private-mode indicator. Shut down
and delete every experiment-owned billable resource as soon as the preview
objectives are met, then retain the ledger until storage inventory and billing
evidence are reconciled.

The operator subsequently explicitly authorized creating a **workspace-scoped
Phala API token with no expiry** for the deletion watchdog, since the signed-in
form offers no delete-only scope. Revoke that token after cleanup. This is
credential authorization, not permission to expose its value, put it in the
repository, expand the spending ceiling, or skip the watchdog and deletion
checks above.

The operator later selected the full **one-week (168-hour) experiment window**,
including synchronization and cleanup, and accepted a **one-hour assumed
deletion-latency allowance** within that window. The previously proposed
close-of-Thursday cutoff is withdrawn. The operator also accepted a **1 MiB
(1,048,576-byte) per-response cap** for the Phala management API watchdog.
These selections are not Phala guarantees, additional spending authority, or
permission to run the service for 168 hours and then begin cleanup.

The operator then **waived the external watchdog for this public preview**,
choosing manual operation of the single CPU CVM instead. This supersedes the
earlier watchdog prerequisite above for this preview only; the private-mode
release gates are unchanged. Keep the original durable ledger and record the
exact start and deadline before the
billable create call. Manually request **deletion**, not merely stop, no later
than one hour before that deadline, and earlier if the demo is complete, the
$45 experiment trigger is reached, or the selected configuration would exhaust
the $50 ceiling. Verify the CVM and attached storage disappear and reconcile
billing afterward. There is no automatic spending cap or guarantee that an
unattended manual plan will run on time. The accepted 1 MiB cap remains
available for optional manual management-API diagnostics but no watchdog job
will be installed or activated.
