# GCP deletion and billing follow-up (2026-09-26)

This is an internal contract review. It involved no Google account, API call,
resource creation, deployment, credential, or charge.

## Compute deletion

The v1 [instance](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/delete),
[disk](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/delete),
[image](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/delete),
[firewall](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls/delete),
[network](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/delete),
and [subnetwork](https://docs.cloud.google.com/compute/docs/reference/rest/v1/subnetworks/delete)
DELETE methods address a resource by its name. Their `requestId` query
parameter deduplicates retries; it does not condition deletion on the numeric
resource ID observed by the journal. A matching GET immediately before DELETE
therefore cannot rule out a same-name replacement between the two calls.
`LIVE_DEPLOYMENT_BLOCKERS` and the Compute DELETE refusal remain necessary.

A possible future admission model is an exclusive experiment project whose
creation permissions and change authority are controlled outside the lifecycle
process. It would need a review of the project's identity, inherited IAM allow
policies, deny policies, all principals capable of creating/replacing the six
Compute resource types, and policy-change authority for the entire evaluation.
[Inherited allow policies](https://docs.cloud.google.com/iam/docs/resource-hierarchy-access-control)
and [eventually consistent deny changes](https://docs.cloud.google.com/iam/docs/deny-overview)
mean a project-level policy snapshot or newly installed deny rule is not by
itself a race-free admission proof. This contract has not been implemented or
accepted. No local receipt or Boolean should unblock live deletion.

## Billing

The [detailed billing export](https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/detailed-usage)
includes Compute Engine and Cloud Storage resource fields, but
[export delivery has no latency guarantee](https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables).
Late usage and corrections can appear after an earlier query, and
[invoice-month totals can differ from usage-time totals](https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/standard-usage).
The ledger's optional billing evidence digest is therefore an immutable audit
reference after observed cleanup, not an automated settlement verdict. The
controller continues to report `ResourcesAbsentBillingUnreconciled` even when
that digest is present. An operator still needs a separately reviewed export,
invoice/adjustment comparison, and resource inventory covering the actual
project and staging bucket. No fixed wait interval proves reconciliation.

The follow-up code rejects a malformed, early, changed, or removed billing
evidence digest. Its synthetic test also confirms that recording the digest
does not change the unreconciled status. This hardens journal history only; it
does not resolve Compute deletion or prove final billing.
