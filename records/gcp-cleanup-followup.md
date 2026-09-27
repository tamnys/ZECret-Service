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

The primary [IAM deny-permission catalog](https://docs.cloud.google.com/iam/docs/deny-permissions-support)
currently lists the six relevant `compute.googleapis.com/{instances,disks,
images,firewalls,networks,subnetworks}.create` permissions and their `delete`
counterparts. Google [supports denying all principals with a named exception](https://docs.cloud.google.com/iam/docs/deny-overview),
so an exclusive project is a plausible provider control, not yet an established
one. The exact admission proof still needs:

1. A dedicated project ID **and numeric project identity** with no shared
   experiment resource names, plus a complete initial inventory in every
   global, regional, and zonal collection used by the package.
2. The [applicable allow and deny policies](https://docs.cloud.google.com/iam/docs/troubleshoot-policies)
   at project, folder, and organization levels, including deny-policy UID and
   etag, custom roles, conditional grants, group membership, service agents,
   policy editors, and impersonation/token-minting authority. The future
   controller identity must be the only effective principal able to replace a
   planned Compute name. Alternate create, rename, bulk, and restore paths
   also require method-level permission review; `instances.setName` is listed
   in the deny-permission catalog.
3. A pre-existing, effective deny/allow configuration and authorized negative
   tests for another principal's create/rename attempts. Google states that
   [IAM changes are eventually consistent](https://docs.cloud.google.com/iam/docs/access-change-propagation),
   so a newly submitted policy and a timed wait are insufficient evidence.
4. Continuous external authority over policy changes and controller credentials
   for the evaluation and teardown window, with audit evidence of any IAM or
   project-hierarchy change. An actor able to use the excepted identity or
   modify the deny policy can still create a same-name replacement. A local
   `GET` or signed operator receipt cannot close that gap.

No offline package or journal field can prove these live authority facts. The
implementation therefore retains both the creation block and Compute DELETE
refusal until this contract is independently reviewed and exercised.

## Staging-object residuals

An ordinary object GET can miss a recorded generation that remains noncurrent
or soft-deleted. Google's [objects.get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get)
supports selecting the exact `generation` and fetching soft-deleted metadata
with `softDeleted=true`; [soft-deleted objects keep accruing storage charges](https://docs.cloud.google.com/storage/docs/soft-delete).
The adapter now checks that the shared staging bucket still exists, then
queries both forms for the recorded generation before committing observed
absence. A retained generation or provider error leaves cleanup unresolved.
The synthetic test covers both residual classes and a failed residual read.

This check does not prove that the shared bucket cannot be replaced, that its
policy cannot change later, or that billing has settled. Those properties
require live external authority and reconciliation. Compute creation and
deletion remain blocked.

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
