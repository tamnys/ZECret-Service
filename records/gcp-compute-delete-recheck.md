# Compute deletion identity recheck (2026-09-27)

This read-only review made no Google account or API call. It changes neither
deployment admission nor private-mode approval.

Google's Compute v1 DELETE methods address the planned [instance](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/delete),
[disk](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/delete),
[image](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/delete),
[firewall](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls/delete),
[network](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/delete),
and [subnetwork](https://docs.cloud.google.com/compute/docs/reference/rest/v1/subnetworks/delete)
by name. None documents a numeric-resource-ID or etag/`If-Match` deletion
precondition. Their `requestId` parameter deduplicates a retried request; the
operation's `targetId` is returned only after deletion has been dispatched.
Google describes a permanent numeric-ID URI for [renamed VMs](https://docs.cloud.google.com/compute/docs/instances/rename-instance),
but the instance DELETE reference still specifies a name. That URI does not
establish ID-conditional DELETE support for the instance or the other resources.

**Inference, not an accepted provider contract:** a dedicated experiment
project might prevent another principal from replacing a recorded name if an
effective, pre-existing IAM policy denies the relevant create permissions and
`instances.setName` to everyone except a tightly controlled controller identity.
Google documents [deny rules with exceptions](https://docs.cloud.google.com/iam/docs/deny-overview)
and lists the [supported Compute permissions](https://docs.cloud.google.com/iam/docs/deny-permissions-support).
This is an authority constraint, not an atomic DELETE precondition. It also
depends on the exception identity and policy editors remaining controlled.

Admission would require live evidence for the project's numeric identity and
complete initial inventory; effective project, folder and organization allow
and deny policies; all create, rename, bulk, impersonation and policy-change
paths; negative tests using a separate principal; and continued external
control through teardown. [Inherited allow policies](https://docs.cloud.google.com/iam/docs/resource-hierarchy-access-control)
and [eventual IAM propagation](https://docs.cloud.google.com/iam/docs/access-change-propagation)
make a project-level snapshot or newly submitted deny rule insufficient on its
own. No such project-specific evidence was reviewed here.

The controller's [live creation blocker](../crates/lifecycle/src/gcp/mod.rs)
and the provider's [Compute DELETE refusal](../crates/lifecycle/src/gcp/provider.rs)
therefore remain required. A matching GET immediately before a name-based
DELETE would still leave a same-name replacement race.
