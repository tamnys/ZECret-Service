# Google Cloud operator lifecycle

The Rust operator tool prepares local, hash-bound packages and keeps an
append-only experiment journal. It is separate from the confidential guest and
private-query client. Keep its files and Google credentials on the external
Linux controller.

```sh
cargo run --locked -p zrpc-lifecycle --bin zrpc-gcp-lifecycle -- --help
```

Run build and test commands through the project's managed container.

## Prepare a package

Supply a `DeploymentSpec` JSON object with `schema_version: 5`, matching
`crates/lifecycle/src/gcp/package.rs`. Its artifact fields are objects containing
an absolute `path` and lowercase `sha256`. Required inputs include the raw disk
archive, release manifest, boot policy, memory measurements, reproducibility
report, DER Secure Boot PK/KEK certificates, a binary `secure_boot_db_esl`, and
a reviewed binary `dbx` revocation database. The `db` file must be one UEFI
`EFI_CERT_SHA256_GUID` signature list with exactly one PE/COFF image hash for
the intended UKI. A signer certificate in `db` is rejected because it would also
authorize other images signed by that key. Supply `esp_diagnostic` and
`uki_digest_diagnostic` artifacts from offline inspection of the exact raw disk
and extracted UKI; the package matches their disk, UKI-file, and PE/COFF image
hashes to the `db` entry. These reports do not verify the UKI signature or
establish boot or release approval. The package supplies all four Secure Boot
variables to the image API; omitting `dbx` would select Google's default. Keep
signing private keys outside this package. The operator package's `release_manifest`
is not a client-embedded approved release.

Save the JSON output of the offline `gcp_import_archive.py pack` command and
supply it as the `import_receipt` artifact. Supply `import_verifier_python` as
an artifact for the operator host's resolved `/usr/bin/python3` executable
(the canonical target if that path is a symlink). The receipt describes the
archive producer; the verifier artifact identifies the separate local
interpreter used to check the archive during package preparation.

Specify the project, C3 machine type, region/zone, boot/data disk capacities,
private subnet CIDR, wrapper port, and an existing private staging bucket.
The package creates its own network, subnet, ingress rule, image, separate boot
and public-data disks, and VM. It does not delete the shared staging bucket.

Provide a dated pricing record with its supporting artifact and separate
compute, boot disk, public data disk, image, staging, external IP, network, and
tax components. These values describe the selected configuration; they are not
a spending authorization or a hard billing cap. The original start and deadline
must be no more than 168 hours apart.

```sh
zrpc-gcp-lifecycle prepare \
  --spec /operator/evaluation/spec.json \
  --package /operator/evaluation/package.json \
  --state /operator/evaluation/journal
```

Preparation creates new local files only and refuses existing outputs. Save the
reported package SHA-256 for the later explicit operator action. Protect the
original journal: copying a new deadline into a replacement journal is not a
recovery procedure.

## Direct REST permission inventory

The controller uses the external operator's Google CLI identity to mint a token
for fixed Compute Engine and Cloud Storage REST calls. The guest VM has no
service account. Before deployment, record the exact controller principal,
project ID and number, staging-bucket owner, applicable project/folder/
organization allow and deny policies, service agents, and policy-change
authority. Confirm the effective permissions for that identity and the archive
reader in the selected project. This table describes the calls in
`crates/lifecycle/src/gcp/provider.rs` and the permissions documented for their
methods; it is not evidence that a particular identity has them.

| Controller call | Documented permissions to check |
| --- | --- |
| Existing bucket policy and generation-conditional staging object upload, reads, and deletion | `storage.buckets.get`; `storage.objects.create`, `storage.objects.get`, `storage.objects.delete`. An independent inventory also needs `storage.objects.list`. See the [Cloud Storage JSON method matrix](https://docs.cloud.google.com/storage/docs/access-control/iam-json). |
| Network and subnetwork creation, reads, and deletion | `compute.networks.create`, `compute.networks.get`, `compute.networks.delete`, `compute.subnetworks.create`, `compute.subnetworks.get`, `compute.subnetworks.delete`; the subnetwork's specified network requires `compute.networks.updatePolicy`. See [networks.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/insert) and [subnetworks.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/subnetworks/insert). |
| Firewall creation, reads, and deletion | `compute.firewalls.create`, `compute.firewalls.get`, `compute.firewalls.delete`, and `compute.networks.updatePolicy` on the specified network. See [firewalls.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert) and [firewalls.delete](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls/delete). |
| Direct raw-disk image creation, reads, and deletion | `compute.images.create`, `compute.images.get`, `compute.images.delete`; the boot-disk source image also requires `compute.images.useReadOnly`. Confirm which Google principal fetches the private `rawDisk.source` and its `storage.objects.get` access before import. See [images.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/insert) and [disks.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/insert). |
| Separate boot and public-data disk creation, reads, and deletion | `compute.disks.create`, `compute.disks.get`, `compute.disks.delete`; the boot disk's source image requires `compute.images.useReadOnly`. See [disks.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/insert). |
| Instance creation, reads, and deletion | `compute.instances.create`, `compute.instances.get`, `compute.instances.delete`; the supplied tags, metadata, deletion-protection field, existing disks, and external-IP subnet can require `compute.instances.setTags`, `compute.instances.setMetadata`, `compute.instances.setDeletionProtection`, `compute.disks.use`, `compute.subnetworks.use`, and `compute.subnetworks.useExternalIp`. Review the exact `serviceAccounts: []` field's authorization behavior as well. See [instances.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/insert) and [instances.delete](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/delete). |
| Global, regional, and zonal operation polling and recovery | `compute.globalOperations.get`, `compute.globalOperations.list`, `compute.regionOperations.get`, `compute.regionOperations.list`, `compute.zoneOperations.get`, and `compute.zoneOperations.list` in the scope of each resource. See [Compute Engine audit-method permissions](https://docs.cloud.google.com/compute/docs/logging/audit-logging). |
| Independent residual-resource inventory | The inventory principal also needs `compute.networks.list`, `compute.subnetworks.list`, `compute.firewalls.list`, `compute.images.list`, `compute.disks.list`, and `compute.instances.list` for the package's scopes. These are not controller calls. See the [Compute Engine IAM catalog](https://docs.cloud.google.com/compute/docs/access/iam). |

Grant only the permissions required by the final reviewed requests. The direct
`images.insert` path does not invoke the separate automated image-import CLI.
No IAM grant, role name, policy snapshot, or successful `GET` proves that a
different actor cannot replace a Compute name between inspection and deletion.
The current controller refuses live creation and Compute deletion until that
incarnation-safety contract is resolved and exercised in the selected project.

## External controller

`Runtime` selects an operator-installed Google CLI and its reviewed distribution
receipt, private CLI configuration directory, explicit DER TLS roots, and
operator-selected invocation/response bounds. OAuth token minting uses the
Google CLI; tokens are never printed or written to the journal.

`Controls` binds the package, controller executable, runtime file, non-root
controller UID, Linux machine identity, measured cleanup timings, deletion
rehearsal, and independent backstop. Export its units with:

```sh
zrpc-gcp-lifecycle export-watchdog \
  --state /operator/evaluation/journal \
  --controls /operator/evaluation/controls.json \
  --output /operator/evaluation/units
```

Export does not install or activate systemd. Operator installation must enable
the startup reconciliation service and both timers. Deployment checks the
effective unit files, absence of drop-ins, active/enabled timers, synchronized
clock, executable identity, and local permissions. The deadline reserves an
in-flight invocation, poll interval, measured deletion duration, and manager
delay. Timers and reminders cannot guarantee a spending cap.

Deployment appends the exact Controls file digest, runtime-file identity, and
deletion-start time to the original journal before Google authentication. Keep
that Controls file unchanged for the evaluation. If it changes or disappears,
the next watchdog invocation starts teardown rather than moving the original
cleanup trigger later. It still requires the original runtime-file identity.
A watchdog invocation before deployment makes no cloud call.

## Cloud commands and cleanup

`deploy`, `observe`, `teardown`, and `watchdog-once` are separate commands.
`deploy` additionally requires `--approve-package` with the frozen package
SHA-256 and live external-control validation. Each invocation makes one bounded
pass; `pending` means another pass is needed. The watchdog never creates
resources. After deployment admission, `observe` and `teardown` also require
the original runtime-file identity.

Live creation currently fails closed because the Compute adapter cannot safely
delete a specific resource incarnation when another actor replaces its name
between observation and deletion. Compute deletion also fails closed. Resolve
that provider contract before using this tool for a hosted experiment. Live
creation also requires complete inspection of the exact raw disk's GPT, signed
UKI, command line, verity root, installed components, and effective Secure Boot
policy. The ESP and UKI digest reports are insufficient for this admission.
Google C3 TDX hash-only `db` behavior also requires a production-platform test.
Cloud Storage deletion uses the recorded generation and a generation
precondition. Staging buckets must have public access prevention enabled and
must not retain deleted objects through versioning, soft delete, or retention
policies.

Read local history with `status --state DIRECTORY`. For an interrupted journal
publication, `recover --state DIRECTORY` can finish a complete pending snapshot;
it rejects truncated or inconsistent snapshots. Never delete pending files to
force progress.

Cleanup does not depend on an unexpired price quote or continued availability
of the image files. Resource absence remains separate from final billing
reconciliation. The tool never reports private-mode approval or a guaranteed
zero balance.

## Hardware acceptance sequence

Use the exact packaged image and configuration throughout this sequence. Keep
the client release catalog empty and use synthetic inputs during the hosted
evaluation. If a step fails, preserve the original ledger and evidence, start
teardown, and leave private mode blocked.

1. Before any cloud command, complete offline inspection of the raw disk, GPT,
   ESP, signed UKI, fixed command line, root/verity pair, installed components,
   and Secure Boot databases. Reconstruct the expected MRTD and ordered CCEL/
   RTMR values from reviewed artifacts and [Google firmware endorsements](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware),
   never from a first-seen quote. Freeze the package hash, selected project/zone,
   measured memory and disk fit, current full quote, and 168-hour deadline.
2. Establish the exclusive-name cleanup authority described above, verify the
   external Linux watchdog's effective units and reboot behavior, rehearse
   interrupted deletion, and arrange an independent deadline backstop. Obtain
   explicit spending approval for this exact package before `deploy`.
3. Run one explicit `deploy` pass and repeat only while it reports `pending`.
   Preserve every journal snapshot and reconcile each returned operation,
   numeric resource ID, and Storage generation with an independent inventory.
   Do not attach a guest service account or substitute an adapted image.
4. Boot the exact C3 TDX VM with synthetic input. Read back its image, Secure
   Boot policy, boot disks, metadata, firewall, public IP, and guest-service-
   account absence. Independently collect the raw TDX quote, binary CCEL, and
   current signed collateral. Compare firmware provenance, MRTD, RTMR replay,
   event semantics, UKI/rootfs/configuration, and live TLS-exporter binding.
   Assess [Google host and instance provenance](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/tdx-provenance)
   separately; the current native client does not appraise it.
   `inspect-endpoint --platform gcp-tdx` through the configured local Tor
   process is diagnostic only; it sends no private RPC body. See the
   [GCP client guide](../../../docs/gcp-tdx.md) for its exact options.
5. On this artifact, exercise altered boot inputs and root/data disks, console
   and metadata administration paths, writable-location and secret-canary
   checks through success, error, crash, and OOM, quote/collateral and event-log
   tampering, nonce/key/connection replacement, absent Tor, and direct-network
   detection. Check that Zebra synchronizes testnet within the measured VM
   resources, its RPC stays loopback-only, and wrapper methods remain bounded.
   `verify`, `query --stdin`, and the dashboard must continue to refuse private
   sessions while the catalog is empty.
6. Run `teardown` and the independent watchdog until completed operations and
   inventory establish absence of the VM, both disks, image, staging object
   generation, and experiment-owned network resources. A stopped VM, DELETE
   response, or missing name is insufficient. Reconcile delayed billing and
   invoice adjustments separately; retain the original ledger and evidence.

Only after review of the complete hardware, storage, administration, Tor,
channel, and cleanup evidence may a new native-client release package an
approved GCP manifest. This operator package never grants that approval.

After teardown, preserve a reviewed billing export and invoice comparison as a
local file. Create an `Artifact` JSON object containing its absolute `path` and
lowercase `sha256`, then append its digest to the original journal with:

```sh
zrpc-gcp-lifecycle record-billing-evidence \
  --state /operator/evaluation/journal \
  --evidence /operator/evaluation/billing-artifact.json
```

The command verifies the file and makes no cloud call. It stores only the
digest, never the billing data. Preserve the referenced file separately. The
command reports `billing_reconciled: false`; the journal records only the
evidence digest. Later charges or corrections can arrive.
