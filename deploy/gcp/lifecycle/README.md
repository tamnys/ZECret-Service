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

Supply a `DeploymentSpec` JSON object with `schema_version: 4`, matching
`crates/lifecycle/src/gcp/package.rs`. Its artifact fields are objects containing
an absolute `path` and lowercase `sha256`. Required inputs include the raw disk
archive, release manifest, boot policy, memory measurements, reproducibility
report, DER Secure Boot PK/KEK/db certificates, and a reviewed binary `dbx`
revocation database. The package supplies all four Secure Boot variables to
the image API; omitting `dbx` would select Google's default. Keep signing
private keys outside this package.

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
that provider contract before using this tool for a hosted experiment.
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
