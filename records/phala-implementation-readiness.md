# Phala correction implementation and readiness — 2026-09-26

Internal implementation evidence. No Phala resource was created, no image was
published, no provider setting or schedule was changed, no support message was
sent, and no account credits were spent. Private mode remains blocked.

## Local implementation

- `experiments/ephemeral-runtime/prepare-image-source.py` reads eight files
  from the catalog-matched dstack v0.5.9 Git commit object, checks their SHA-256,
  and rejects a checkout at another commit. The pinned commit is
  `282eeb27d22d8f091ad0fa5a90e638f85cf68751`. Its generated source
  overlay checks volatile storage before overlays, puts the work directory on
  fresh tmpfs, binds Docker/containerd/Sysbox roots from memory, excludes the
  nested persistent mount from `/dstack`, rejects mutable data-device selection,
  scripts, the Bash runner, ZFS, swap and unencrypted storage, and hashes the
  same copied compose bytes used for policy and event measurement. The current
  source candidate is deliberately **unbound**: it rejects every launch before
  disk setup and again before container startup. A future image build must use
  `--launch-config` and `--sys-config` together to embed the SHA-256 of both
  exact reviewed, guest-owned JSON inputs; unpaired inputs are rejected. The
  patched loader checks the copied system bytes before parsing the KMS,
  gateway and VM settings and uses that snapshot. The generator rejects
  duplicate JSON keys, malformed nested VM configuration, scripts, public logs and
  environment allowances. It and the patched dstack loader require a
  nonempty KMS provider identity because the pinned upstream loader otherwise
  skips its identity comparison when `key_provider_id` is empty. They also
  require a restrictive one-port gateway policy without PROXY headers; the
  selected port must still be reviewed against the actual wrapper listener. A digest
  alone does not review Docker Compose privileges or mounts. The preparation
  script refuses an existing Compose
  YAML and derives it from the copied JSON; the app launcher verifies both the
  bound JSON digest and exact derived YAML before Docker starts. It also removes
  pre-launch execution and disables on-boot Compose builds and pulls. The
  patched dstack loader now rejects a nonempty host-supplied encrypted
  environment or user configuration, removes the `user_config` symlink, and
  rejects a host-supplied Docker registry override before key request or
  container startup. File read errors fail closed except for genuinely absent
  optional inputs. The bound `sys_config` still requires review of its KMS and
  gateway URLs, VM configuration and stability across boots; a digest is no
  substitute for the supported production contract. The
  candidate removes the upstream preparation reboot target,
  disables persistent journal capture and console-forwarded unit output, and
  changes the guest-agent sockets from world-accessible to root-only. The
  dstack socket also serves key and signing methods. A local Rust quote-only
  Unix bridge now reuses the existing bounded dstack `GetQuote` call and rejects
  every other route. Its candidate unit requires a fresh memory-backed startup
  marker and a dedicated wrapper group; neither the binary nor group is
  installed in a guest image. The overlay emits service/socket drop-ins with
  preparation dependencies, pre-start guards, `Restart=no` and
  `FailureAction=poweroff-force` for preparation, runtime and socket failures.
  The quote bridge candidate unit now has `BindsTo` and `After` edges for the
  app launcher, Docker, containerd, Sysbox services and guest agent, so
  deactivation of one of those effective units would stop the bridge and close
  the wrapper's liveness connection under [systemd's documented dependency
  semantics](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml).
  The candidate app launcher now stays attached to `docker --host
  unix:///run/docker.sock compose --env-file /dev/null -f docker-compose.yaml
  up --abort-on-container-exit`, and its unit is
  `Type=simple` rather than a detached oneshot. Any Compose return, including a
  successful return after a container stops, makes the launcher fail, which
  should deactivate the bound quote bridge.
  [Docker documents](https://docs.docker.com/reference/cli/docker/compose/up/)
  that this attached option stops all containers when one stops. The explicit
  file selection excludes Compose's automatic override-file discovery, while
  the explicit empty environment file replaces its default `.env` input. The
  [Docker CLI host flag](https://docs.docker.com/reference/cli/docker/) selects
  the local daemon socket instead of an ambient context or `DOCKER_HOST`;
  [Docker's file-selection rules](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/)
  explain the default merge, and [its environment-file rules](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)
  document the override. The candidate generator now requires JSON Compose
  content with unique keys, a restricted service field set, exact image digests,
  non-root read-only services, dropped capabilities, disabled logs and restarts,
  and no `$` interpolation. The restricted fields reject `include`, `extends`,
  `env_file`, build contexts, secrets, configs and profiles before the launch
  digest is embedded. [Docker documents JSON Compose input](https://docs.docker.com/compose/support-and-feedback/faq/).
  The candidate now rejects all service volumes, ports, temporary mounts,
  process overrides, extra groups, healthchecks and init controls. A later
  bound profile must explicitly review and add the public Zebra data mount,
  memory-backed cookie sharing and wrapper port; the currently restricted
  schema cannot express a deployable application. Image contents and the exact
  plugin's interpretation still require review. This is not an effective
  failure test of the exact guest's Compose version or unit graph; the final
  effective Compose profile and Docker runtime must confirm no automatic
  restart, and an unhealthy but still running container needs separate
  liveness handling.
  A read-only extraction from the previously verity-verified stock rootfs found
  a 60,960,216-byte Compose plugin at
  `/usr/lib/docker/cli-plugins/docker-compose`, SHA-256
  `5d2c840dea24293b76cbac9f83e5694fdda462fc3d179f236ebbf1426615ea3e`.
  Its static strings include `--abort-on-container-exit`; this is not an
  executed compatibility or container-failure test.
  The pinned gateway source permits an administrator port-policy
  override ahead of the guest-reported policy, so the guest check cannot prove
  that Phala's production gateway will expose only the wrapper port.
  [The generated candidate manifest](../experiments/ephemeral-runtime/candidate-manifest.json)
  records every generated file hash and explicitly says that the full source
  tree as built, bound launch profile, built image and private acceptance are
  **not** verified. The overlay is not an installed image or a measured release.
- `runtime-guard.rs` checks the relevant procfs mount topology and swap state.
  A root-owned `/run` marker can deny a same-boot service restart; it cannot
  authorize startup. The pre-overlay mode checks `/var/volatile`, `/run` and
  `/tmp` before the first overlay mount. The final guard rechecks `/run`,
  `/tmp`, `/dstack` and runtime roots, including persistent descendant mounts.
  The generated preparation script sets an empty kernel core pattern,
  `core_uses_pid=0` and `fs.suid_dumpable=0` before KMS; both guard modes read
  those live kernel settings and reject file- or pipe-based dump policies.
  Failure to set or read them blocks startup. The exact production kernel and
  crash/OOM behavior remain untested. The targeted
  [guest write-path audit](guest-write-audit.md) records other static surfaces
  and the missing effective write-policy proof.
- `experiments/ephemeral-runtime/prepare-rootfs-source.py` now derives a
  separate production-rootfs recipe candidate from two hash-checked Git objects
  at meta-dstack `e3655d1390feee3736476f4bda35c4354b4a12fc`. The pinned
  production recipe selects `nologin`, but the inspected stock rootfs retains
  rescue/emergency services, sulogin and mutable boot-command generators. The
  candidate's rootfs postprocess requires those exact observed paths, confines
  canonical rootfs and every affected parent to BitBake's work directory,
  removes the paths, and masks rescue, emergency, debug, hibernation and
  offline-update units. A changed recipe, missing observed path, symlinked
  parent or preexisting mask fails closed. This source is not installed in a
  built image and cannot rule out
  Phala console, exec, update or recovery controls outside the guest image.
- The native verifier has an opaque `ApprovedRelease` separate from diagnostic
  `WorkloadPolicy`. An external policy can select only a client-embedded release.
  The manifest's launch-config digest must equal the app-compose hash used in
  authenticated workload appraisal; a mismatched pair is rejected locally.
  The client now also extracts the pinned image digests from that exact launch
  document and requires the embedded manifest's container-digest multiset to
  match. It rejects ambiguous service names and unreviewed Compose fields in
  this approval check, including external includes and bind mounts.
  It also requires a reviewed system-config digest, enforced by the measured
  image candidate rather than a separate event-log field.
  **The embedded catalog is empty.** Neither synthetic fixtures, a provider
  `verified: true` value, a local policy file nor a first-seen quote can add one.
- The transport has a non-serializable `VerifiedRpcSession` that retains the
  original Tor/TLS HTTP sender, authenticates the quote, event replay, strict
  TCB/collateral, approved workload, nonce, current clock and REPORTDATA exporter
  comparison before a one-shot typed `/rpc` request. Because there is no
  approved release, this promotion cannot currently succeed. The server's
  optional typed `/rpc` route requires quote issuance on that TLS session and
  uses the existing loopback `LocalNode` allowlist. An explicit library-level
  node listener now binds the same ephemeral-key TLS service with that route;
  its production constructor probes only `/run/zrpc-quote/quote.sock` and
  establishes a liveness connection to `/run/zrpc-quote/watch.sock` before
  opening TCP, with a separate test-only constructor for synthetic fixtures.
  Loss of that connection shuts down the local listener and its owned TLS
  sessions. Loss of the wrapper's watch connection makes the bridge exit, so
  its quote sessions close and the candidate systemd failure action can shut
  down the guest. This covers a local process-loss path, not arbitrary daemon
  failure or a production boot.
  A new `zrpc-node-wrapper` executable wires this listener to the typed node
  adapter. It requires explicit numeric listen/node addresses and quote limits,
  a non-root process, and Zebra's exact v6.4.2-format cookie at the fixed
  `/run/zrpc-node/.cookie` path. The cookie loader uses pinned `rustix` safe
  fd-relative opens, rejects symlinks, checks owner-only mode and effective
  user, verifies the opened inode is on tmpfs, and never logs the credential.
  Zebra's reviewed source generates a 32-byte random password, base64-encodes
  it and writes `__cookie__:` plus that encoding as a 0600 `.cookie` file.
  [Pinned Zebra source](https://github.com/ZcashFoundation/zebra/blob/e3eef2f37c35127ad1769f19a1ebc7eaa5d5d291/zebra-rpc/src/server/cookie.rs),
  [rustix safe `openat`](https://docs.rs/rustix/1.1.5/rustix/fs/fn.openat.html).
  The original `zrpc-wrapper` remains public-attestation-only. Neither node
  launcher nor the memory-backed Zebra cookie mount is installed in a guest
  image; no deployable node/wrapper configuration exists yet.
- `zrpc verify`, `query --stdin` and `dashboard` accept explicit endpoint,
  loopback SOCKS, collateral, compose and release-selection inputs. The
  dashboard uses the same native client core; `demo` remains fixture-only. Live
  dashboard requests currently fail before Tor dialing because the catalog is
  empty. Local capability, Host/Origin, no-store and text rendering checks stay
  in place. A configured SOCKS endpoint is not proof of the Tor process.

## Verification and limits

- Eighteen standalone guard tests pass, including persistent mounts, swap,
  pre-overlay backing and same-boot retry rejection. Generated preparation and
  application Bash pass `bash -n`; the generator ignores working-tree edits and
  rejects the wrong source commit before creating output. Synthetic pre-launch
  and Bash-runner canaries do not execute. Four permanent synthetic
  launch-profile tests in `scripts/check.sh`
  rejected duplicate keys, missing KMS identity, public logs, mutable
  environment allowances and
  scripts, plus missing, unrestricted, multiport and PROXY gateway policies.
  System-config tests reject unpaired inputs, duplicate keys, malformed nested
  VM JSON and a registry override. The six permanent launch-profile tests also
  run the pinned upstream app launcher after transformation with a stub Docker:
  both zero and nonzero Compose returns fail the launcher, and changed bound
  configuration reaches no Docker call. The transformed unit is no longer a
  detached oneshot. This synthetic stub does not establish real Compose event
  or systemd behavior.
  The unbound app launcher never called Docker; a bound synthetic
  launcher rejected changed JSON, poisoned or missing Compose YAML, and
  reached a stub Docker only for the exact matching files. All 21 generated
  candidate-file digests were recomputed against both candidate manifests.
  The bound synthetic manifest is test-only; the repository manifest stays
  unbound. The patched
  `dstack-util` compiles with the pinned lockfile
  in an isolated copy of the cached dstack source, on the local
  `aarch64-unknown-linux-gnu` container, including the new embedded digest
  check. That is not a production x86_64 image
  build, image integration or boot test. Local `systemd-analyze verify` cannot
  resolve the production Docker unit or the candidate guest executables in this
  container, so it does not prove the effective production units or runtime
  failure propagation.
- Rust verifier/server/transport/client and CLI tests exercise empty-catalog
  rejection, zero private-body transmission on synthetic evidence, the
  manifest/compose digest equality rule,
  attestation-first RPC route, typed node restrictions and dashboard blocked
  state. A synthetic TLS/quote/loopback-node integration test confirms the
  optional listener's same-connection route and JSON-RPC result envelope;
  quote-bridge tests reject key/signing routes and malformed data before the
  root-only backend, check private socket publication, watch-loss shutdown and
  same-boot restart denial, and pass a synthetic quote without granting client approval. The
  new node-cookie tests accept the exact format from `/dev/shm` and reject a
  non-tmpfs workspace file, permissive mode, symlink and malformed format;
  a startup test rejects missing, stale, symlinked and public quote sockets.
  All 51 server library tests and the node-launcher parser test pass. The
  pinned `rustix` 1.1.5 and `linux-raw-sys` 0.12.1 releases predate the
  managed seven-day hold; Cargo locked their registry checksums. The new
  `rustix` build script was inspected: it probes the local compiler and
  architecture, with no network or installer operation. The earlier complete
  check failed in an unrelated intermittent lifecycle fixture:
  `LedgerStore::initialize` could not open a just-published synthetic original
  (`regular open: ENOENT`); the exact focused lifecycle test passed on rerun.
  The lifecycle filesystem failure is unresolved; the passing rerun does not
  repair it. [Prior diagnostics](lifecycle-test-diagnostics.md) record the
  earlier occurrences and three-round investigation limit. The first full
  check after adding the node launcher found a generated `zrpc-wrapper` binary
  with mode 0644; after restoring its executable bit, the wrapper smoke check
  and `bash scripts/check.sh --browser` passed. Direct execution of the new
  node launcher with no tmpfs cookie exited with its fixed error before binding
  an available local TCP port. Browser checks covered
  simulation and live-blocked dashboard states at desktop and narrow widths.
  After adding the bridge watch and its malformed-acknowledgement test, the
  focused server suite and complete `bash scripts/check.sh --browser` passed.
  After binding the launch digest, 21 verifier tests, the patched dstack-util
  compile and the complete `bash scripts/check.sh --browser` passed. The latter
  succeeded on rerun after another intermittent generated `target/debug/deps`
  write-permission error; no source change or permission bypass was used.
  After the host-input and paired system-config corrections, a regenerated
  bound synthetic `dstack-util` source passed `cargo check --locked` in the
  isolated pinned source copy, four launch-profile tests and all 21 verifier
  tests passed, and all 21 file hashes in each bound/unbound candidate manifest
  were recomputed. The exact generated host-input predicate and its negative
  unit test passed as a standalone `rustc --test` extraction. The full
  `dstack-util` unit-test build failed on the recurring generated-object
  `Permission denied` error, including with a separate workspace target
  directory; no dependency or permission policy was changed to bypass it.
  No guest boot or full host-input injection test ran.
  After the core-dump guard correction, the generated shell passed `bash -n`,
  all 21 unbound candidate-file hashes matched the manifest, the then-17 guard
  tests passed, and the complete `bash scripts/check.sh` passed in the managed
  browser-profile container. This does not test the actual guest kernel's
  sysctl writes or a crash/OOM path. After adding `/run` and `/tmp` mount
  checks, all 18 focused guard tests and the complete `bash scripts/check.sh`
  passed in the managed container. The source manifest was then regenerated
  from the pinned commit, and all 21 generated-file hashes, including the
  updated guard and attached launcher, were recomputed. The full check after
  the attached-Compose change also passed `bash scripts/check.sh` in the
  managed container.
  After pinning Compose to the checked file with `-f`, the six synthetic
  launch-profile tests, generated Bash syntax check and full
  `bash scripts/check.sh --browser` passed in the managed container. All
  generated candidate-file hashes matched the regenerated unbound manifest;
  only the app launcher hash changed. No exact-guest Compose execution ran.
  After restricting the inner Compose document to unambiguous JSON and the
  private runtime field set, eight synthetic launch-profile tests and the full
  `bash scripts/check.sh --browser` passed. The generated unbound manifest's
  file hashes were recomputed; only the launch script hash changed because it
  now pins the local Docker socket and supplies an empty environment file. The
  exact production Compose plugin, mount set and namespace behavior remain
  untested.
  After removing unreviewed mount, port and process-control fields, the eight
  synthetic launch-profile tests, generated Bash syntax/hash checks and full
  `bash scripts/check.sh --browser` passed again. The generated manifest is
  unchanged because the source overlay's output did not change.
  The container-digest approval check was exercised with matching, missing,
  duplicate, changed-byte and external-Compose-input cases; focused verifier
  and transport tests passed. The complete `bash scripts/check.sh --browser`
  then passed in the managed container with Cargo compilation serialized. Two
  preceding concurrent runs stopped at the previously observed intermittent
  `target/debug/deps` write-permission error, despite owner-writable directories;
  this does not establish its cause. The catalog remains empty, so these local
  tests do not demonstrate a genuine private session.
  Five synthetic rootfs-postprocess tests passed, including root-path and
  internal-symlink escape refusals and a BitBake-style recipe-variable
  expansion with those variables absent from the shell environment. The
  generator read the exact pinned meta-dstack commit and recomputed its output
  recipe hash. The
  wrong source commit was refused before output; every required removal path
  matched the prior verity-verified rootfs inventory. The complete
  `bash scripts/check.sh --browser` passed in the managed container with Cargo
  compilation serialized. These tests run on a temporary file tree; no Yocto
  rootfs, guest boot or effective administrative path was tested. The managed
  container has only the `aarch64-unknown-linux-gnu` Rust target and no x86_64
  cross-linker. It cannot produce the required TDX x86_64 binaries without a
  separately reviewed build environment.
  One intermediate build attempt
  reported a temporary-file permission error under generated `target/debug/deps`;
  the workspace directory was owner-writable, and the unmodified full check
  passed on rerun. The cause of that transient artifact error is unknown.
  No local test is hardware acceptance.
- No production image/verity commitment or reconstructed measurements exist for
  this overlay. No guest namespace, systemd boot/failure, console/exec, KMS
  release, persistence poisoning, canary retention, real Tor, Zebra sync or
  real TDX test has run. The systemd failure action and pre-start guard do not
  yet prove that Docker, containerd or guest-agent failure closes a surviving
  wrapper/container session on the supported production image. The local
  bridge-loss test does not establish that effective systemd or container
  ordering.

## Gates and deployment boundary

1. **Image and administration:** Phala must identify a supported production
   image/custom-image admission and compatible KMS policy. Integrate the overlay
   and guard into that immutable build, inventory all units and write paths,
   disable guest console/rescue/exec/update controls, prohibit same-boot runtime
   recovery, install and measure the quote bridge and non-root node launcher,
   share only a tmpfs cookie directory and the quote-only socket with the
   wrapper, keep the guest agent's key/signing sockets out of the wrapper and
   node, prove that the production gateway cannot administratively override
   the single allowed wrapper port, and prove
   failure-triggered shutdown/session closure on the exact
   artifact. The exact production `sys_config` bytes and their stability across
   boots and node placement must be known before a bound image can start. The
   unsent [support draft](phala-support-request.md) requests these
   contracts; sending it is a separate operator action.
2. **Hardware and keys:** Reconstruct measurements from the built rootfs and
   exact launch/container/KMS inputs. Test a real TDX quote, strict collateral,
   event replay, key ownership on the retained TLS connection, KMS disk-key
   release, and rejection of altered/rolled-back inputs. Only then may a
   reviewed manifest digest be packaged in a new native-client release.
3. **Node fit:** The intended TDX target is x86_64. The official Zebra v6.4.2
   x86_64 GNU archive is listed as 67,178,756 bytes with GitHub metadata SHA-256
   `505cab2c616dac1a5bc1c414716206a775f38f41ca6f70a60729df40c29e7b8b`,
   published 2026-09-25 19:59:10 UTC. It is still inside the existing seven-day
   package hold. No archive was downloaded; signed checksum/provenance,
   advisories, ELF compatibility, memory use and real testnet behavior remain
   unchecked. The exact Zebra RPC cookie configuration, shared network
   namespace and tmpfs mount must be installed and tested with that release.
   [Official release](https://github.com/ZcashFoundation/zebra/releases/tag/v6.4.2).
4. **Lifecycle and cost:** The existing ledger, provider adapter and uninstalled
   Linux/systemd watchdog bundle remain local. The Linux host, permissions,
   clock, effective units, credentials, restart behavior, usage-ID mapping,
   attached-storage deletion evidence and final billing reconciliation have not
   been validated. A 204 DELETE, stopped state, or absent CVM does not prove
   storage deletion or billing finality. Keep the independent deadline/manual
   backstop.

The currently published `tdx.large` rate is $0.232/hour and storage is
$0.000139/GB/hour. For 80 GB over 168 hours, the arithmetic baseline is
`168 × (0.232 + 80 × 0.000139) = $40.84416`. This is not an account quote,
memory-fit result, fee bound or guaranteed total. Retain the $50 total ceiling,
$45 deletion trigger and 168-hour maximum including synchronization. Requote
the complete selected configuration after memory testing and before a separate
deployment approval. Storage continues billing while stopped and ceases only
after deletion. [Phala instance rates](https://cloud.phala.com/about/instance-types),
[Phala billing/storage policy](https://cloud.phala.com/about/pricing).

The exact deployment package is **not ready**: it lacks a supported image/KMS
tuple, built artifact identities/measurements, eligible x86_64 Zebra, measured
resource fit, binding account quote, external deletion timing and storage/billing
evidence. None of these gaps is replaced by a UI indicator or simulation.

Next safe operator command, from this repository in the managed container:

```sh
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --command cargo run --locked -p zrpc-cli -- doctor
```

It reports the blocked state and creates no cloud resource. Deployment has no
automatic command or scheduled action in this work.
