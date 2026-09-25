# Measured early-boot runtime investigation

Date: 2026-09-25. The operator selected investigation of an early-boot configuration that keeps runtime state in memory. This record is source analysis and a local shell fault-injection result, not a deployment configuration, guest-boot proof or plaintext-access demonstration.

## Result

The successful boot sequence provides a place to establish ephemeral runtime storage. However, a script supplied only through the inspected stock `init_script` invocation cannot establish the required failure guarantee: errors while deciding whether to run the hook or extracting its contents can leave preparation reporting success without running the hook. A guard installed inside the skipped hook cannot cover those cases. Gate D remains unresolved.

This needs a supported measured image with checked hook invocation or an independent, pre-existing runtime-start barrier that requires the intended storage configuration. The exact image and its behavior must be verified; no changed OS measurement or special attestation flag is invented here.

## Submission and normal ordering

The official [OpenAPI AppComposeV2 schema](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json#L8039) declares `init_script` as optional string/null. The [provision request](https://github.com/Phala-Network/phala-docs/blob/5176d4c53fcee5aec3a8ccbbb05840a0a678c553/openapi.json#L31453) references that schema. This establishes a documented submission field, not backend acceptance, measured-byte preservation or account availability. The project's Rust implementation does not call a cloud SDK or provisioning endpoint.

In [dstack v0.5.11 preparation](https://github.com/Dstack-TEE/dstack/blob/40eaf35e6b3f112998d01569f2a26110baab123b/basefiles/dstack-prepare.sh#L262), persistent runtime roots are mounted before the hook, which precedes normal Docker/containerd startup. Sysbox also uses persistent runtime storage. A successful-path candidate would establish fresh memory-backed roots for these runtimes, verify backing mounts and absence of persistent swap, and allow only public node state to use persistent storage. RAM capacity, storage-driver support, configuration identity and restart behavior need the selected image; no memory allocation default is chosen without measurement.

Rejected inference: `Wants`/`After` without `Requires` alone proves a runtime-start race. Exact systemd 255.4 source instead supports cancellation of queued runtime starts when the normal reboot transaction is successfully installed. Failure handling is [synchronous](https://github.com/systemd/systemd-stable/blob/387a14a7b67b8b76adaed4175e14bb7e39b2f738/src/core/unit.c#L2789), runnable jobs use [deferred dispatch](https://github.com/systemd/systemd-stable/blob/387a14a7b67b8b76adaed4175e14bb7e39b2f738/src/core/manager.c#L729), and stop jobs [cancel conflicting starts](https://github.com/systemd/systemd-stable/blob/387a14a7b67b8b76adaed4175e14bb7e39b2f738/src/core/job.c#L232). This does not prove every deployed failure path or transaction-enqueue failure safe.

## Reproduced hook failure propagation

The pinned v0.5.11 branch checks a `jq` result inside `if` and sources a `jq` process substitution. Bash's `set -e` does not turn either injected producer failure into failure of this preparation fragment. A subsequent successful runner lookup permits continuation.

The current upstream `next` commit [0fb3b24bbd94c18d4af2900b41cd82bcd1c0c284](https://github.com/Dstack-TEE/dstack/blob/0fb3b24bbd94c18d4af2900b41cd82bcd1c0c284/os/common/rootfs/dstack-prepare.sh#L315) changes extraction to `mapfile` with a `jq` process substitution. A failed producer can still yield an empty list and successful continuation. This is not an approved release or a claim about the image offered to this account.

`records/probes/check-stock-init-failure.py` models these exact shell control-flow boundaries using an injected failing `jq` function. It does not mount storage, execute the full boot script, start a runtime, access hardware or contact a provider. Managed-container Bash 5.2.37 produced:

| Case | Hook ran | Preparation fragment exit |
| --- | --- | --- |
| Successful control | Yes | 0 |
| v0.5.11 condition producer fails | No | 0 |
| v0.5.11 extraction producer fails | No | 0 |
| Current next mapfile producer fails | No hook loop | 0 |

Exit 137 is injected to represent a failed producer; no actual kernel OOM was induced. The probe confirms error propagation behavior, not a cloud exploit. A full image test still needs faults before/during extraction and mount setup, process-execution observation through failure/reboot, poisoned persistent runtime state, restarts, and memory pressure. Passing source checks or finding no processes after reboot is insufficient.

## Input needed

Anonymous read-only GET requests to the documented `https://cloud-api.phala.com/api/v1/kms` and `/api/v1/instance-types` returned HTTP 403. No credentials, resource creation, update, allocation or billable operation was used. Obtain the account's supported production OS image ID/version and artifact/source mapping, Cloud KMS identity/configuration, and region before selecting a concrete target. Any authenticated quote and external deletion/deadline proof still precede a separate operator deployment action.

To reproduce the local finding:

```sh
cd /Users/j/Code/phala-zcash-rpc
/Users/j/.codex/bin/codex-in-container --trust untrusted --profile browser --command python3 records/probes/check-stock-init-failure.py
```

The probe should exit successfully while reporting that the injected failures skip the hook. It confirms the unresolved requirement; it does not approve private mode.
