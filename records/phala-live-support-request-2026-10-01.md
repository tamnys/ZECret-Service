# Phala live CVM questions — unsent draft

Subject: Pre-launch script and missing instance ID on `cvm_MeD4o0eQ`

Hi Phala team,

We're testing a public Zcash Testnet RPC preview on `prod9` with CVM
`cvm_MeD4o0eQ` (app ID `5af400d6c4fd5312a9b9693fe0988d5bdc0ee726`).
Before evaluating private queries, we need to resolve two issues with this
running CVM:

1. Our launch document had no `pre_launch_script` and set `public_logs` and
   `public_sysinfo` to false. The initial API readback had both flags true and
   added a 17,569-byte script (SHA-256
   `982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8`).
   The script exactly matches [this dstack example](https://github.com/Dstack-TEE/dstack-examples/blob/4b1819d7f2cca610b2478a7be354358b1cad5b97/phala-cloud-prelaunch-script/prelaunch.sh).
   We corrected the two visibility flags, but the script remains. Which layer
   adds it, how do we deploy without it, and which exact launch-document bytes
   are measured into the guest's quote? On this production image, which
   SSH, console, recovery, exec and configuration-update paths can change the
   guest after attestation?

2. API version `2026-06-23` still returns `instance_id: null`, although
   `no_instance_id` is false and the CVM is running. A dry run of
   `PATCH /cvms/cvm_MeD4o0eQ/instance-id` with `overwrite: false` returned
   `skipped/gateway_rpc_failed`, `source: teepod_state` and
   `verified_with_gateway: false`. How should we repair this safely? The usage
   API's `instance_id` equals this CVM's `vm_uuid`
   (`05decd53-6a57-4b1d-97f5-ecff44749040`); is that the supported billing
   identity across restarts, replicas and deletion?

Please advise before changing the live CVM or creating resources. The RPC
workload has received only public Testnet preview requests; we have not
approved it for private mode.
