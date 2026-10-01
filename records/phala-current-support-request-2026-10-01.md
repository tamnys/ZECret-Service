# Phala support request — unsent draft

Subject: Launch script and missing instance ID for `cvm_MeD4o0eQ`

Hi Phala team,

We're testing a Zcash Testnet RPC workload on `prod9` (CVM
`cvm_MeD4o0eQ`, app ID `5af400d6c4fd5312a9b9693fe0988d5bdc0ee726`).
Could you help us resolve two questions about this running CVM?

1. We did not supply a `pre_launch_script`, but the API readback includes an
   official Phala script (SHA-256
   `982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8`).
   Which layer adds it, can we disable it, and does the attested `compose-hash`
   cover the exact launch document used by the guest?
2. The CVM API returns `instance_id: null`. A dry-run instance-ID refresh
   returned `skipped/gateway_rpc_failed`. How should we safely recover or
   verify this ID? The usage API instead lists VM UUID
   `05decd53-6a57-4b1d-97f5-ecff44749040` as `instance_id`; can we use that
   to reconcile this CVM's charges through deletion?

We have not changed the live CVM to work around either issue. Thanks for
pointing us to the supported path.
