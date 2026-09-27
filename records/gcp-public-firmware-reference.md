# Public Google TDX firmware-reference diagnostic

Date: 2026-09-27. This is a historical, unapproved public-artifact check.
It did not use a VM quote, cloud credentials, a project, or paid resources.
The downloaded binaries stayed in ignored workspace scratch; neither binary
is committed. The result does not identify firmware that will boot on a
future C3 instance and cannot authorize a private query.

[Google's firmware guide](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware)
documents the public bucket paths for TDX launch endorsements and OVMF binaries,
the Google root certificate, and signed measurement comparison. Although its
normal retrieval path starts with a quote's MRTD, an unauthenticated
[public GCS listing](https://storage.googleapis.com/storage/v1/b/gce_tcb_integrity/o?prefix=ovmf_x64_csm%2Ftdx%2F&maxResults=1)
was accessible. The first lexicographic entry was chosen **only to exercise
pre-quote verification**; listing order, object metadata, and an endorsement
filename are not release-selection authority. Google calls the bucket a
best-effort transparency backup hosted in `us-west1`.

| Input | Exact public identity | Digest |
| --- | --- | --- |
| Signed endorsement | [TDX `.binarypb`, generation `1728951531410960`](https://storage.googleapis.com/download/storage/v1/b/gce_tcb_integrity/o/ovmf_x64_csm%2Ftdx%2F038de02f6584df60c9ad245045aecf6f0b9d90018eeff5736357334c37965b1cd5bf09032a94e6b721f34fa8973a1086.binarypb?generation=1728951531410960&alt=media), object `ovmf_x64_csm/tdx/038de02f6584df60c9ad245045aecf6f0b9d90018eeff5736357334c37965b1cd5bf09032a94e6b721f34fa8973a1086.binarypb`, 5,066 bytes | SHA-256 `2e0cf3a75a4316e5879a2da9a9281ae157be0e89122f31c87a6e83e55e9b42eb` |
| OVMF binary | [`.fd`, generation `1726777931759407`](https://storage.googleapis.com/download/storage/v1/b/gce_tcb_integrity/o/ovmf_x64_csm%2F20b3fcb6ba64310e069653db3a938d9ae8bae750c14f41044fdea90fe1a52d4d2beee09c4ab578fae05e55a3b1992a49.fd?generation=1726777931759407&alt=media), object `ovmf_x64_csm/20b3fcb6ba64310e069653db3a938d9ae8bae750c14f41044fdea90fe1a52d4d2beee09c4ab578fae05e55a3b1992a49.fd`, 2,097,152 bytes | SHA-384 `20b3fcb6ba64310e069653db3a938d9ae8bae750c14f41044fdea90fe1a52d4d2beee09c4ab578fae05e55a3b1992a49`; SHA-256 `59e277baccd6a037e42454911d68beae8c16f55e8df9189348eea0dfac10e06d` |

The object metadata dates are September–October 2024. They indicate a
historical pair; they do not prove deployment then or now. The endorsement's
signed TDX section reports SVN 2 and 13 measurements. The object filename
matches its `ram_gib=88, early_accept=true` MRTD. That shape-specific value
was decoded for context, not independently reconstructed by this tool. The
tool separately reconstructed and compared the signed **generic**
`ram_gib=0, early_accept=false` MRTD:

```text
df09e135fb464db0fd53610ac380475c43a0c1f08efe412a709d929c520c723fbcd87dcc9593e45ef33f3f31152efdf1
```

The merged tool at repository commit `5a91381` was run inside the managed
untrusted browser-profile container with Go 1.27.1 and `GOTOOLCHAIN=local`.
Its Go module lock pins `google/gce-tcb-verifier` commit
`022f7554a942ea49f1085256104df1de9c8b3e98` and the embedded Google
root DER SHA-256
`e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c`.
With the two files above already present locally, the command was:

```sh
cd /workspace/tools/gcp-endorsement
go run -mod=readonly . \
  --endorsement /workspace/.codex-tmp/gcp-public-firmware/endorsement.binarypb \
  --firmware /workspace/.codex-tmp/gcp-public-firmware/firmware.fd
```

It returned exit 0 and this exact diagnostic result:

```json
{"schema_version":1,"status":"signed_firmware_reference_reconstructed_unapproved","endorsement_sha256":"2e0cf3a75a4316e5879a2da9a9281ae157be0e89122f31c87a6e83e55e9b42eb","firmware_sha384":"20b3fcb6ba64310e069653db3a938d9ae8bae750c14f41044fdea90fe1a52d4d2beee09c4ab578fae05e55a3b1992a49","google_root_certificate_sha256":"e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c","google_verifier_commit":"022f7554a942ea49f1085256104df1de9c8b3e98","measurement_profile":"google_current_generic","tdx_firmware_svn":2,"mrtd":"df09e135fb464db0fd53610ac380475c43a0c1f08efe412a709d929c520c723fbcd87dcc9593e45ef33f3f31152efdf1","private_mode_approved":false}
```

This establishes that a public, Google-signed endorsement and matching OVMF
binary can be authenticated and their generic MRTD reconstructed without a
first-seen VM quote. It does **not** establish which signed firmware or launch
variant Google will use for a selected future C3 VM. Google's public guidance
describes quote-MRTD-indexed retrieval, not an authoritative predeployment
project/zone/machine-to-firmware mapping. Our inference is that a client can
prepackage only independently reviewed references and must reject an actual
boot outside them; the public listing cannot fill that selection gap by itself.
RTMR0–3, Secure Boot state, signed UKI, rootfs, guest administration, and
hardware acceptance remain separate unresolved gates.
