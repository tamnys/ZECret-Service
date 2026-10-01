# Phala custom guest build inputs — unsent

Subject: Supported custom guest image for `prod9`

Hi Phala team,

We're preparing a custom TDX guest image for a Zcash Testnet evaluation. Our current tuple is `dstack-0.5.9-bd369a8c` on `prod9` with the `phala-prod9` KMS.

Can a project-built image based on that version be admitted to this production node and KMS? If so, please provide the fixed kernel and Yocto source revisions (the current `linux-yocto-dev` recipe uses `AUTOREV`), supported build procedure, required image and measurement artifacts, and admission steps. If another base is required, please identify its exact version and corresponding build inputs.

Please do not change our running CVM or create resources in response; this is an information request only.
