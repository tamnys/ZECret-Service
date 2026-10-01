# Phala custom guest build inputs — unsent

Subject: Supported custom guest image for `prod9`

Hi Phala team,

We're preparing a custom TDX guest image for a Zcash Testnet evaluation. Our current tuple is `dstack-0.5.9-bd369a8c` on `prod9` with the `phala-prod9` KMS.

Can a project-built image based on that version be admitted to this production node and KMS? The selected `linux-yocto-dev` recipe uses `AUTOREV` for both the kernel (`v6.9/standard/base`) and `yocto-kernel-cache` metadata (`master`). Please provide supported fixed commits for both, the supported base/Yocto revision and build procedure, required image and measurement artifacts, and KMS admission steps. If another base is required, please identify its exact version and corresponding build inputs.

Please do not change our running CVM or create resources in response; this is an information request only.
