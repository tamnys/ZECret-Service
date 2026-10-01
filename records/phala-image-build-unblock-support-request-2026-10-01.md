# Phala image build and admission request — unsent

Subject: Fixed build inputs and admission for a custom TDX guest on `prod9`

Hi Phala team,

We're preparing a custom Zcash Testnet guest based on the catalog image `dstack-0.5.9-bd369a8c` for `prod9` with the `phala-prod9` KMS. Can this node and KMS run a project-built image?

If so, please provide the supported dstack/Yocto base, fixed commits for the `linux-yocto-dev` kernel and `yocto-kernel-cache` sources (the matching recipes use `AUTOREV`), the required build and measurement artifacts, and the production image/KMS admission procedure. Please also identify the disk-key release policy: could a changed image receive the same key?

If that image route is unsupported, which production node/image/KMS combination supports a custom guest? This is an information request only; please do not change our running CVM or create resources.
