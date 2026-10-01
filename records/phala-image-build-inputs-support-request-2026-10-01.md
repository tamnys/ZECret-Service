# Phala image build inputs — unsent draft

Subject: Production custom-image build inputs for `prod9`

Hi Phala team,

We're preparing a custom TDX guest image for a Zcash Testnet RPC evaluation. Our current catalog tuple is `dstack-0.5.9-bd369a8c` on `prod9` with the `phala-prod9` KMS. We need to build from fixed, reviewable inputs before testing an image on production hardware.

Is a project-built image supported with that node and KMS? If so, please share the supported base version, exact kernel and Yocto metadata source revisions, build instructions, required image and measurement artifacts, and the process for admitting the image. The matching `linux-yocto-dev` recipe uses `AUTOREV`, so we cannot treat its current kernel sources as fixed build inputs.

This is an information request only. Please do not change our running CVM or create resources in response.
