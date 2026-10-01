# Phala production guest support request — unsent

Subject: Custom TDX guest support on `prod9`

Hi Phala team,

We're preparing a Zcash Testnet guest that keeps runtime and private request state in memory and disables guest administrative access. Our current catalog tuple is `dstack-0.5.9-bd369a8c` on `prod9` with the `phala-prod9` KMS.

Can a project-built guest image with those changes run on this production node and KMS? If so, please provide the supported base and fixed kernel/Yocto source revisions, the image build and admission procedure, and the artifacts needed to independently reconstruct its measurements. The matching `linux-yocto-dev` recipe currently uses `AUTOREV` for both the kernel and `yocto-kernel-cache`.

We also need to know whether the KMS could release the same disk key to a changed or rolled-back image, and whether the admitted configuration can disable injected pre-launch scripts and console, exec, recovery, and update access. If this combination is unsupported, which production image/node/KMS combination supports these controls?

This is an information request only. Please do not change our running CVM or create resources.
