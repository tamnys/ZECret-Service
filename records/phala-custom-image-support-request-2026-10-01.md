# Phala custom-image support request — unsent

Subject: Custom TDX image and KMS support on `prod9`

Hi Phala team,

We're preparing a custom guest for a Zcash Testnet RPC evaluation. It must keep container runtime and private request state in memory, while persisting only public chain data. Our current production tuple is `dstack-0.5.9-bd369a8c` on `prod9` with the `phala-prod9` KMS.

Can a project-built image run on this node and KMS? If so, please provide:

1. The supported dstack/Yocto base, fixed kernel and `yocto-kernel-cache` source commits (the matching recipes use `AUTOREV`), and the build inputs needed to reproduce the image and its measurements.
2. The image admission steps and KMS disk-key authorization policy, including whether a changed image could receive the same disk key.
3. The supported way to disable or fix the injected pre-launch script and guest administration, exec, and update paths for this image.

If custom images are not supported on this tuple, please identify the production-supported alternative. This is an information request only; please do not change our running CVM or create resources.
