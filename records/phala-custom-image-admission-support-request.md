Subject: Custom production TDX image and KMS admission on prod9

Hi Phala team,

We're preparing a Zcash Testnet RPC guest based on the catalog-matched
`dstack-0.5.9-bd369a8c` source. It needs to keep container runtime and private
request state in memory, disable guest administrative access, and fail closed if
startup preparation fails. We have not built or submitted a production image.

Can a project-built image with these changes run on `prod9` with the
`phala-prod9` KMS? If so, please point us to the supported base version, image
build and admission process, and the artifact and measurement references we
would need to verify it independently. Please also identify the KMS
authorization policy for the image and whether a changed image could obtain the
same app disk key.

For that approved image, can we disable Phala's injected pre-launch script and
other mutable startup or guest-administration paths? If this image route is not
supported, which production-supported route meets those requirements?

This is an information request only; please do not change our running CVM or
create resources in response.
