# GCP guest image source contract, 2026-09-26

This is a local source audit, not an image build or release approval. No
signing operation or cloud call was performed; private mode remains blocked.

The pinned mkosi 25.3 source installs `Bootloader=uki` at
`/efi/EFI/BOOT/BOOTX64.EFI`, then fills the ESP from the repart `CopyFiles=`
sources. The old ESP definition copied only `/boot`, so its configured UKI
would not enter the ESP. The definition now copies only `/efi:/`. The staging
check rejects a missing `/efi` copy, any extra repart definition, a source
`mkosi.conf.d`/companion file, or drift in the reviewed mkosi settings. This
keeps the source recipe direct-UEFI and excludes unused Type 1 `/boot` entries
from the ESP. It does not prove the contents of a future built ESP.

Mkosi's first repart pass produces the root and root-verity partitions and
returns a root hash; `install_kernel()` adds `roothash=` to the UKI command
line before the second pass fills the ESP. Debian 13's
[verity generator](https://manpages.debian.org/trixie/systemd-cryptsetup/systemd-veritysetup-generator.8.en.html)
derives data/hash partition IDs from that hash, and its
[fstab generator](https://manpages.debian.org/trixie/systemd/systemd-fstab-generator.8.en.html)
mounts `/dev/mapper/root` when `roothash=` is present. Thus disabling GPT
auto-discovery in the fixed command line does not itself disable this verity
root path. This is a source-level conclusion, not a boot or tamper test.

`SecureBoot=yes` tells mkosi to sign the generated UKI. The staged config now
references a builder-only key path at
`/run/zrpc-build-signing/secure-boot.key`, while its locked artifacts include
only the public certificate. Staging does not read or copy the key and cannot
establish that the path exists, is memory-backed, is operator-owned, or matches
the certificate. A later reviewed builder must establish those properties and
record the exact mkosi invocation and signed UKI. The public certificate must
match the Google custom image Secure Boot `db` configuration. Google documents that
[custom Shielded VM certificates are set when creating the image](https://docs.cloud.google.com/compute/shielded-vm/docs/creating-shielded-images),
not enrolled interactively in the guest. Neither signing nor platform support
for the selected configuration has been tested. The public GitHub runner has
not been given a production signing key.

The staging directory is created fresh from the exact reviewed source files;
it does not copy mkosi companion settings or hooks. A later builder command
could still override settings, and the supplied base tree/initrd and output
ESP remain unaudited. Release review must bind the actual build invocation,
final signed PE, UKI sections and command line, root/verity hashes, complete
ESP inventory, Secure Boot variables, firmware evidence, and real boot behavior.
Google's [TDX measurement table](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/measurement-register-contents)
describes the register classes but does not authenticate this unbuilt profile.

The managed amd64 container passed 11 synthetic `test_prepare.py` cases and
mkosi 25.3 parsed the source profile. `prepare.py preflight` still exited 1:
its mkosi/systemd-repart/ukify/gpgv/sbsign/veritysetup tools are absent and
user namespace creation is denied. No raw image, signed UKI, measured root,
reproducibility result, or hardware acceptance exists.
