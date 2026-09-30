# Phala public-preview resource sizing — 2026-09-30

This is a local, native ARM64 Zebra observation and a published-rate comparison. It is not a measurement of the complete x86_64 Phala guest, a current account quote, a resource reservation, or approval to deploy or accept private queries.

At 08:23:38 UTC, the existing managed-container Testnet node returned `chain: "test"`, 4,420,060 blocks and headers, and `verificationprogress: 1.0` through its authenticated loopback RPC. The single `zebrad` process reported 843,124 kB RSS and 846,448 kB high-water RSS. Its container reported 4,132,634,624 bytes of current memory, including 790,183,936 bytes anonymous, 3,290,480,640 bytes file-backed cache, and 51,245,056 bytes kernel memory. The container had no cgroup memory limit (`memory.max: max`), and its public state directory occupied 13,714,700,374 bytes. These are point-in-time values; the container also hosts other processes. The earlier import and catch-up evidence is in [the native Testnet sync record](phala-native-testnet-sync.md).

[Zebra's current system requirements](https://zebra.zfnd.org/user/requirements.html) list 4 GB minimum and 16 GB recommended RAM. Its general 300 GB disk recommendation reflects Mainnet; the same page estimates approximately 10 GB of Testnet cache and temporarily about twice the cache size during snapshot extraction. The observed Testnet state is already larger than that published estimate. Neither the ARM64 process RSS nor the container memory total establishes peak x86_64 application, quote bridge, Docker/dstack, snapshot import, or full guest memory use.

The [published Phala instance list](https://cloud.phala.com/about/instance-types) lists `tdx.large` at 4 vCPU, 8 GB RAM and $0.232/hour, and `tdx.xlarge` at 8 vCPU, 16 GB RAM and $0.464/hour. The [published storage rate](https://cloud.phala.com/about/pricing) is $0.000139/GB-hour while running or stopped. For the previously selected 80 GB disk and the authorized **168-hour maximum**, arithmetic on those published rates gives:

| Size | Published compute + 80 GB storage per hour | 168-hour published-rate total |
| --- | ---: | ---: |
| `tdx.large` | $0.24312 | $40.84416 |
| `tdx.xlarge` | $0.47512 | $79.82016 |

These totals exclude any unconfirmed fees, rounding, network charges, and account-specific credits or pricing. The 168 hours are a maximum, not a required rental duration. The existing **$50 total ceiling** and **$45 deletion trigger** remain in force. At published rates, a 168-hour `tdx.xlarge` run would exceed that ceiling; selecting it would require a shorter, separately approved evaluation or a changed operator budget, not an automatic size switch. The September 25 signed-in [account preflight](phala-account-preflight.md) is stale for availability and binding price.

`tdx.large` remains an unproven preview candidate. Before selecting it for a billable run, test the exact x86_64 image with the snapshot import, Zebra, wrapper and quote bridge under the effective guest memory and disk limits; record peak use and failure behavior. Requote the selected account configuration and set external deletion controls before requesting separate spending approval. A native GitHub x86_64 [image smoke](phala-native-image-smoke.md) established basic loader/startup behavior but did not perform that resource-fit test. The stock Phala guest still fails the memory-only runtime and administration requirements for genuine private mode.

The existing no-charge standard GitHub `ubuntu-24.04` x86_64 runner has
[14 GB of storage](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
below the measured **24,612,598,918-byte** simultaneous archive-plus-file-body
floor for this snapshot. It cannot run the full import on its advertised disk,
even before Docker image and filesystem overhead. The local ARM64 import and
the native x86_64 cold-start smoke therefore remain separate evidence; neither
proves the complete x86_64 import or 8 GB guest fit. No paid larger runner was
started for this check.
