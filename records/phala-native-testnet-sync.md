# Native ARM64 public Testnet import and catch-up — 2026-09-30

This is local public-chain evidence. It is not a Phala guest boot, a TDX quote,
an approved release, or a private-query test. No cloud resource was created.

The managed ARM64 container ran the reviewed
`deploy/phala/image/snapshot_import.py` against the selected unsigned snapshot
lock. The archive download completed at exactly 11,137,971,554 bytes and passed
its pinned SHA-256
`e1702bb220a337f94496e1f65b683b63f22334fdc500c5421dd118e593358636`.
The importer exited 0, published `state/v28/testnet`, and wrote a marker binding
that archive to snapshot-lock SHA-256
`a05312fe3fa447e33c48c94c512e7e6e3fcade103f9204a27516a1fdcdcc70ac`.
The compressed archive was removed. A Colima restart released its deleted-file
handle; the imported marker survived the new VM boot. The independent archive
scan and measured 24,612,598,918-byte peak floor are in
`records/phala-snapshot-size-verification.md`.

Local decompression used the PyPI `zstandard==0.25.0` CPython 3.13 ARM64 wheel,
5,063,001 bytes, SHA-256
`bfc4e20784722098822e3eee42b8e576b379ed72cca4a7cb856ae733e62192ea`.
The exact PyPI metadata, an empty OSV PyPI version-query result, wheel bytes,
safe extraction, and native module import were checked on 2026-09-30. The
tracked `tools/phala-local/import_snapshot_arm64.py` and adjacent local lock
make that preparation repeatable without installing packages or running wheel
hooks. Its completed-state idempotence and four focused negative tests passed
inside the managed container. The full 11 GB import used an earlier local
scratch driver calling the same production importer; the tracked wrapper's
fresh-import branch has not itself repeated that transfer.

The [ARM64 Zebra v6.4.2 stage](https://github.com/tamnys/ZECret-service/pull/230)
provided ELF SHA-256
`2eadc8f8f9a56df78526420703bfa56bd0e04f5eab89d213ffc1c973eda5cde9`.
Its release-age exception is local only; its signed checksums and build
attestation were verified with the patched pinned Cosign tool. Zebra ran
natively in the managed ARM64 container with the imported state. Authenticated
loopback `getblockchaininfo` reported `chain: "test"` and advanced from block
4,385,476 to 4,419,457; the latter response reported equal `blocks` and
`headers` and `verificationprogress: 0.9999997737279096`. The public fixture
address `tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3` returned `balance: 0` and
`received: 0` with no RPC error. The RPC cookie was in `/dev/shm`; loopback
accepted a TCP connection and the container's non-loopback address refused it.
No container port was published.

At the near-tip observation, Zebra's process RSS was 711,252 kB and its high
water mark was 715,208 kB; container cgroup memory was 1,539,530,752 bytes.
These are local node-only samples, not a sizing result for the complete Phala
guest. The detached Zebra process continued after its launcher shell exited.
This evidence does not establish current peer-tip agreement, sustained memory
fit, Phala guest integrity, attestation, deletion readiness, or private mode.
