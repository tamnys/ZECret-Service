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

An opt-in Rust integration test now exercises the production `LocalNode`
adapter against this same native Zebra process. Inside the managed container,
with `ZRPC_LIVE_ZEBRA_RPC=127.0.0.1:18232` and
`ZRPC_LIVE_ZEBRA_COOKIE=/dev/shm/zrpc-local-node-cookie/.cookie`,
`cargo test --locked -p zrpc-server --test live_zebra -- --ignored` passed on
2026-09-30. It loaded the cookie through the adapter's tmpfs/ownership checks,
read Testnet `getblockchaininfo`, and sent a checksum-validated public
transparent-address balance request. At 04:51 UTC the node reported equal
block and header height 4,419,664. `cargo fmt --all -- --check` passed. The
test does not use a TEE quote, TLS listener, Tor, or the native client.

At the near-tip observation, Zebra's process RSS was 711,252 kB and its high
water mark was 715,208 kB; container cgroup memory was 1,539,530,752 bytes.
These are local node-only samples, not a sizing result for the complete Phala
guest. The detached Zebra process continued after its launcher shell exited.
This evidence does not establish current peer-tip agreement, sustained memory
fit, Phala guest integrity, attestation, deletion readiness, or private mode.

## Later catch-up observation — 2026-09-30 06:34 UTC

The same running native ARM64 Zebra process returned Testnet block and header
height **4,419,929** with `verificationprogress: 1.0` through authenticated
loopback `getblockchaininfo`. A separate authenticated `getpeerinfo` request
returned **26 peers**. The process had run for 2 hours 16 minutes in that
container and had RSS **841,200 kB**; its container cgroup reported
**3,605,852,160 bytes** of memory in use, including other processes and cache.
The imported public-state directory occupied about **13 GiB** on the workspace
volume, which reported **18 GiB** available. The compressed snapshot archive
was already removed. No port was published and no cloud resource was created.

This is stronger evidence that local import and network catch-up work, but the
height was not independently compared with an authoritative public Testnet
tip. The ARM64 node-only measurements do not establish the full x86_64 Phala
guest's 8 GB memory fit, 80 GB storage fit, startup timing or private mode.
The production `LocalNode` integration test above was not rerun: its code and
the node configuration had not changed since its passing run.

## Independent tip comparison — 2026-09-30 06:46 UTC

A fresh authenticated loopback `getblockchaininfo` response from the same
native ARM64 Zebra process reported `chain: "test"`, equal block and header
height **4,419,945**, `verificationprogress: 1.0`, and best-block hash
`00000731fb90927bc71b4e7a5f7fc82099fc03bbcbb29be1902950d85977e9a0`.
Within the same observation window, the
[CipherScan Testnet API](https://api.testnet.cipherscan.app/api/blockchain-info)
reported the same chain, height, header height, progress, and hash. Its
[API documentation](https://cipherscan.app/docs) describes this endpoint as
reading `getblockchaininfo` from its Zebra node. The first external read was
one block behind; a fresh external read matched the local response.

This is a time-bound agreement between two node views, not proof of network
wide consensus or finality. It does not establish a Phala boot, TEE evidence,
private-query protection, or deployment readiness. No Phala resource or spend
was involved.

## Local TLS-to-live-node diagnostic — 2026-09-30

The existing ignored Rust test
`bootstrap::tests::node_listener_reaches_live_zebra_after_synthetic_attestation`
passed inside the managed ARM64 container against the still-running local
Zebra process at `127.0.0.1:18232` and its memory-backed cookie. It exercised
the Rust node listener, an ephemeral TLS connection, a synthetic quote response,
and `getblockchaininfo` plus the public fixture-address balance on that same
connection. The test checks `chain: test` and typed result fields but does not
record a new block-height value. It does not verify the fake quote, use Tor or
the native client, start a Phala guest, or approve private mode. The packaged
x86_64 cold-node counterpart is recorded in
[the native image smoke](phala-native-mount-smoke.md).
