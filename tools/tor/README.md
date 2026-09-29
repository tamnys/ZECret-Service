# Pinned local Tor for the Linux arm64 demo client

`prepare.py` stages Tor 0.4.9.13 from the Tor Project's Debian trixie arm64
package. It verifies the committed, signed `InRelease` against the Tor Project
[Debian repository key](https://support.torproject.org/little-t-tor/getting-started/installing/)
(primary fingerprint `A3C4 F0F9 79CA A22C DBA8 F512 EE8C BC9E 886D DD89`),
checks its `Packages.gz` digest, then checks the exact package identity, size,
and SHA-256 before extracting `/usr/bin/tor`. It does not install the package
or run its maintainer scripts.

From the repository root in the managed Linux arm64 **browser-profile**
container shell, stage Tor on the workspace volume:

```sh
python3 tools/tor/prepare.py --output /workspace/.codex-tmp/tor-package
```

The pinned package's seven-day release hold ends **September 30, 2026 at
19:26:42 UTC**. The command refuses to download or stage it before then. The
signed repository snapshot expires **November 4, 2026 at 11:28:01 UTC**; staging
after that date requires a refreshed, reviewed pin.

Pass `/workspace/.codex-tmp/tor-package/bin/tor` as the native client's
`--tor-executable`. The client launches its own Tor process with a private
Unix SOCKS socket and requires that process for the connection. The managed
container must provide the package's Debian trixie runtime libraries; this
preparation does not install them. It does not approve the Phala workload or
private RPC.

The package targets Linux arm64 and is not a native macOS executable. The demo
client runs in the managed container on the Mac mini; the Mac mini's separate
Colima Linux VM is the candidate external deletion-watchdog host.
