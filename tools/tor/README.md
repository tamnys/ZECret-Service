# Pinned local Tor for the Linux arm64 demo client

`prepare.py` stages the Tor 0.4.9.12 executable from the Tor Browser
**16.0a12 alpha Expert Bundle** for Linux arm64. It downloads the exact
archive and detached signature in `bundle.lock.json`, checks their recorded
sizes and SHA-256 hashes, verifies the signature against the committed Tor
Browser Developers public key, and extracts only regular files and directories.
The public key's primary fingerprint is
`EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290` ([Tor's signing
guide](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/)).
The script refuses to replace an existing output directory.

From the repository's managed Linux arm64 **browser-profile** container shell,
stage it once on the workspace volume:

```sh
python3 tools/tor/prepare.py --output /workspace/.codex-tmp/tor-bundle
```

Pass `/workspace/.codex-tmp/tor-bundle/tor/tor` as the native client's
`--tor-executable`. The client launches its own Tor process with a private
Unix SOCKS socket and requires that process for the connection. It does not
accept a general SOCKS proxy as proof of Tor. The executable and local host
remain part of the operator's trust boundary; this preparation does not approve
the Phala workload or private RPC.

The pinned bundle targets Linux arm64 and is not a native macOS executable.
The demo client runs in the managed container on the Mac mini; the Mac mini's
separate Colima Linux VM is the candidate external deletion-watchdog host.
