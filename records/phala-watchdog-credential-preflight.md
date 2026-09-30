# Phala watchdog credential and route preflight — 2026-09-30

The operator explicitly authorized a workspace-scoped, non-expiring Phala API
token for the external deletion watchdog, with revocation after cleanup. The
account offered no delete-only token scope. A password verification was
completed privately in Chrome. The token was copied directly from the
clipboard into an owner-private file in the selected Mac mini's Colima Linux
VM; the clipboard was then cleared. The file is nonempty, ASCII without
whitespace, owned by the VM login UID, and mode 0600. Its bytes, hash, and
workspace identifier are absent from this repository and this record.

A read-only request to Phala's `/api/v1/auth/me` returned HTTP 200 with that
token and yielded a workspace ID, which was saved in a separate mode-0600 VM
file without displaying it. The request used TLS with the independently
selected GTS Root R4 trust anchor; a root-only public API request verified the
current chain, and the selected certificate's SHA-256 fingerprint is
`349DFA4058C5E263123B398AE795573C4E1313C83FE68F93556CD5E8031B3C7D`.
The root's DER copy is in the VM. This validates the current credential and
chain only, not durable network reachability or the Rust provider client.

The current ARM64 `zrpc` CLI was built with `cargo build --locked -p zrpc-cli`
in the managed container, installed as an owner-private executable in the VM,
and ran `lifecycle ledger --help` there. Its source and installed SHA-256 both
equal `b9708198b37a0e9673ffd336753b42d4bf8c7476d61f0dcf38be8b536972f712`.
This is executable compatibility, not an installed deletion job.

The authorized Colima restart recovered Docker, and the local public Testnet
node resumed. Its authenticated loopback RPC returned `chain: test`, equal
block and header height 4,422,624, and progress 1.0. The VM's default
`eth0` route intermittently timed out to the Phala API while a request bound
to the existing `col0` interface succeeded. Its route metrics matched
[Colima issue #1551](https://github.com/abiosoft/colima/issues/1551): `eth0`
200 and `col0` 300. A temporary lower-metric `col0` route gave a 0.36-second
HTTP 200 response, then was removed and verified absent. The operator had
authorized a Colima restart. Its documented `network.preferredRoute` option
was set to `true`, preserving the previous configuration in a local backup.
Normal shutdown hung, so the VM was force-stopped without deleting its disk;
`env -u SSH_AUTH_SOCK colima start` recovered it. After that restart, the
default route selected `col0` and a root-verified Phala API request completed
in 0.24 seconds. Relaunching a managed container restored the separate
`CODEX_EGRESS_POLICY` Docker firewall rules; those rules still reject private
and metadata destinations. This proves one VM restart and the current network
path, not Mac power-loss recovery or continuous provider availability.

The native Rust `zrpc lifecycle observe` command then used the same private
credential file and explicit DER root with a **synthetic, untracked experiment
ledger**. It authenticated to Phala, completed a read-only inventory scan,
and reported zero CVMs. The live identity response measured 1,833 bytes in
0.21 seconds and the empty inventory response 57 bytes in 0.60 seconds; the
synthetic command's supplied bounds are test inputs, not deployment timing or
size allowances. No provider mutation was available through that command.

No systemd watchdog unit or timer is installed, no original experiment ledger
has been initialized, and no Phala CVM or billable resource has been created.
The token must be revoked after all resource deletion and billing checks are
complete.
