# GCP guest builder follow-up, 2026-09-26

This is a local source/input checkpoint, not a built guest or release approval.
No cloud API, image publication, signing operation, package installation, or
privileged build was performed.

## Debian trust input and authenticated metadata

The repository now contains the public Debian 12 archive, Debian 13 archive,
and Debian 13 release keys fetched from the [Debian FTP master key directory](https://ftp-master.debian.org/keys/).
The Debian 13 archive key download matched the SHA-256 published in the
[Debian key announcement](https://lists.debian.org/debian-devel/2025/04/msg00079.html):
`6f1d277429dd7ffedcc6f8688a7ad9a458859b1139ffa026d1eeaadcbffb0da7`.
The accepted primary archive fingerprint is
`04B54C3CDCA79751B16BC6B5225629DF75B188BD`, also listed on the
[FTP master signing-key page](https://ftp-master.debian.org/keys.html).
The three source ASC hashes and derived combined binary keyring hash are pinned
in `deploy/gcp/guest/input-identities.json` and the verifier source. The Debian
12 and release 13 keys permit verification of all signatures currently present
on the InRelease; acceptance requires a valid Debian 13 archive signature.

Fetched `dists/trixie/InRelease` from the exact
`20260926T000000Z` [Debian snapshot](https://snapshot.debian.org/) and compared
its SHA-256 with the previously saved file: both were
`0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675`.
The managed container's maintained GnuPG verified the InRelease against the
pinned three-key keyring with exit 0. The status contained `VALIDSIG` for the
Debian 13 archive primary fingerprint above, plus the Debian 12 archive and
Debian 13 release signatures. This authenticates that Release file, not the
mkosi `.dsc` by itself, a package closure, or an image. Source membership is
checked separately below.

The Release file signs `main/binary-amd64/Packages.xz` at SHA-256
`7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498`
and 9,678,380 bytes. Downloading it through the snapshot's SHA-256 by-hash
path produced the same digest. The local parser read 68,825 package records.
These files are scratch inputs under `.codex-tmp/gcp-source`, not a committed
package lock.

## Staging change and limits

`tools/gcp-guest/prepare.py` now requires lock schema 2, a signed InRelease,
the matching `Packages.xz`, and local content-addressed `.deb` files whose
name, version, architecture, archive path, size, and SHA-256 agree with the
signed package index. It sets the source date from the signed Release date and
rejects a Release newer than the selected snapshot. Staging pins package
versions in mkosi and includes the verified local archive files. A missing,
unmatched, or invalid-signature `gpgv` blocks staging before output creation.
The accepted executable hash is pinned to Debian `gpgv`
`2.4.7-21+deb13u1+b5`, whose `.deb` hash was read from the signed package index.
This pins the executable bytes, but its dynamic library and builder image
closure still need review. No verifier
network fetch or automatic trust update was added.

The exact complete dependency closure, mkosi/tooling authentication, base-tree
contents, kernel/initramfs provenance, Zebra eligibility, installed-package
comparison, and actual image build remain open. Staging remains explicitly
`staged-unbuilt-unapproved` and does not authorize private mode. The untrusted
amd64 managed profile still lacks an installed `gpgv` and the other image-building
tools. Its builder preflight remains blocked. `inspect-inputs` reports matched
offline signatures and hashes with toolchain review pending, rather than full
authentication of all build inputs.

## Verification

`python3 tools/gcp-guest/test_prepare.py` passed 10 synthetic tests in the
managed untrusted amd64 container. Those tests cover missing/changed inputs,
signature-gate refusal, staged configuration, signed-index/hash mismatch,
keyring and `gpgv` identity, configuration injection, prohibited packages,
and rootfs restrictions; the positive
test mocks signature verification and cannot establish real trust. The pinned
mkosi 25.3 parser accepted the generated staged synthetic configuration with
`summary` exit 0. No image build or systemd boot was attempted.

For an additional source-backed integration check, the Debian `gpgv` amd64
package was fetched from the selected snapshot at SHA-256
`104e4c57b98f0b883aa94c68fbe7ec7b48bcdec7c0f9dedf2a51a5054aaeb5ae`,
matching the signed index. `dpkg-deb -x` extracted it as data without running
package scripts or installing it. Its executable hash was
`3f29dddc10e4089aeac5b2675313f4e5fe822abe5ab3bf7898d238c32d758304`.
That exact `gpgv` verified the saved InRelease with exit 0, and the verifier's
`verify_signature()` accepted it through the pinned-key and pinned-executable
path. Three actual Debian `.deb` files named in the signed index were fetched
and hash-checked; staging them with **synthetic remaining guest artifacts**
returned `staged-unbuilt-unapproved` and parsed with mkosi 25.3 `summary` exit 0.
This proves the local metadata/package path can run. It does not prove package
closure, reviewed toolchain libraries, an image, or approved guest execution.

## Signed mkosi source membership, 2026-09-27 UTC

The same authenticated InRelease signs `main/source/Sources.xz` at SHA-256
`6002f81f463a2d976d84b34170367cc16da2d60bd0ba9ab9d868d6e1c1a935d9`
and 10,540,436 bytes. The index was downloaded from that hash's immutable
snapshot path and matched both the signed Release entry and the pinned local
identity. Its single `mkosi` version `25.3-7` record binds the `.dsc`, upstream
tarball, and Debian patch tarball to the SHA-256 values already recorded in
`input-identities.json`; the local copies of all three match those hashes and
sizes. `tools/gcp-guest/verify_mkosi_source.py` repeats this check using the
pinned Debian keyring and executable hash. The real-input invocation returned
`source-membership-verified-toolchain-unreviewed`; four synthetic parser tests
passed in the managed amd64 container.

This resolves source-archive membership in Debian's signed snapshot. It does
not authenticate the extracted `gpgv` dynamic-library closure, establish that
the upstream release tar corresponds to the separately recorded Git commit,
authenticate the installed mkosi/systemd/apt toolchain, complete the package
closure, or build the guest. The managed amd64 container remains UID 502 with
zero effective capabilities, `NoNewPrivs: 1`, active seccomp, and denied
`CLONE_NEWUSER`; it also lacks mkosi, systemd-repart, ukify, gpgv, sbsign, and
veritysetup. The pinned [mkosi 25.3 requirements](https://github.com/systemd/mkosi/blob/54c625c380ef5500f17460981a3c67b109b6a847/mkosi/resources/man/mkosi.1.md#requirements)
require namespace creation. Its offline repart mode avoids loop devices but
does not avoid the namespace requirement. The next image-building step needs a
reviewed managed builder with that capability and a fully authenticated
toolchain; changing this guest preparer cannot make the current container
build-capable.

## Snapshot hold correction, 2026-09-27 UTC

The September 26 snapshot URL above had authenticated metadata, but did not
meet the managed APT policy's seven-day snapshot hold. The
[September 18 snapshot](https://snapshot.debian.org/archive/debian/20260918T000000Z/)
does meet that hold. Its `dists/trixie/InRelease`,
`main/binary-amd64/Packages.xz`, and `main/source/Sources.xz` were fetched into
ignored workspace scratch storage through the managed untrusted amd64 container.
Their respective SHA-256 values were exactly the previously authenticated
`0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675`,
`7778d3e3f303b7ddb8ce0fe7c8d57473a076c6bf2e8f241f75421d2396352498`,
and `6002f81f463a2d976d84b34170367cc16da2d60bd0ba9ab9d868d6e1c1a935d9`.
The signed archive contents therefore remain byte-identical while the selected
snapshot timestamp clears the hold. `input-identities.json` now names the older
snapshot. The pinned `verify_mkosi_source.py` accepted the September 18
InRelease and Sources index with status
`source-membership-verified-toolchain-unreviewed`; its four synthetic tests
passed. No package closure, builder toolchain, or guest image was accepted by
this check.
