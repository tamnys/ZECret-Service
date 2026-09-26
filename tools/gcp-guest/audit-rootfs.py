#!/usr/bin/env python3
"""Fail the local image build on unapproved guest surfaces; no release approval."""
import argparse
import os
from pathlib import Path
import stat
import sys

FORBIDDEN_BINARIES = ("usr/sbin/sshd", "usr/bin/docker", "usr/bin/containerd", "usr/bin/ctr", "usr/bin/google_guest_agent", "usr/bin/google_osconfig_agent", "usr/bin/dstack-guest-agent", "usr/bin/sudo", "usr/bin/pkexec")
MASKED_UNITS = ("ssh.service", "sshd.service", "ssh.socket", "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service", "debug-shell.service", "rescue.service", "rescue.target", "emergency.service", "emergency.target", "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service", "systemd-confext.service", "systemd-firstboot.service", "cloud-init.service", "cloud-final.service", "google-guest-agent.service", "google-osconfig-agent.service")

def audit(root):
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path("/"):
        raise ValueError("explicit build root required")
    for name in FORBIDDEN_BINARIES:
        if (root / name).exists() or (root / name).is_symlink():
            raise ValueError("administrative binary present")
    for unit in MASKED_UNITS:
        path = root / "etc/systemd/system" / unit
        if not path.is_symlink() or path.readlink() != Path("/dev/null"):
            raise ValueError("administrative unit unmasked")
    for account in ("root", "zrpc-node", "zrpc-wrapper"):
        entries = [line.split(":") for line in (root / "etc/passwd").read_text().splitlines() if line.split(":")[0] == account]
        if len(entries) != 1 or (account != "root" and entries[0][-1] != "/usr/sbin/nologin"):
            raise ValueError("guest account surface differs")
        shadow = [line.split(":") for line in (root / "etc/shadow").read_text().splitlines() if line.split(":")[0] == account]
        if len(shadow) != 1 or not shadow[0][1].startswith(("!", "*")):
            raise ValueError("guest account is not locked")
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError("setuid/setgid executable remains")
        if path.name.endswith((".addon.efi", ".cred", ".raw")) and ("boot" in relative.parts or "credstore" in relative.parts):
            raise ValueError("unapproved boot companion or credential")
        if path.name.endswith(".extra.d") or relative.parts[:2] == ("etc", "extensions") or relative.parts[:3] == ("usr", "lib", "extensions"):
            raise ValueError("boot extension input remains")
        if path.is_file() and not path.is_symlink() and ("credstore" in relative.parts or "credstore.encrypted" in relative.parts):
            raise ValueError("guest credential store must be empty")
    for name in ("zrpc-node-wrapper", "zrpc-gcp-quote-broker", "zrpc-gcp-guard", "zrpc-gcp-cookie", "zebrad"):
        path = root / "usr/lib/zrpc" / name
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o022:
            raise ValueError("guest executable missing or mutable")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(os.environ["BUILDROOT"]) if "BUILDROOT" in os.environ else None)
    args = parser.parse_args()
    try:
        if args.root is None:
            raise ValueError("build root absent")
        audit(args.root)
        print("Rootfs surface audit passed; boot/TDX/release acceptance remains separate.")
    except (OSError, ValueError, IndexError) as error:
        print("Rootfs build rejected: " + str(error), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
