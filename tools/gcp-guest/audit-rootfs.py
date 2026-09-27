#!/usr/bin/env python3
"""Fail the local image build on unapproved guest surfaces; no release approval."""
import argparse
import os
from pathlib import Path
import stat
import sys

FORBIDDEN_BINARIES = ("usr/sbin/sshd", "usr/bin/docker", "usr/bin/containerd", "usr/bin/ctr", "usr/bin/google_guest_agent", "usr/bin/google_osconfig_agent", "usr/bin/dstack-guest-agent", "usr/bin/sudo", "usr/bin/pkexec")
MASKED_UNITS = (
    "ssh.service", "sshd.service", "ssh.socket",
    "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service", "container-getty@.service",
    "debug-shell.service", "rescue.service", "rescue.target", "emergency.service", "emergency.target",
    "systemd-hibernate.service", "systemd-suspend.service", "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service",
    "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service", "systemd-confext.service",
    "systemd-sysupdate.service", "systemd-sysupdate.timer", "systemd-firstboot.service", "systemd-sysusers.service",
    "systemd-user-sessions.service", "cloud-init.service", "cloud-final.service",
    "google-guest-agent.service", "google-osconfig-agent.service", "apt-daily.timer", "apt-daily-upgrade.timer",
)

def account_file(root, name, fields):
    path = root / "etc" / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("guest account file missing or redirected")
    entries = {}
    for line in path.read_text().splitlines():
        parts = line.split(":")
        if len(parts) != fields or not parts[0] or parts[0] in entries:
            raise ValueError("guest account database malformed or duplicated")
        entries[parts[0]] = parts
    return entries

def audit_accounts(root):
    if (root / "etc").is_symlink():
        raise ValueError("guest account directory redirected")
    passwd = account_file(root, "passwd", 7)
    shadow = account_file(root, "shadow", 9)
    groups = account_file(root, "group", 4)
    expected = {"root": (0, 0), "zrpc-node": None, "zrpc-wrapper": None}
    protected_uids = set()
    for name, fixed in expected.items():
        entry = passwd.get(name)
        password = shadow.get(name)
        if (
            entry is None
            or password is None
            or entry[1] != "x"
            or not password[1].startswith(("!", "*"))
        ):
            raise ValueError("guest account missing or unlocked")
        try:
            uid, gid = int(entry[2]), int(entry[3])
        except ValueError as error:
            raise ValueError("guest account identity malformed") from error
        if (
            uid < 0
            or gid < 0
            or (fixed is not None and (uid, gid) != fixed)
            or (
                name != "root"
                and (
                    uid == 0
                    or gid == 0
                    or entry[5:] != ["/nonexistent", "/usr/sbin/nologin"]
                )
            )
        ):
            raise ValueError("guest account identity differs")
        if uid in protected_uids:
            raise ValueError("guest service UID is shared")
        protected_uids.add(uid)
    for name, entry in passwd.items():
        if name not in expected:
            try:
                uid = int(entry[2])
            except ValueError as error:
                raise ValueError("guest account UID malformed") from error
            if uid in protected_uids:
                raise ValueError("guest service UID has an alias")
    protected_gids = set()
    for name in ("zrpc-node", "zrpc-wrapper", "zrpc-cookie"):
        entry = groups.get(name)
        if entry is None or entry[1] != "x":
            raise ValueError("guest service group missing")
        try:
            gid = int(entry[2])
        except ValueError as error:
            raise ValueError("guest service GID malformed") from error
        if (
            gid <= 0
            or gid in protected_gids
            or (name != "zrpc-cookie" and gid != int(passwd[name][3]))
        ):
            raise ValueError("guest service GID differs")
        members = entry[3].split(",") if entry[3] else []
        expected_members = {"zrpc-node", "zrpc-wrapper"} if name == "zrpc-cookie" else {name}
        if (
            len(members) != len(set(members))
            or not set(members) <= expected_members
            or (name == "zrpc-cookie" and set(members) != expected_members)
        ):
            raise ValueError("guest service group membership differs")
        protected_gids.add(gid)
    for name, entry in groups.items():
        if name not in ("zrpc-node", "zrpc-wrapper", "zrpc-cookie"):
            try:
                gid = int(entry[2])
            except ValueError as error:
                raise ValueError("guest group GID malformed") from error
            if gid in protected_gids:
                raise ValueError("guest service GID has an alias")

def audit(root):
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path("/"):
        raise ValueError("explicit build root required")
    # mkosi prepends these image-tree files to KernelCommandLine=. The UKI must
    # contain only the reviewed flags and mkosi's repart-derived roothash.
    for name in ("etc/kernel/cmdline", "usr/lib/kernel/cmdline"):
        path = root / name
        if path.exists() or path.is_symlink():
            raise ValueError("unreviewed kernel command line source")
    for name in FORBIDDEN_BINARIES:
        if (root / name).exists() or (root / name).is_symlink():
            raise ValueError("administrative binary present")
    for unit in MASKED_UNITS:
        path = root / "etc/systemd/system" / unit
        if not path.is_symlink() or path.readlink() != Path("/dev/null"):
            raise ValueError("administrative unit unmasked")
    audit_accounts(root)
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
