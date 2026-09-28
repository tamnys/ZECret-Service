#!/usr/bin/env python3
"""Fail the local image build on unapproved guest surfaces; no release approval."""
import argparse
import os
from pathlib import Path
import stat
import sys

FORBIDDEN_BINARIES = ("usr/sbin/sshd", "usr/bin/docker", "usr/bin/containerd", "usr/bin/ctr", "usr/bin/google_guest_agent", "usr/bin/google_osconfig_agent", "usr/bin/dstack-guest-agent", "usr/bin/sudo", "usr/bin/pkexec", "usr/sbin/unix_chkpwd", "usr/bin/mount", "usr/bin/umount", "usr/bin/su", "usr/lib/dbus-1.0/dbus-daemon-launch-helper")
MASKED_UNITS = (
    "ssh.service", "sshd.service", "ssh.socket",
    "getty.target", "getty@.service", "serial-getty@.service", "console-getty.service", "container-getty@.service",
    "debug-shell.service", "rescue.service", "rescue.target", "emergency.service", "emergency.target",
    "systemd-hibernate.service", "systemd-suspend.service", "systemd-hybrid-sleep.service", "systemd-suspend-then-hibernate.service",
    "systemd-coredump.socket", "systemd-pstore.service", "systemd-sysext.service", "systemd-sysext.socket",
    "systemd-sysext@.service", "systemd-confext.service", "systemd-udev-load-credentials.service",
    "systemd-sysupdate.service", "systemd-sysupdate.timer", "systemd-firstboot.service", "systemd-sysusers.service",
    "systemd-user-sessions.service", "cloud-init.service", "cloud-final.service",
    "google-guest-agent.service", "google-osconfig-agent.service", "apt-daily.timer", "apt-daily-upgrade.timer",
)
APPLIANCE_UNITS = (
    "zrpc-node.service", "zrpc-gcp-quote.service", "zrpc-cookie.service",
    "zrpc-wrapper.service", "zrpc.target",
)
PROTECTED_UNITS = (*APPLIANCE_UNITS, "multi-user.target")
# Debian trixie's systemd.unit(5) load path. Runtime generators and transient
# units must also be checked on the exact booted image; they do not exist in a
# finalized rootfs and this audit does not claim to check their later output.
UNIT_DIRS = (
    "etc/systemd/system.control", "run/systemd/system.control",
    "run/systemd/transient", "run/systemd/generator.early",
    "etc/systemd/system", "etc/systemd/system.attached",
    "run/systemd/system", "run/systemd/system.attached",
    "run/systemd/generator", "usr/local/lib/systemd/system",
    "usr/lib/systemd/system", "run/systemd/generator.late",
)


def present(path):
    return path.exists() or path.is_symlink()


def protected_unit_additions(units):
    """Names whose systemd load semantics can alter an appliance unit."""
    names = {"service.d", "target.d"}
    for unit in units:
        names.update(f"{unit}.{suffix}" for suffix in ("d", "wants", "requires", "upholds"))
        stem, kind = unit.rsplit(".", 1)
        for index, character in enumerate(stem):
            if character == "-":
                names.add(f"{stem[:index + 1]}.{kind}.d")
    return names


def protected_aliases(root):
    """Follow effective static unit-name aliases, including Debian runlevels."""
    effective = {}
    for relative in UNIT_DIRS:
        directory = root / relative
        if not present(directory):
            continue
        if not directory.is_dir():
            raise ValueError("system unit load path redirected")
        for entry in directory.iterdir():
            if entry.name.endswith((".service", ".target")) and entry.name not in effective:
                effective[entry.name] = entry.readlink().name if entry.is_symlink() else None
    protected = set(PROTECTED_UNITS)
    while True:
        aliases = {name for name, target in effective.items() if target in protected}
        if aliases <= protected:
            return protected
        protected.update(aliases)


def audit_appliance_units(root):
    for relative in UNIT_DIRS:
        path = root
        for component in Path(relative).parts:
            path = path / component
            if path.is_symlink():
                raise ValueError("system unit load path redirected")
    vendor = root / "usr/lib/systemd/system"
    if vendor.is_symlink() or not vendor.is_dir():
        raise ValueError("appliance unit directory missing or redirected")
    for unit in APPLIANCE_UNITS:
        path = vendor / unit
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o022:
            raise ValueError("appliance unit missing or mutable")

    configured = root / "etc/systemd/system"
    if configured.is_symlink() or not configured.is_dir():
        raise ValueError("system unit configuration directory missing or redirected")
    default = configured / "default.target"
    if not default.is_symlink() or default.readlink() != Path("/usr/lib/systemd/system/zrpc.target"):
        raise ValueError("appliance default target differs")
    wants = configured / "multi-user.target.wants"
    network_units = {"systemd-networkd.service", "systemd-resolved.service"}
    if wants.is_symlink() or not wants.is_dir() or {entry.name for entry in wants.iterdir()} != network_units:
        raise ValueError("appliance boot dependencies differ")
    for unit in network_units:
        path = wants / unit
        if not path.is_symlink() or path.readlink() != Path("/usr/lib/systemd/system") / unit:
            raise ValueError("appliance network dependency differs")

    additions = protected_unit_additions(protected_aliases(root))
    for relative in UNIT_DIRS:
        directory = root / relative
        if not present(directory):
            continue
        if not directory.is_dir():
            raise ValueError("system unit load path redirected")
        for name in additions:
            # The exact /etc network wants are checked above. Debian may
            # install vendor wants; their final set remains an image-review
            # gate, not a license for extra wants in other load paths.
            if name == "multi-user.target.wants" and directory in (configured, vendor):
                continue
            if present(directory / name):
                raise ValueError("appliance unit override or dependency present")
        if directory != vendor:
            for unit in PROTECTED_UNITS:
                if present(directory / unit):
                    raise ValueError("appliance unit replaced")
        # An alias carries its own drop-ins into the target unit. The image
        # recipe declares only default.target -> zrpc.target as such an alias.
        for path in directory.iterdir():
            if not path.is_symlink() or path == default:
                continue
            if path.readlink().name in APPLIANCE_UNITS:
                raise ValueError("unreviewed appliance unit alias")

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
    if passwd.keys() != shadow.keys():
        raise ValueError(
            "guest passwd and shadow accounts differ: "
            f"passwd_only={sorted(passwd.keys() - shadow.keys())!r}, "
            f"shadow_only={sorted(shadow.keys() - passwd.keys())!r}")
    for name, entry in passwd.items():
        if entry[1] != "x" or not shadow[name][1].startswith(("!", "*")):
            raise ValueError("guest account missing or unlocked")
        try:
            uid, gid = int(entry[2]), int(entry[3])
        except ValueError as error:
            raise ValueError("guest account identity malformed") from error
        if uid < 0 or gid < 0 or (name != "root" and (uid == 0 or gid == 0)):
            raise ValueError("guest account identity differs")
    if groups.get("root") is None or groups["root"][1:] != ["x", "0", ""]:
        raise ValueError("guest root group missing")
    for name, entry in groups.items():
        try:
            gid = int(entry[2])
        except ValueError as error:
            raise ValueError("guest group GID malformed") from error
        if gid < 0 or (gid == 0) != (name == "root"):
            raise ValueError("guest group identity differs")
        members = entry[3].split(",") if entry[3] else []
        for member in members:
            if member in {"systemd-network", "systemd-resolve", "zrpc-node", "zrpc-wrapper"}:
                if not ((name == "zrpc-cookie" and member in {"zrpc-node", "zrpc-wrapper"})
                        or (name == member and member in {"zrpc-node", "zrpc-wrapper"})):
                    raise ValueError("guest service has unreviewed supplementary group")
    expected = {"root": (0, 0), "systemd-network": None,
                "systemd-resolve": None, "zrpc-node": None,
                "zrpc-wrapper": None}
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
        if name == "root" and (entry[6] != "/usr/sbin/nologin" or password[1] != "!*"):
            raise ValueError("guest root login policy differs")
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
                    or entry[5:] != [
                        "/" if name in {"systemd-network", "systemd-resolve"}
                        else "/nonexistent", "/usr/sbin/nologin"]
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
    for name in ("systemd-network", "systemd-resolve", "zrpc-node",
                 "zrpc-wrapper", "zrpc-cookie"):
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
        expected_members = ({"zrpc-node", "zrpc-wrapper"} if name == "zrpc-cookie"
                            else set() if name in {"systemd-network", "systemd-resolve"}
                            else {name})
        if (
            len(members) != len(set(members))
            or not set(members) <= expected_members
            or (name == "zrpc-cookie" and set(members) != expected_members)
        ):
            raise ValueError("guest service group membership differs")
        protected_gids.add(gid)
    for name, entry in groups.items():
        if name not in ("systemd-network", "systemd-resolve", "zrpc-node",
                        "zrpc-wrapper", "zrpc-cookie"):
            try:
                gid = int(entry[2])
            except ValueError as error:
                raise ValueError("guest group GID malformed") from error
            if gid in protected_gids:
                raise ValueError("guest service GID has an alias")

def audit(root):
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path("/"):
        raise ValueError("explicit build root required")
    # This direct-UKI recipe generates /efi only after the finalize audit.
    # Repart copies its entire contents to the ESP, where systemd-stub can
    # consume global addons and credentials outside the UKI itself.
    efi = root / "efi"
    if efi.is_symlink() or (efi.exists() and (not efi.is_dir() or any(efi.iterdir()))):
        raise ValueError("unapproved EFI boot input")
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
    audit_appliance_units(root)
    audit_accounts(root)
    privileged = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
            privileged.append(relative.as_posix())
        if path.name.endswith((".addon.efi", ".cred", ".raw")) and ("boot" in relative.parts or "credstore" in relative.parts):
            raise ValueError("unapproved boot companion or credential")
        if path.name.endswith(".extra.d") or relative.parts[:2] == ("etc", "extensions") or relative.parts[:3] == ("usr", "lib", "extensions"):
            raise ValueError("boot extension input remains")
        if path.is_file() and not path.is_symlink() and ("credstore" in relative.parts or "credstore.encrypted" in relative.parts):
            raise ValueError("guest credential store must be empty")
    if privileged:
        raise ValueError("setuid/setgid executable remains: " + repr(sorted(privileged)))
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
