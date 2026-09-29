#!/usr/bin/env python3
"""Reject an unexpected generated systemd initrd before mkosi writes its cpio.

This checks the separate, kernel-independent initrd subimage. It cannot audit
mkosi's later appended kernel-modules initrd or the final signed UKI.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


# The required files are supplied by the locked Debian systemd,
# systemd-cryptsetup, udev, dmsetup and kmod package seeds. Pinned mkosi 25.3
# creates /init only if ExtraTrees did not supply it; it also creates
# /etc/initrd-release before running finalize scripts.
# prepare.py replaces this marker with the hash of the separately pinned
# x86_64 Rust PID1 artifact. Running an unstaged audit fails closed.
EXPECTED_INIT_SHA256 = "__STAGED_INIT_SHA256__"
# The retained mount(8) must match the hash-verified signed package ELF.
EXPECTED_MOUNT_SHA256 = "__STAGED_MOUNT_SHA256__"
REQUIRED_EXECUTABLES = (
    "usr/lib/systemd/systemd",
    "usr/lib/systemd/systemd-modules-load",
    "usr/lib/systemd/systemd-veritysetup",
    "usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "usr/bin/udevadm",
    "usr/bin/kmod",
    "usr/sbin/dmsetup",
)
REQUIRED_UNITS = (
    "usr/lib/systemd/system/initrd.target",
    "usr/lib/systemd/system/initrd-root-fs.target",
    "usr/lib/systemd/system/systemd-modules-load.service",
    "usr/lib/systemd/system/systemd-udevd.service",
)
FORBIDDEN_UNITS = (
    "rescue.service", "rescue.target", "emergency.service", "emergency.target",
    "debug-shell.service", "getty.target", "getty@.service", "serial-getty@.service",
    "console-getty.service", "container-getty@.service",
    "runlevel1.target",
    "systemd-sysext.service", "systemd-sysext.socket",
    "systemd-sysext@.service", "systemd-confext.service",
    "systemd-udev-load-credentials.service",
)
FORBIDDEN_DIAGNOSTIC_UNITS = ("systemd-pstore.service",)
FORBIDDEN_CONFIG_UNITS = ("systemd-network-generator.service",)
FORBIDDEN_EXECUTABLES = (
    "usr/lib/systemd/systemd-sulogin-shell", "usr/sbin/sulogin",
    "usr/bin/bash", "usr/bin/dash", "usr/bin/sh", "usr/bin/perl",
    "usr/bin/perl5.40.1", "usr/bin/login",
    "usr/bin/su", "usr/bin/sudo", "usr/bin/pkexec", "usr/sbin/sshd",
    "usr/bin/umount", "usr/sbin/losetup", "usr/sbin/swapon", "usr/sbin/swapoff",
    "bin/bash", "bin/dash", "bin/sh", "bin/login", "bin/su", "sbin/sulogin",
)
FORBIDDEN_TREES = (
    "usr/lib/modules", "usr/lib/zrpc", "etc/zrpc", "etc/ssh",
    "var/lib/zebra", "boot", "efi",
)
FORBIDDEN_FILES = (
    "usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf",
)
FORBIDDEN_DIRECTORIES = (
    "var/log/journal", "var/mail",
)
CREDENTIAL_TREES = (
    "etc/credstore", "etc/credstore.encrypted", "usr/lib/credstore",
    "usr/lib/credstore.encrypted",
)


def present(path):
    return path.exists() or path.is_symlink()


def directory(root, relative):
    path = root / relative
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"initrd directory missing or redirected: {relative}")


def regular(root, relative, executable=False):
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"initrd required file missing or redirected: {relative}")
    mode = path.stat().st_mode
    if mode & 0o022 or (executable and not mode & 0o111):
        raise ValueError(f"initrd required file permissions differ: {relative}")


def exact_symlink(root, relative, target):
    path = root / relative
    if not path.is_symlink() or path.readlink() != Path(target):
        raise ValueError(f"initrd entry missing or redirected: {relative}")


def audit(root, expected_init_sha256=EXPECTED_INIT_SHA256,
          expected_mount_sha256=EXPECTED_MOUNT_SHA256):
    if root.is_symlink() or not root.is_dir() or root.resolve() == Path("/"):
        raise ValueError("explicit initrd build root required")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_init_sha256):
        raise ValueError("early init artifact identity absent")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_mount_sha256):
        raise ValueError("initrd mount artifact identity absent")
    for relative in ("proc", "etc", "usr", "usr/bin", "usr/lib", "usr/lib/systemd",
                     "usr/lib/systemd/system", "usr/lib/systemd/system-generators",
                     "usr/sbin"):
        directory(root, relative)
    regular(root, "init", executable=True)
    with (root / "init").open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected_init_sha256:
            raise ValueError("early init differs from pinned artifact")
    exact_symlink(root, "etc/initrd-release", "/etc/os-release")
    # The locked Debian base-files archive owns this relative link and target.
    # Resolving an absolute guest link with Path.is_file() could inspect the
    # builder host instead of the initrd tree.
    exact_symlink(root, "etc/os-release", "../usr/lib/os-release")
    regular(root, "usr/lib/os-release")
    for relative in REQUIRED_EXECUTABLES:
        regular(root, relative, executable=True)
    # systemd's sysroot.mount executes mount(8) in the initrd. Keep the
    # signed-package ELF, but never its package-default setuid privilege.
    mount = root / "usr/bin/mount"
    try:
        descriptor = os.open(mount, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError("initrd required file missing or redirected: usr/bin/mount") from error
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("initrd required file missing or redirected: usr/bin/mount")
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o555:
            raise ValueError("initrd mount ownership or permissions differ")
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected_mount_sha256:
            raise ValueError("initrd mount differs from pinned package artifact")
    for relative in REQUIRED_UNITS:
        regular(root, relative)
    exact_symlink(root, "usr/lib/systemd/systemd-udevd", "../../bin/udevadm")

    for unit_dir in ("etc/systemd/system", "usr/lib/systemd/system"):
        directory(root, unit_dir)
        for path in (root / unit_dir).rglob("*"):
            if path.name in FORBIDDEN_CONFIG_UNITS or (
                path.is_symlink() and path.readlink().name in FORBIDDEN_CONFIG_UNITS
            ):
                raise ValueError(f"initrd mutable configuration unit remains: {path.relative_to(root)}")
            if path.name in FORBIDDEN_DIAGNOSTIC_UNITS or (
                path.is_symlink() and path.readlink().name in FORBIDDEN_DIAGNOSTIC_UNITS
            ):
                raise ValueError(f"initrd diagnostic unit remains: {path.relative_to(root)}")
            if path.name in FORBIDDEN_UNITS or (
                path.is_symlink() and path.readlink().name in FORBIDDEN_UNITS
            ):
                raise ValueError(f"initrd administrative unit remains: {path.relative_to(root)}")
    for relative in FORBIDDEN_EXECUTABLES:
        if present(root / relative):
            raise ValueError(f"initrd administrative executable remains: {relative}")
    for relative in FORBIDDEN_TREES:
        path = root / relative
        if path.is_symlink() or (path.is_dir() and any(path.iterdir())) or (present(path) and not path.is_dir()):
            raise ValueError(f"initrd unexpected content remains: {relative}")
    for relative in FORBIDDEN_FILES:
        if present(root / relative):
            raise ValueError(f"initrd forbidden file remains: {relative}")
    for relative in FORBIDDEN_DIRECTORIES:
        if present(root / relative):
            raise ValueError(f"initrd forbidden directory remains: {relative}")
    for relative in CREDENTIAL_TREES:
        path = root / relative
        if path.is_symlink() or (path.is_dir() and any(path.iterdir())) or (present(path) and not path.is_dir()):
            raise ValueError(f"initrd credential store is not empty: {relative}")
    # sd-stub adds only its signed .osrel file after this initrd is unpacked.
    # No companion tree belongs in the base initrd itself.
    if present(root / ".extra"):
        raise ValueError("base initrd contains a stub companion tree")
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError(f"initrd privileged file remains: {path.relative_to(root)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(os.environ["BUILDROOT"]) if "BUILDROOT" in os.environ else None)
    args = parser.parse_args()
    try:
        if args.root is None:
            raise ValueError("initrd build root absent")
        audit(args.root)
        print("Generated initrd surface audit passed; final UKI and boot remain unverified.")
    except (OSError, ValueError) as error:
        print("Initrd build rejected: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
