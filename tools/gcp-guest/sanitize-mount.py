#!/usr/bin/env python3
"""Strip privilege from the exact signed Debian mount helper before audit.

Systemd needs mount(8) in both the initrd and switched root. The Debian
package may install it setuid; this build-only script checks the package ELF
identity and makes its installed copy non-privileged. It grants no boot or
private-mode approval.
"""

import hashlib
import os
from pathlib import Path
import re
import stat
import sys


EXPECTED_SHA256 = "__STAGED_MOUNT_SHA256__"
EXPECTED_SIZE = "__STAGED_MOUNT_SIZE__"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def sanitize(root, expected_sha256=EXPECTED_SHA256, expected_size=EXPECTED_SIZE):
    root = Path(root)
    if (not root.is_absolute() or root == Path("/") or root.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or not str(expected_size).isdecimal() or int(expected_size) <= 0):
        raise ValueError("reviewed mount identity or build root absent")
    root_fd = os.open(root, DIRECTORY_FLAGS)
    try:
        usr_fd = os.open("usr", DIRECTORY_FLAGS, dir_fd=root_fd)
        try:
            bin_fd = os.open("bin", DIRECTORY_FLAGS, dir_fd=usr_fd)
            try:
                mount_fd = os.open("mount", FILE_FLAGS, dir_fd=bin_fd)
                try:
                    before = os.fstat(mount_fd)
                    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                            or (before.st_uid, before.st_gid) != (0, 0)
                            or before.st_size != int(expected_size)
                            or not before.st_mode & 0o111 or before.st_mode & 0o022):
                        raise ValueError("signed mount ELF metadata differs")
                    digest = hashlib.sha256()
                    remaining = before.st_size
                    while remaining:
                        chunk = os.read(mount_fd, min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError("signed mount ELF truncated")
                        digest.update(chunk)
                        remaining -= len(chunk)
                    after_read = os.fstat(mount_fd)
                    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                                             info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    if identity(before) != identity(after_read) or digest.hexdigest() != expected_sha256:
                        raise ValueError("signed mount ELF bytes differ")
                    os.fchmod(mount_fd, 0o555)
                    sealed = os.fstat(mount_fd)
                    if (not stat.S_ISREG(sealed.st_mode) or sealed.st_nlink != 1
                            or (sealed.st_uid, sealed.st_gid) != (0, 0)
                            or sealed.st_size != before.st_size
                            or (sealed.st_dev, sealed.st_ino) != (before.st_dev, before.st_ino)
                            or stat.S_IMODE(sealed.st_mode) != 0o555):
                        raise ValueError("non-privileged mount ELF mode differs")
                finally:
                    os.close(mount_fd)
            finally:
                os.close(bin_fd)
        finally:
            os.close(usr_fd)
    finally:
        os.close(root_fd)


def main():
    if os.geteuid() != 0 or "BUILDROOT" not in os.environ:
        print("Reviewed mount finalization requires mkosi root context", file=sys.stderr)
        return 1
    try:
        sanitize(os.environ["BUILDROOT"])
    except (OSError, ValueError) as error:
        print("Reviewed mount finalization failed: " + str(error), file=sys.stderr)
        return 1
    print("Reviewed mount ELF sealed without privilege; boot/private acceptance remains separate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
