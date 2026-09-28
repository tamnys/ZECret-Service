#!/usr/bin/env python3
"""Check reviewed guest account bytes, then seal shadow in mkosi's build root.

This source-bound finalize script runs before audit-rootfs.py. It never reads
mutable build sources, prints account data, or authorizes boot/private mode.
"""

import hashlib
import os
from pathlib import Path
import stat
import sys


ACCOUNT_FILES = {
    "passwd": (1100, "f42d295b4a2ad2a9d9a82865bc4ba6043fafe03e77e5b57e7081a8d67450c2ff", 0o644),
    "group": (661, "c2209f60f6d80a4b10479c1ba9e2df7877bb8a648911a45629f0dc6d86bb1b00", 0o644),
    "shadow": (509, "92ec1ef612eb9c38cbe22403a595d268bf38546cadded7d8e0471bf271f15d13", 0o400),
}
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def seal(root):
    root = Path(root)
    if not root.is_absolute() or root == Path("/") or root.is_symlink():
        raise ValueError("explicit non-root build tree required")
    root_fd = os.open(root, DIRECTORY_FLAGS)
    try:
        etc_fd = os.open("etc", DIRECTORY_FLAGS, dir_fd=root_fd)
        try:
            shadow_fd = None
            try:
                for name, (size, digest, mode) in ACCOUNT_FILES.items():
                    fd = os.open(name, FILE_FLAGS, dir_fd=etc_fd)
                    try:
                        before = os.fstat(fd)
                        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                                or before.st_size != size
                                or stat.S_IMODE(before.st_mode) != mode
                                or (before.st_uid, before.st_gid) != (0, 0)):
                            raise ValueError("reviewed account metadata differs: " + name)
                        data = bytearray()
                        while len(data) <= size:
                            chunk = os.read(fd, size + 1 - len(data))
                            if not chunk:
                                break
                            data.extend(chunk)
                        after = os.fstat(fd)
                        if (len(data) != size or identity(before) != identity(after)
                                or hashlib.sha256(data).hexdigest() != digest):
                            raise ValueError("reviewed account bytes differ: " + name)
                        if name == "shadow":
                            shadow_fd = fd
                            fd = None
                    finally:
                        if fd is not None:
                            os.close(fd)
                if shadow_fd is None:
                    raise ValueError("reviewed shadow file absent")
                os.fchmod(shadow_fd, 0o000)
                sealed = os.fstat(shadow_fd)
                if (not stat.S_ISREG(sealed.st_mode)
                        or stat.S_IMODE(sealed.st_mode) != 0o000
                        or (sealed.st_uid, sealed.st_gid) != (0, 0)):
                    raise ValueError("shadow final mode or owner differs")
            finally:
                if shadow_fd is not None:
                    os.close(shadow_fd)
        finally:
            os.close(etc_fd)
    finally:
        os.close(root_fd)


def main():
    if os.geteuid() != 0 or "BUILDROOT" not in os.environ:
        print("Reviewed shadow finalization requires mkosi root context", file=sys.stderr)
        return 1
    try:
        seal(os.environ["BUILDROOT"])
    except (OSError, ValueError) as error:
        print("Reviewed shadow finalization failed: " + str(error), file=sys.stderr)
        return 1
    print("Reviewed account bytes and sealed shadow mode; boot/private acceptance remains separate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
