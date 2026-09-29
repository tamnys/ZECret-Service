#!/usr/bin/env python3
"""Build and check the exact, offline disk.raw archive used by images.insert.

This checks import media, not boot integrity, hardware evidence, or private-mode
approval. Run it in the reviewed Linux builder; it makes no network calls.
Google's manual import contract requires disk.raw, whole-GB raw size, and a
gzip-compressed GNU oldgnu TAR archive:
https://docs.cloud.google.com/compute/docs/import/import-existing-image
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib


GIB = 1024 ** 3
# Google manual boot-disk import documents a 2048 GB (2 TB) ceiling for this
# raw-disk import workflow; Compute sizeGb uses base-2 GiB units.
MAX_IMPORT_GIB = 2048
GNU_TAR = "/usr/bin/tar"
GNU_GZIP = "/usr/bin/gzip"
GNU_MAGIC = b"ustar  \0"
WORKSPACE_ROOT = Path("/workspace")


def _regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        stream.close()
        raise ValueError("input must be a regular file without symlink redirection")
    return stream


def _hash(stream):
    stream.seek(0)
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(block)
    stream.seek(0)
    return result.hexdigest()


def _identity(value, size):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("SHA-256 must be a lowercase hex digest")
    if type(size) is not int or size == 0 or size % GIB or size // GIB > MAX_IMPORT_GIB:
        raise ValueError("disk.raw size must be a positive whole GiB at most 2048 GiB")


def verify(archive_path, archive_sha256, raw_sha256, raw_bytes):
    """Hash the logical disk bytes and reject any other archive member/input."""
    _identity(raw_sha256, raw_bytes)
    if not re.fullmatch(r"[0-9a-f]{64}", archive_sha256):
        raise ValueError("archive SHA-256 must be a lowercase hex digest")
    with _regular(archive_path) as archive:
        if _hash(archive) != archive_sha256:
            raise ValueError("archive SHA-256 differs from reviewed package")
        with gzip.GzipFile(fileobj=archive) as compressed:
            header = compressed.read(512)
        if len(header) != 512 or header[257:265] != GNU_MAGIC:
            raise ValueError("first TAR header is not GNU oldgnu")
        # For GNU sparse entries tarfile replaces TarInfo.size with the
        # logical size after reading the header. Retain its physical size to
        # locate the real next header and cross-check the extent map.
        physical_bytes = tarfile.TarInfo.frombuf(header, tarfile.ENCODING,
                                                 "surrogateescape").size
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:gz") as contents:
            member = contents.next()
            if (member is None or member.offset != 0 or member.name != "disk.raw"
                    or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.GNUTYPE_SPARSE)
                    or member.linkname or member.pax_headers):
                raise ValueError("archive must contain only a regular disk.raw")
            if member.size != raw_bytes:
                raise ValueError("disk.raw logical size differs from reviewed package")
            source = contents.extractfile(member)
            if source is None:
                raise ValueError("disk.raw cannot be read")
            actual = hashlib.sha256()
            total = 0
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > raw_bytes:
                    raise ValueError("disk.raw exceeds reviewed logical size")
                actual.update(block)
            if total != raw_bytes or actual.hexdigest() != raw_sha256:
                raise ValueError("disk.raw logical bytes differ from reviewed package")
            stored = sum(length for _, length in member.sparse) if member.sparse is not None else member.size
            if stored < 0 or stored > raw_bytes or stored != physical_bytes:
                raise ValueError("GNU sparse stored size differs from its extent map")
            trailer_offset = member.offset_data + ((physical_bytes + 511) // 512) * 512
            if contents.offset != trailer_offset:
                raise ValueError("TAR next-header offset differs from physical stored size")
            if contents.next() is not None:
                raise ValueError("archive has an additional TAR member")
        # tarfile stops at the first end marker. A separate streaming zlib pass
        # checks every trailing byte, the gzip CRC, and that there is exactly
        # one gzip member; it never materializes the raw disk in memory.
        archive.seek(0)
        decoder = zlib.decompressobj(wbits=31)
        expanded_bytes = 0
        trailer_bytes = 0
        for compressed_block in iter(lambda: archive.read(4096), b""):
            if decoder.eof:
                raise ValueError("archive has bytes after its gzip member")
            expanded = decoder.decompress(compressed_block)
            if decoder.unused_data:
                raise ValueError("archive has multiple gzip members or trailing compressed bytes")
            before_trailer = max(0, min(len(expanded), trailer_offset - expanded_bytes))
            tail = expanded[before_trailer:]
            if any(tail):
                raise ValueError("archive has nonzero content after disk.raw")
            trailer_bytes += len(tail)
            expanded_bytes += len(expanded)
        if not decoder.eof or expanded_bytes < trailer_offset:
            raise ValueError("TAR or gzip stream ends before disk.raw payload")
        if trailer_bytes < 1024 or trailer_bytes % 512:
            raise ValueError("archive lacks complete TAR end blocks")
    return {"archive_sha256": archive_sha256, "raw_disk_sha256": raw_sha256,
            "raw_disk_bytes": raw_bytes, "oldgnu_single_member_checked": True,
            "private_mode_approved": False}


def pack(raw_path, archive_path, *, allow_non_workspace_paths=False):
    raw_path = Path(raw_path).absolute()
    archive_path = Path(archive_path).absolute()
    if raw_path.name != "disk.raw" or archive_path.suffixes[-2:] != [".tar", ".gz"]:
        raise ValueError("input must be disk.raw and output must end in .tar.gz")
    if not archive_path.parent.is_dir() or archive_path.exists() or archive_path.is_symlink():
        raise ValueError("archive output must be a new file in an existing directory")
    # The managed Linux builder mounts large source and output state at
    # /workspace. Another location requires a visible operator CLI override;
    # neither the archive validator nor this flag authorizes cloud deployment.
    in_workspace = (raw_path.resolve().is_relative_to(WORKSPACE_ROOT)
                    and archive_path.parent.resolve().is_relative_to(WORKSPACE_ROOT))
    if not in_workspace and not allow_non_workspace_paths:
        raise ValueError("disk and archive require /workspace or explicit --allow-non-workspace-paths")
    with _regular(raw_path) as raw:
        raw_bytes = os.fstat(raw.fileno()).st_size
        _identity("0" * 64, raw_bytes)
        raw_sha256 = _hash(raw)
        # The canonical producer is maintained GNU tar, using Google's oldgnu
        # sparse format with stable header metadata. It never extracts input.
        # Do not let an inherited PATH, loader hook, or tar option select code
        # from the workspace. Keep both executables open through their use:
        # hashing a pathname before and after exec leaves a replacement race.
        # Tool hashes remain diagnostic until the separate operator toolchain
        # admission gate is reviewed.
        environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        with _regular(GNU_TAR) as tar_binary, _regular(GNU_GZIP) as gzip_binary:
            tar_sha256 = _hash(tar_binary)
            gzip_sha256 = _hash(gzip_binary)
            tar_fd = tar_binary.fileno()
            gzip_fd = gzip_binary.fileno()
            tar_exec = f"/proc/self/fd/{tar_fd}"
            gzip_exec = f"/proc/self/fd/{gzip_fd}"
            probe = subprocess.run([GNU_TAR, "--version"], executable=tar_exec,
                                   pass_fds=(tar_fd,), capture_output=True, text=True,
                                   check=True, env=environment)
            if not probe.stdout.startswith("tar (GNU tar) "):
                raise ValueError("GNU tar is required")
            gzip_probe = subprocess.run([GNU_GZIP, "--version"], executable=gzip_exec,
                                        pass_fds=(gzip_fd,), capture_output=True,
                                        text=True, check=True, env=environment)
            if not gzip_probe.stdout.startswith("gzip "):
                raise ValueError("GNU gzip is required")
            descriptor, temporary = tempfile.mkstemp(prefix=".disk-import-", suffix=".tar.gz",
                                                      dir=archive_path.parent)
            os.close(descriptor)
            try:
                subprocess.run([GNU_TAR, "--format=oldgnu", "--sparse", "--create",
                                f"--use-compress-program={gzip_exec}",
                                f"--file={temporary}", f"--directory={raw_path.parent}",
                                "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner",
                                "--mode=0644", "disk.raw"], executable=tar_exec,
                               pass_fds=(tar_fd, gzip_fd), check=True, env=environment,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                with _regular(temporary) as output:
                    archive_sha256 = _hash(output)
                receipt = verify(temporary, archive_sha256, raw_sha256, raw_bytes)
                # A changed source or input redirection after hashing cannot pass.
                if os.fstat(raw.fileno()).st_size != raw_bytes or _hash(raw) != raw_sha256:
                    raise ValueError("disk.raw changed during archive creation")
                receipt["gnu_tar_version"] = probe.stdout.splitlines()[0]
                if _hash(tar_binary) != tar_sha256:
                    raise ValueError("GNU tar changed during archive creation")
                if _hash(gzip_binary) != gzip_sha256:
                    raise ValueError("GNU gzip changed during archive creation")
                receipt["gnu_tar_sha256"] = tar_sha256
                receipt["gnu_gzip_version"] = gzip_probe.stdout.splitlines()[0]
                receipt["gnu_gzip_sha256"] = gzip_sha256
                with _regular(Path(sys.executable).resolve()) as executable:
                    receipt["python_executable_sha256"] = _hash(executable)
                receipt["python_version"] = sys.version.split()[0]
                receipt["toolchain_reviewed"] = False
                receipt["workspace_volume_override_used"] = allow_non_workspace_paths
                os.link(temporary, archive_path)
                with _regular(archive_path) as output:
                    os.fsync(output.fileno())
                directory = os.open(archive_path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                os.unlink(temporary)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    producer = commands.add_parser("pack")
    producer.add_argument("raw_disk")
    producer.add_argument("archive")
    producer.add_argument("--allow-non-workspace-paths", action="store_true")
    checker = commands.add_parser("verify")
    checker.add_argument("archive")
    checker.add_argument("archive_sha256")
    checker.add_argument("raw_disk_sha256")
    checker.add_argument("raw_disk_bytes", type=int)
    args = parser.parse_args()
    if args.command == "pack":
        result = pack(args.raw_disk, args.archive,
                      allow_non_workspace_paths=args.allow_non_workspace_paths)
    else:
        result = verify(args.archive, args.archive_sha256,
                        args.raw_disk_sha256, args.raw_disk_bytes)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
