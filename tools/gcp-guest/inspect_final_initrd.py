#!/usr/bin/env python3
"""Audit every byte appended to the reviewed GCP initrd before UKI signing.

The base zstd CPIO has a separate, source-bound audit. Pinned mkosi 25.3
appends a second zstd CPIO made from kernel modules and ``modules*`` files.
This inspector reconstructs the latter from the exact signed Debian kernel
and kmod archives. It does not establish firmware trust, boot, or private mode.
"""

import ctypes
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile


STATUS = "diagnostic-complete-final-initrd-package-bound-unapproved"
# The dependency closure was read from the .modinfo records in the exact
# linux-image-6.12.107+deb13-cloud-amd64_6.12.107-1_amd64.deb. A kernel
# update requires reviewing this set again; the bytes are checked against
# that package below, never copied from a first-seen image.
MODULES = frozenset({
    "kernel/drivers/md/dm-verity.ko.xz",
    "kernel/drivers/md/dm-bufio.ko.xz",
    "kernel/drivers/md/dm-mod.ko.xz",
    "kernel/lib/reed_solomon/reed_solomon.ko.xz",
})
PACKAGE_METADATA = frozenset({
    "modules.builtin", "modules.builtin.modinfo", "modules.order",
})
BOOT_CONFIG = {
    # Google requires these options for custom TDX images. The quote broker
    # additionally needs the upstream TDX/TSM ConfigFS report interface.
    "CONFIG_INTEL_TDX_GUEST": frozenset({"y"}),
    "CONFIG_TDX_GUEST_DRIVER": frozenset({"m"}),
    "CONFIG_TSM_REPORTS": frozenset({"m"}),
    "CONFIG_CONFIGFS_FS": frozenset({"y", "m"}),
    "CONFIG_GVE": frozenset({"m"}),
    "CONFIG_NET_VENDOR_GOOGLE": frozenset({"y"}),
    "CONFIG_PCI_MSI": frozenset({"y"}),
    "CONFIG_SWIOTLB": frozenset({"y"}),
    # The reviewed final initrd deliberately contains no NVMe modules, so
    # the root disk can only be mounted if both NVMe drivers are built in.
    "CONFIG_BLK_DEV_NVME": frozenset({"y"}),
    "CONFIG_NVME_CORE": frozenset({"y"}),
}
BOOT_MODULES = {
    "CONFIG_TDX_GUEST_DRIVER": "kernel/drivers/virt/coco/tdx-guest/tdx-guest.ko.xz",
    "CONFIG_TSM_REPORTS": "kernel/drivers/virt/coco/tsm.ko.xz",
    "CONFIG_CONFIGFS_FS": "kernel/fs/configfs/configfs.ko.xz",
    "CONFIG_GVE": "kernel/drivers/net/ethernet/google/gve/gve.ko.xz",
}
NVME_BUILTINS = frozenset({
    "kernel/drivers/nvme/host/nvme-core.ko",
    "kernel/drivers/nvme/host/nvme.ko",
})
HEX = re.compile(r"[0-9a-f]{64}\Z")
CPIO_FIELDS = re.compile(rb"[0-9a-fA-F]{104}\Z")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_package(path, entry, source):
    """Recheck the exact archive identity already admitted by prepare.py."""
    if (type(entry) is not dict or type(entry.get("size")) is not int
            or entry["size"] <= 0 or not isinstance(entry.get("sha256"), str)
            or not HEX.fullmatch(entry["sha256"])):
        raise ValueError("signed package identity is incomplete")
    raw = source.guest.debian_snapshot.bounded_regular_bytes(
        path, entry["size"], "signed guest package")
    if len(raw) != entry["size"] or sha256(raw) != entry["sha256"]:
        raise ValueError("signed guest package bytes differ from reviewed lock")
    return source.builder.closure.deb_data_tar(raw)


def canonical_member(name, prefix):
    if name in {".", "./"}:
        return False, "."
    if not name.startswith("./"):
        raise ValueError("signed kernel package has a noncanonical path")
    relative = name[2:]
    if (not relative or any(part in {"", ".", ".."} for part in relative.split("/"))
            or not relative.isascii()):
        raise ValueError("signed kernel package has an unsafe path")
    return relative == prefix or relative.startswith(prefix + "/"), relative


def package_tree(payload, root, kernel_version):
    """Copy only the signed module tree to private scratch for depmod replay."""
    prefix = "usr/lib/modules/" + kernel_version
    module_root = root / prefix
    module_root.mkdir(parents=True)
    (root / "lib").symlink_to("usr/lib")
    seen = set()
    signed = {}
    module_parent_seen = False
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as archive:
        for member in archive:
            if member.name == "./usr/lib/modules":
                if (module_parent_seen or not member.isdir() or member.mode != 0o755
                        or member.uid or member.gid):
                    raise ValueError("signed kernel package module parent differs")
                module_parent_seen = True
            selected, relative = canonical_member(member.name, prefix)
            if not selected:
                continue
            if (relative in seen or member.uid != 0 or member.gid != 0
                    or member.mode & (stat.S_ISUID | stat.S_ISGID | 0o022)):
                raise ValueError("signed kernel package module entry differs")
            seen.add(relative)
            target = root / relative
            if member.isdir():
                if member.mode != 0o755:
                    raise ValueError("signed kernel package module directory mode differs")
                target.mkdir(parents=True, exist_ok=False) if relative != prefix else None
                target.chmod(member.mode)
            elif member.isfile():
                if not target.parent.is_dir() or target.parent.is_symlink():
                    raise ValueError("signed kernel package omits a parent directory")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("signed kernel package member cannot be read")
                digest = hashlib.sha256()
                with target.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError("truncated signed kernel package member")
                        output.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                target.chmod(member.mode)
                signed[relative] = (member.size, digest.hexdigest(), member.mode)
            else:
                raise ValueError("signed kernel package module tree has a link or special file")
    if not module_parent_seen:
        raise ValueError("signed kernel package omits the module parent")
    base = prefix + "/"
    for name in MODULES | PACKAGE_METADATA:
        if base + name not in signed:
            raise ValueError("reviewed dm-verity module or package metadata is absent")
    return signed


def signed_kernel_config(payload, kernel_version):
    """Read only the exact config from the already hash-checked kernel deb."""
    target = "./boot/config-" + kernel_version
    config = None
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as archive:
        for member in archive:
            if member.name != target:
                continue
            if (config is not None or not member.isfile() or member.size <= 0
                    or member.uid or member.gid or member.mode != 0o644):
                raise ValueError("signed kernel config is duplicate or not a regular package file")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("signed kernel config cannot be read")
            config = stream.read()
            if len(config) != member.size:
                raise ValueError("signed kernel config is truncated")
    if config is None:
        raise ValueError("signed kernel package omits its exact config")
    return config


def boot_driver_preflight(config, builtins, signed, kernel_version):
    """Check package-described boot drivers; this does not prove a TDX boot."""
    try:
        lines = config.decode("ascii").splitlines()
        builtin_lines = builtins.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("signed kernel driver metadata is not ASCII") from error
    values = {}
    for line in lines:
        if line.startswith("CONFIG_"):
            name, separator, value = line.partition("=")
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            name, separator, value = line[2:-11], "=", "n"
        else:
            continue
        if name in BOOT_CONFIG:
            if not separator or name in values:
                raise ValueError("signed kernel boot config is ambiguous")
            values[name] = value
    for name, allowed in BOOT_CONFIG.items():
        if values.get(name) not in allowed:
            raise ValueError(f"signed kernel lacks required boot option {name}")
    if not NVME_BUILTINS <= set(builtin_lines):
        raise ValueError("signed kernel lacks built-in NVMe root-disk drivers")
    prefix = "usr/lib/modules/" + kernel_version + "/"
    module_hashes = {}
    for option, relative in BOOT_MODULES.items():
        if values[option] == "m":
            identity = signed.get(prefix + relative)
            if identity is None:
                raise ValueError(f"signed kernel lacks required module {relative}")
            module_hashes[option] = identity[1]
    return {"status": "diagnostic-signed-kernel-boot-drivers-unapproved",
            "kernel_config_sha256": sha256(config),
            "nvme_builtin": True, "module_sha256": module_hashes,
            "private_mode_approved": False}


def checked_depmod_tool(payload, library_payload, source):
    """Replay the exact pinned kmod executable and dynamic libkmod2 bytes."""
    program = None
    link = None
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as archive:
        for member in archive:
            if member.name == "./usr/bin/kmod":
                if program is not None or not member.isfile() or member.size <= 0:
                    raise ValueError("signed kmod executable is ambiguous")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("signed kmod executable cannot be read")
                program = stream.read()
            elif member.name == "./usr/sbin/depmod":
                if link is not None or not member.issym():
                    raise ValueError("signed depmod launcher is ambiguous")
                link = member.linkname
    if program is None or link != "../bin/kmod":
        raise ValueError("signed kmod package lacks the reviewed depmod launcher")
    library = None
    library_link = None
    with tarfile.open(fileobj=io.BytesIO(library_payload), mode="r:xz") as archive:
        for member in archive:
            if member.name == "./usr/lib/x86_64-linux-gnu/libkmod.so.2.5.1":
                if library is not None or not member.isfile():
                    raise ValueError("signed libkmod2 executable is ambiguous")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("signed libkmod2 executable cannot be read")
                library = stream.read()
            elif member.name == "./usr/lib/x86_64-linux-gnu/libkmod.so.2":
                if library_link is not None or not member.issym():
                    raise ValueError("signed libkmod2 launcher is ambiguous")
                library_link = member.linkname
    if library is None or library_link != "libkmod.so.2.5.1":
        raise ValueError("signed libkmod2 package lacks the reviewed library")
    installed = Path("/usr/bin/kmod")
    depmod = Path("/usr/sbin/depmod")
    installed_library = Path("/usr/lib/x86_64-linux-gnu/libkmod.so.2.5.1")
    linker_name = installed_library.parent / "libkmod.so.2"
    if (installed.is_symlink() or not installed.is_file()
            or not depmod.is_symlink() or os.readlink(depmod) != link
            or installed_library.is_symlink() or not installed_library.is_file()
            or not linker_name.is_symlink() or os.readlink(linker_name) != library_link
            or source.rust_inputs.regular_bytes(installed) != program
            or source.rust_inputs.regular_bytes(installed_library) != library):
        raise ValueError("installed depmod differs from signed Debian kmod")
    return depmod


def tree_files(module_root):
    files = {}
    for directory, children, names in os.walk(module_root, followlinks=False):
        for child in children:
            path = Path(directory) / child
            if path.is_symlink() or not path.is_dir():
                raise ValueError("reconstructed module directory redirects")
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("reconstructed module file redirects")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("reconstructed module file is not regular")
            relative = path.relative_to(module_root).as_posix()
            with path.open("rb") as stream:
                files[relative] = (info.st_size, hashlib.file_digest(stream, "sha256").hexdigest(),
                                   stat.S_IMODE(info.st_mode))
    return files


def reconstructed_members(root, signed, kernel_version, depmod):
    """Use signed kmod behavior to derive exact generated modules.* bytes."""
    module_root = root / "usr/lib/modules" / kernel_version
    before = tree_files(module_root)
    if {"usr/lib/modules/" + kernel_version + "/" + name: identity
            for name, identity in before.items()} != signed:
        raise ValueError("reconstructed signed kernel package changed before depmod")
    # Debian's exact linux-image postinst invokes `depmod $version`. The
    # reviewed replay supplies only a separate basedir and empty configuration.
    result = subprocess.run([str(depmod), "-a", "-b", str(root), "-C", "/dev/null",
                             kernel_version], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                                 "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                            check=False)
    if result.returncode or result.stdout or result.stderr:
        raise ValueError("signed depmod replay failed or emitted diagnostics")
    after = tree_files(module_root)
    if any(after.get(name) != identity for name, identity in before.items()):
        raise ValueError("depmod replay changed a signed kernel package file")
    generated = set(after) - set(before)
    if (not {"modules.dep", "modules.dep.bin"} <= generated
            or any("/" in name or not name.startswith("modules.")
                   or after[name][2] & 0o111 for name in generated)):
        raise ValueError("depmod replay emitted an unreviewed kernel path")
    base = "usr/lib/modules/" + kernel_version + "/"
    expected = {base + name: after[name] for name in MODULES | PACKAGE_METADATA | generated}
    return expected, generated


def cpio_bound(expected):
    """Bound decompressed bytes by exact expected payloads and GNU block pad."""
    directories = {parent for name in expected for parent in Path(name).parents
                   if parent.as_posix() not in {".", "usr", "usr/lib"}}
    names = set(expected) | {item.as_posix() for item in directories}
    total = 0
    for name in names | {"TRAILER!!!"}:
        size = expected[name][0] if name in expected else 0
        header_name = 110 + len(name.encode("utf-8")) + 1
        total += header_name + (-header_name % 4) + size + (-size % 4)
    # GNU cpio's default I/O block is 512 bytes in pinned mkosi 25.3.
    return (total + 511) // 512 * 512


class BoundedStream:
    def __init__(self, stream, maximum):
        self.stream = stream
        self.maximum = maximum
        self.count = 0

    def read(self, size=-1):
        if size < 0 or self.count + size > self.maximum + 1:
            size = self.maximum + 1 - self.count
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > self.maximum:
            raise ValueError("appended initrd exceeds package-derived CPIO size")
        return data


def parse_cpio(stream, expected, source):
    """Accept only the reconstructed files; never extract archive paths."""
    if not expected or not all(isinstance(name, str) for name in expected):
        raise ValueError("appended initrd has no reviewed file inventory")
    allowed_dirs = {item.as_posix() for name in expected for item in Path(name).parents
                    if item.as_posix() not in {".", "usr", "usr/lib"}}
    bounded = BoundedStream(stream, cpio_bound(expected))
    seen = set()
    while True:
        header = source.exact(bounded, 110)
        if header[:6] != b"070701" or not CPIO_FIELDS.fullmatch(header[6:]):
            raise ValueError("appended initrd is not canonical GNU newc")
        fields = [int(header[offset:offset + 8], 16) for offset in range(6, 110, 8)]
        mode, uid, gid, nlink, size, namesize, checksum = (
            fields[1], fields[2], fields[3], fields[4], fields[6], fields[11], fields[12])
        if not 1 <= namesize <= os.pathconf("/", "PC_PATH_MAX"):
            raise ValueError("appended initrd member name exceeds Linux path bound")
        raw_name = source.exact(bounded, namesize)
        source.padded(bounded, 110 + namesize)
        if not raw_name.endswith(b"\0") or b"\0" in raw_name[:-1]:
            raise ValueError("appended initrd member name is malformed")
        try:
            name = raw_name[:-1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("appended initrd member name is not UTF-8") from error
        if name == "TRAILER!!!":
            if size or checksum or uid or gid or mode or nlink not in {0, 1}:
                raise ValueError("appended initrd trailer is malformed")
            block_padding = -bounded.count % 512
            if any(source.exact(bounded, block_padding)) or bounded.read(1):
                raise ValueError("appended initrd has noncanonical trailing content")
            break
        if (not name or name.startswith("/") or any(part in {"", ".", ".."}
                for part in name.split("/")) or name in seen
                or uid or gid or checksum or nlink < 1
                or mode & (stat.S_ISUID | stat.S_ISGID | 0o022)):
            raise ValueError("appended initrd path or metadata is unsafe")
        seen.add(name)
        kind = stat.S_IFMT(mode)
        if name in allowed_dirs:
            # All module-tree directories in the exact pinned kernel deb are 0755.
            if kind != stat.S_IFDIR or size or stat.S_IMODE(mode) != 0o755:
                raise ValueError("appended initrd parent path is not a directory")
        elif name in expected:
            length, wanted, permissions = expected[name]
            if (kind != stat.S_IFREG or nlink != 1 or size != length
                    or stat.S_IMODE(mode) != permissions):
                raise ValueError("appended initrd package file metadata differs")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = source.exact(bounded, min(remaining, 1024 * 1024))
                digest.update(chunk)
                remaining -= len(chunk)
            if digest.hexdigest() != wanted:
                raise ValueError("appended initrd file differs from signed package or depmod replay")
        else:
            raise ValueError("appended initrd contains an unknown or overriding file")
        source.padded(bounded, size)
    if (set(expected) | allowed_dirs) - seen:
        raise ValueError("appended initrd omitted a required module, directory or metadata file")
    return {"entry_count": len(seen), "file_count": len(expected),
            "decompressed_bytes": bounded.count}


def decompress_single_zstd_frame(compressed, library_path, output_bound):
    """Decompress one exact frame with signed libzstd into a package-sized buffer."""
    if compressed[:4] != b"\x28\xb5\x2f\xfd":
        raise ValueError("appended initrd does not start with a zstd frame")
    if library_path.is_symlink() or not library_path.is_file():
        raise ValueError("signed libzstd runtime is missing or redirected")
    library = ctypes.CDLL(str(library_path))
    library.ZSTD_findFrameCompressedSize.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    library.ZSTD_findFrameCompressedSize.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = (ctypes.c_size_t,)
    library.ZSTD_isError.restype = ctypes.c_uint
    data = ctypes.create_string_buffer(compressed)
    length = library.ZSTD_findFrameCompressedSize(data, len(compressed))
    if library.ZSTD_isError(length) or length != len(compressed):
        raise ValueError("appended initrd is not exactly one complete zstd frame")
    library.ZSTD_decompress.argtypes = (ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.c_void_p, ctypes.c_size_t)
    library.ZSTD_decompress.restype = ctypes.c_size_t
    output = ctypes.create_string_buffer(output_bound)
    size = library.ZSTD_decompress(output, output_bound, data, len(compressed))
    if library.ZSTD_isError(size) or size > output_bound:
        raise ValueError("appended initrd exceeds reconstructed package size or is malformed")
    return output.raw[:size]


def inspect(base_sha256, base_bytes, final, final_sha256, final_bytes,
            kernel_archive, kernel_entry,
            kmod_archive, kmod_entry, libkmod_archive, libkmod_entry, libzstd,
            workspace, source):
    """Check the complete split initrd; caller binds it to the UKI section."""
    if (not isinstance(base_sha256, str) or not HEX.fullmatch(base_sha256)
            or type(base_bytes) is not int or base_bytes <= 0
            or not isinstance(final_sha256, str) or not HEX.fullmatch(final_sha256)
            or type(final_bytes) is not int or final_bytes <= base_bytes):
        raise ValueError("exact base and final initrd identities required")
    if (kernel_entry.get("name") != source.guest.prepare.KERNEL_PACKAGE
            or kernel_entry.get("version") != source.guest.prepare.KERNEL_PACKAGE_VERSION
            or kernel_entry.get("architecture") != "amd64"
            or kmod_entry.get("name") != "kmod"
            or kmod_entry.get("version") != "34.2-2"
            or kmod_entry.get("architecture") != "amd64"
            or libkmod_entry.get("name") != "libkmod2"
            or libkmod_entry.get("version") != "34.2-2"
            or libkmod_entry.get("architecture") != "amd64"):
        raise ValueError("kernel or depmod package differs from reviewed closure")
    kernel = checked_package(kernel_archive, kernel_entry, source)
    kmod = checked_package(kmod_archive, kmod_entry, source)
    libkmod = checked_package(libkmod_archive, libkmod_entry, source)
    depmod = checked_depmod_tool(kmod, libkmod, source)
    with tempfile.TemporaryDirectory(prefix="zrpc-final-initrd-", dir=workspace) as scratch:
        root = Path(scratch)
        kernel_version = source.guest.prepare.KERNEL_VERSION
        signed = package_tree(kernel, root, kernel_version)
        expected, generated = reconstructed_members(
            root, signed, kernel_version, depmod)
        builtin_name = "usr/lib/modules/" + kernel_version + "/modules.builtin"
        builtins = (root / builtin_name).read_bytes()
        if ((len(builtins), sha256(builtins)) != signed[builtin_name][:2]):
            raise ValueError("signed kernel built-in inventory changed")
        boot_drivers = boot_driver_preflight(
            signed_kernel_config(kernel, kernel_version), builtins, signed, kernel_version)
        descriptor = os.open(final, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != final_bytes:
                raise ValueError("final initrd is not the expected regular file")
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != final_sha256:
                    raise ValueError("final initrd differs from checked output")
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb") as prefix:
                digest = hashlib.sha256()
                remaining = base_bytes
                while remaining:
                    chunk = source.exact(prefix, min(remaining, 1024 * 1024))
                    digest.update(chunk)
                    remaining -= len(chunk)
                if digest.hexdigest() != base_sha256:
                    raise ValueError("final initrd prefix differs from audited base CPIO")
            os.lseek(descriptor, base_bytes, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb") as suffix:
                compressed = source.exact(suffix, final_bytes - base_bytes)
                if suffix.read(1):
                    raise ValueError("final initrd changed while reading module frame")
            decoded = decompress_single_zstd_frame(compressed, libzstd,
                                                   cpio_bound(expected))
            report = parse_cpio(io.BytesIO(decoded), expected, source)
            after = os.fstat(descriptor)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                                     item.st_nlink, item.st_size, item.st_mtime_ns,
                                     item.st_ctime_ns)
            if identity(before) != identity(after):
                raise ValueError("final initrd changed during inspection")
        finally:
            os.close(descriptor)
    return {"status": STATUS, "final_initrd_sha256": final_sha256,
            "final_initrd_bytes": final_bytes,
            "kernel_package_sha256": kernel_entry["sha256"],
            "kmod_package_sha256": kmod_entry["sha256"],
            "libkmod_package_sha256": libkmod_entry["sha256"],
            "reviewed_module_count": len(MODULES),
            "reconstructed_metadata_count": len(generated),
            "boot_driver_preflight": boot_drivers,
            **report, "private_mode_approved": False}
