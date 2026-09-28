#!/usr/bin/env python3
"""Check the candidate builder APT plan against one signed Debian snapshot.

This is an offline package-resolution diagnostic. It authenticates the
file objects reported by the signed ELF loader's --list mode for APT. It
does not prove kernel-provided objects such as vDSO, later plugin loads,
the full set of programs mkosi may invoke, installed file bytes, Python
imports, a runnable builder image, or an approved guest image.
"""

import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

import debian_snapshot
import verify_builder_packages as direct


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "deploy/gcp/builder-closure.lock.json"
DIRECT_LOCK = ROOT / "deploy/gcp/builder-direct-packages.lock.json"
IDENTITIES = ROOT / "deploy/gcp/guest/input-identities.json"
PACKAGE_FIELDS = {"name", "version", "architecture", "filename", "size", "sha256"}
# Updating the candidate package set requires source review and a new digest.
LOCK_BYTES = 59009
LOCK_SHA256 = "e3cad72ccb699606ffe2eeda2b384a684420499b454497148c3fb0cb4cbeeece"
DIRECT_LOCK_BYTES = 4989
# Exact decoded size of the hash-pinned 20260918 Packages.xz, measured before
# using it as APT input. The filename is the one APT derives for that source.
INDEX_BYTES = 56620099
APT_LIST_NAME = "snapshot.debian.org_archive_debian_20260918T000000Z_dists_trixie_main_binary-amd64_Packages"
APT_INSTALL = re.compile(r"Inst ([a-z0-9][a-z0-9+.-]*) \((\S+) snapshot\.debian\.org \[(amd64|all)\]\)(?: .*)?\Z")
LOADER_OBJECT = re.compile(r"\s*(/proc/self/fd/[0-9]+) \(0x[0-9a-f]+\)\Z")
LOADER_INTERPRETER = re.compile(
    r"\s*/lib64/ld-linux-x86-64\.so\.2 => (/proc/self/fd/[0-9]+) \(0x[0-9a-f]+\)\Z"
)
LOADER_VDSO = re.compile(r"\tlinux-vdso\.so\.1 \(0x[0-9a-f]+\)\Z")
# Exact SONAME providers observed for apt-get 3.0.3 in the reviewed signed
# snapshot. A new resolver or dependency graph requires source review.
APT_ELF_PROVIDERS = (
    ("libapt-private.so.0.0", "apt"),
    ("libapt-pkg.so.7.0", "libapt-pkg7.0"),
    ("libstdc++.so.6", "libstdc++6"),
    ("libgcc_s.so.1", "libgcc-s1"),
    ("libc.so.6", "libc6"),
    ("libz.so.1", "zlib1g"),
    ("libbz2.so.1.0", "libbz2-1.0"),
    ("liblzma.so.5", "liblzma5"),
    ("liblz4.so.1", "liblz4-1"),
    ("libzstd.so.1", "libzstd1"),
    ("libudev.so.1", "libudev1"),
    ("libsystemd.so.0", "libsystemd0"),
    ("libcrypto.so.3", "libssl3t64"),
    ("libxxhash.so.0", "libxxhash0"),
    ("libm.so.6", "libc6"),
    ("libcap.so.2", "libcap2"),
)
APT_ELF_PACKAGES = frozenset(package for _, package in APT_ELF_PROVIDERS)


def indexed_archive(entry, record, archive_dir, *, keep_bytes=False):
    if (not isinstance(entry, dict) or set(entry) != PACKAGE_FIELDS
            or not isinstance(entry["name"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", entry["name"])
            or not isinstance(entry["version"], str)
            or not isinstance(entry["architecture"], str)
            or not isinstance(entry["filename"], str)
            or type(entry["size"]) is not int or entry["size"] <= 0
            or not isinstance(entry["sha256"], str)
            or not debian_snapshot.HEX_SHA256.fullmatch(entry["sha256"])
            or entry["architecture"] not in {"amd64", "all"}):
        raise ValueError("invalid builder closure package identity")
    filename = PurePosixPath(entry["filename"])
    if (filename.is_absolute() or not filename.parts or filename.parts[0] != "pool"
            or ".." in filename.parts or filename.suffix != ".deb"):
        raise ValueError("unsafe builder closure package filename")
    if record is None or any(str(entry[field]) != record.get(index_field) for field, index_field in (
            ("filename", "Filename"), ("size", "Size"), ("sha256", "SHA256"))):
        raise ValueError("builder closure package differs from signed index")
    archive = archive_dir / f'{entry["sha256"]}.deb'
    if archive.is_symlink():
        raise ValueError("builder closure archive redirected")
    try:
        descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ValueError("builder closure archive missing or redirected") from error
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != entry["size"]:
            raise ValueError("builder closure archive differs from signed index")
        if keep_bytes:
            data = stream.read()
            digest = hashlib.sha256(data).hexdigest()
        else:
            if stream.read(8) != b"!<arch>\n":
                raise ValueError("builder closure archive is not a deb")
            stream.seek(0)
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            data = None
        after = os.fstat(stream.fileno())
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if (digest != entry["sha256"] or identity(before) != identity(after)
                or (data is not None and not data.startswith(b"!<arch>\n"))):
            raise ValueError("builder closure archive differs from signed index")
    return data


def deb_data_tar(data):
    """Return the sole xz data member of a hash-checked Debian archive."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("apt package is not a deb")
    offset = 8
    payload = None
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("malformed apt ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size_text = header[48:58].decode("ascii").strip()
        if not size_text.isdecimal():
            raise ValueError("malformed apt ar size")
        size = int(size_text)
        start = offset + 60
        end = start + size
        if end > len(data):
            raise ValueError("truncated apt ar member")
        if name == "data.tar.xz":
            if payload is not None:
                raise ValueError("duplicate apt data member")
            payload = data[start:end]
        offset = end + (size % 2)
    if offset != len(data) or payload is None:
        raise ValueError("apt archive has no unique data member")
    return payload


def apt_get_from_deb(data):
    """Read one regular apt-get file from the hash-checked .deb, without dpkg."""
    found = None
    try:
        with tarfile.open(fileobj=io.BytesIO(deb_data_tar(data)), mode="r:xz") as archive:
            for member in archive:
                if member.name in {"./usr/bin/apt-get", "usr/bin/apt-get"}:
                    if found is not None or not member.isfile():
                        raise ValueError("apt archive has no unique regular apt-get")
                    found = archive.extractfile(member).read()
    except (lzma.LZMAError, tarfile.TarError) as error:
        raise ValueError("invalid apt package data member") from error
    if found is None:
        raise ValueError("apt archive has no unique regular apt-get")
    return found


def package_elf(data, soname):
    """Resolve one same-directory SONAME link inside an authenticated .deb."""
    prefix = "./usr/lib/x86_64-linux-gnu/"
    if not re.fullmatch(r"(?:lib[a-zA-Z0-9+_.-]+|ld-linux-x86-64)\.so(?:\.[0-9]+)*", soname):
        raise ValueError("invalid reviewed ELF SONAME")
    try:
        with tarfile.open(fileobj=io.BytesIO(deb_data_tar(data)), mode="r:xz") as archive:
            members = {}
            for member in archive:
                if member.name.startswith(prefix) and "/" not in member.name[len(prefix):]:
                    if member.name in members:
                        raise ValueError("duplicate signed ELF archive path")
                    members[member.name] = member
            current = members.get(prefix + soname)
            if current is None:
                raise ValueError("signed ELF SONAME absent from provider archive")
            if current.issym():
                if (not re.fullmatch(r"[a-zA-Z0-9+_.-]+", current.linkname)
                        or not current.linkname.startswith(soname)):
                    raise ValueError("signed ELF SONAME link escapes provider archive")
                current = members.get(prefix + current.linkname)
            if current is None or not current.isfile():
                raise ValueError("signed ELF SONAME has no regular target")
            elf = archive.extractfile(current).read()
    except (lzma.LZMAError, tarfile.TarError) as error:
        raise ValueError("invalid signed ELF archive data member") from error
    if not elf.startswith(b"\x7fELF"):
        raise ValueError("signed ELF SONAME target is not ELF")
    return elf


def parse_apt_plan(result):
    if result.returncode != 0 or result.stderr.strip():
        raise ValueError("offline APT package simulation failed")
    resolved = {}
    for line in result.stdout.splitlines():
        if line.startswith(("Remv ", "Purg ")):
            raise ValueError("offline APT attempted package removal")
        if line.startswith("Inst "):
            match = APT_INSTALL.fullmatch(line)
            if match is None:
                raise ValueError("unrecognized offline APT package selection")
            name, version, architecture = match.groups()
            if name in resolved:
                raise ValueError("duplicate offline APT package selection")
            resolved[name] = (version, architecture)
    if not resolved:
        raise ValueError("offline APT selected no builder packages")
    return resolved


@contextmanager
def sealed_elf_bytes(data):
    """Keep a signed archive member unchanged across loader inspection and use."""
    if not data.startswith(b"\x7fELF"):
        raise ValueError("signed runtime object is not ELF")
    descriptor = os.memfd_create("zrpc-signed-apt-elf", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("signed runtime object could not be sealed")
            view = view[written:]
        os.fchmod(descriptor, 0o500)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield Path(f"/proc/self/fd/{descriptor}"), descriptor
    finally:
        os.close(descriptor)


def check_loader_report(result, loader, preloads):
    """Reject file objects outside the sealed fds; identify the kernel vDSO."""
    if result.returncode != 0 or result.stderr.strip():
        raise ValueError("signed APT ELF loader inspection failed")
    expected = {str(loader), *(str(path) for path in preloads)}
    found = []
    vdso_observed = False
    for index, line in enumerate(result.stdout.splitlines()):
        if LOADER_VDSO.fullmatch(line):
            if index != 0 or vdso_observed:
                raise ValueError("duplicate or relocated kernel vDSO loader report")
            vdso_observed = True
            continue
        match = LOADER_INTERPRETER.fullmatch(line) or LOADER_OBJECT.fullmatch(line)
        if match is None:
            raise ValueError("unrecognized signed APT ELF loader report")
        found.append(match.group(1))
    if len(found) != len(expected) or set(found) != expected:
        raise ValueError("signed APT ELF loader used missing or ambient objects")
    return vdso_observed


def apt_plan(index_bytes, scratch, apt_get, resolver, anchors, snapshot, runtime_archives):
    if scratch.is_symlink() or not scratch.is_dir():
        raise ValueError("workspace scratch directory missing or redirected")
    with tempfile.TemporaryDirectory(prefix="zrpc-builder-apt-", dir=scratch) as temporary:
        root = Path(temporary)
        lists = root / "lists"
        lists.mkdir()
        with lzma.open(io.BytesIO(index_bytes), "rb") as compressed:
            decoded = compressed.read(INDEX_BYTES + 1)
            if len(decoded) != INDEX_BYTES or compressed.read(1):
                raise ValueError("signed package index decoded size differs from review")
        (lists / APT_LIST_NAME).write_bytes(decoded)
        (root / "status").write_bytes(b"")
        (root / "extended_states").write_bytes(b"")
        cache = root / "cache"
        cache.mkdir()
        log = root / "log"
        log.mkdir()
        etc = root / "etc"
        etc.mkdir()
        for name in ("apt.conf", "sources.list", "preferences"):
            (etc / name).write_bytes(b"")
        for name in ("apt.conf.d", "sources.list.d", "preferences.d"):
            (etc / name).mkdir()
        empty_lib = root / "empty-lib"
        empty_lib.mkdir()
        (etc / "sources.list.d/snapshot.sources").write_text(
            "Types: deb\nURIs: " + snapshot.rstrip("/") + "\nSuites: trixie\n"
            "Components: main\nSigned-By: " + str(debian_snapshot.KEYRING.resolve()) + "\n"
        )
        arguments = [
            "--simulate", "--no-install-recommends",
            "-o", f"Dir::State::lists={lists}",
            "-o", f"Dir::State::status={root / 'status'}",
            "-o", f"Dir::State::extended_states={root / 'extended_states'}",
            "-o", f"Dir::Cache={cache}/",
            "-o", f"Dir::Log={log}/",
            "-o", f"Dir::Etc={etc}/", "-o", "Debug::NoLocking=1",
            "install", *(f'{entry["name"]}={entry["version"]}' for entry in anchors),
        ]
        with ExitStack() as stack:
            program, program_fd = stack.enter_context(debian_snapshot.sealed_reviewed_file(
                apt_get, resolver["executable_sha256"], resolver["executable_size"],
                "APT resolver", executable=True))
            loader, loader_fd = stack.enter_context(sealed_elf_bytes(
                package_elf(runtime_archives["libc6"], "ld-linux-x86-64.so.2")))
            preloads = []
            file_descriptors = [program_fd, loader_fd]
            for soname, package in APT_ELF_PROVIDERS:
                library, descriptor = stack.enter_context(sealed_elf_bytes(
                    package_elf(runtime_archives[package], soname)))
                preloads.append(library)
                file_descriptors.append(descriptor)
            prefix = [str(loader), "--inhibit-cache", "--preload",
                      ":".join(str(path) for path in preloads),
                      "--library-path", str(empty_lib)]
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root),
                   "APT_CONFIG": str(etc / "apt.conf")}
            inspection = subprocess.run(
                [*prefix, "--list", str(program)], capture_output=True, text=True,
                check=False, pass_fds=file_descriptors, env=env,
            )
            vdso_observed = check_loader_report(inspection, loader, preloads)
            result = subprocess.run(
                [*prefix, str(program), *arguments], capture_output=True, text=True,
                check=False, pass_fds=file_descriptors, env=env,
            )
    return parse_apt_plan(result), vdso_observed


def verify(inrelease, packages_index, archive_dir, apt_get, scratch, *,
           lock_path=LOCK, direct_lock_path=DIRECT_LOCK, identities_path=IDENTITIES):
    lock_bytes = debian_snapshot.bounded_regular_bytes(lock_path, LOCK_BYTES, "builder closure lock")
    if len(lock_bytes) != LOCK_BYTES or hashlib.sha256(lock_bytes).hexdigest() != LOCK_SHA256:
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=direct.unique_object)
    identities = direct.read_json(identities_path)
    signed_snapshot = identities["downloaded_metadata"]["trixie_snapshot_candidate"]
    direct_report = direct.verify(
        inrelease, packages_index, archive_dir,
        lock_path=direct_lock_path, identities_path=identities_path,
    )
    if (not isinstance(lock, dict)
            or set(lock) != {"schema_version", "status", "snapshot", "inrelease_sha256",
                             "packages_index_sha256", "signed_release_date_epoch",
                             "direct_lock_sha256", "resolver", "packages"}
            or type(lock["schema_version"]) is not int or lock["schema_version"] != 1
            or lock["status"] != "apt-resolved-candidate-unbuilt-unapproved"
            or lock["snapshot"] != signed_snapshot["url"]
            or lock["inrelease_sha256"] != signed_snapshot["inrelease_sha256"]
            or lock["packages_index_sha256"] != signed_snapshot["main_binary_amd64_packages_xz_sha256"]
            or lock["signed_release_date_epoch"] != signed_snapshot["signed_release_date_epoch"]
            or lock["direct_lock_sha256"] != direct_report["lock_sha256"]):
        raise ValueError("builder closure lock differs from reviewed direct inputs")
    resolver = lock["resolver"]
    if (not isinstance(resolver, dict)
            or set(resolver) != {"package", "version", "executable", "executable_size",
                                 "executable_sha256", "empty_dpkg_status", "install_recommends"}
            or resolver["package"] != "apt" or resolver["executable"] != "usr/bin/apt-get"
            or type(resolver["executable_size"]) is not int or resolver["executable_size"] <= 0
            or not isinstance(resolver["executable_sha256"], str)
            or not debian_snapshot.HEX_SHA256.fullmatch(resolver["executable_sha256"])
            or resolver["empty_dpkg_status"] is not True
            or resolver["install_recommends"] is not False):
        raise ValueError("unsupported builder APT resolver identity")
    direct_bytes = debian_snapshot.bounded_regular_bytes(
        direct_lock_path, DIRECT_LOCK_BYTES, "direct builder lock",
    )
    if hashlib.sha256(direct_bytes).hexdigest() != direct_report["lock_sha256"]:
        raise ValueError("direct builder lock changed during inspection")
    anchors = json.loads(direct_bytes, object_pairs_hook=direct.unique_object)["packages"]
    apt_anchor = next(entry for entry in anchors if entry["name"] == "apt")
    if resolver["version"] != apt_anchor["version"]:
        raise ValueError("APT resolver version differs from direct lock")
    epoch, (index_hash, _), index_bytes = debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, signed_snapshot["inrelease_sha256"],
    )
    if epoch != lock["signed_release_date_epoch"] or index_hash != lock["packages_index_sha256"]:
        raise ValueError("signed builder package index differs from source-reviewed candidate")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    if archive_dir.is_symlink() or not archive_dir.is_dir():
        raise ValueError("builder closure archive directory missing or redirected")
    entries = lock["packages"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("builder closure package list missing")
    selected = {}
    runtime_archives = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("invalid builder closure package identity")
        name = entry["name"]
        if name in selected:
            raise ValueError("duplicate builder closure package")
        record = records.get((name, entry.get("version"), entry.get("architecture")))
        data = indexed_archive(entry, record, archive_dir,
                               keep_bytes=name in APT_ELF_PACKAGES)
        selected[name] = (entry["version"], entry["architecture"])
        if data is not None:
            runtime_archives[name] = data
    if [entry["name"] for entry in entries] != sorted(selected):
        raise ValueError("builder closure package order differs from reviewed lock")
    if any(selected.get(entry["name"]) != (entry["version"], entry["architecture"])
           for entry in anchors):
        raise ValueError("builder closure excludes a direct tool package")
    if set(runtime_archives) != APT_ELF_PACKAGES:
        raise ValueError("builder closure excludes signed APT ELF provider")
    extracted = apt_get_from_deb(runtime_archives["apt"])
    if (len(extracted) != resolver["executable_size"]
            or hashlib.sha256(extracted).hexdigest() != resolver["executable_sha256"]):
        raise ValueError("APT resolver executable differs from signed apt archive")
    resolved, vdso_observed = apt_plan(index_bytes, scratch, apt_get, resolver, anchors,
                                      lock["snapshot"], runtime_archives)
    if selected != resolved:
        raise ValueError("builder closure differs from offline APT package plan")
    return {
        "schema_version": 1,
        "status": "diagnostic-signed-builder-apt-plan-matched-unbuilt",
        "closure_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "direct_lock_sha256": direct_report["lock_sha256"],
        "signed_packages_index_sha256": index_hash,
        "package_count": len(selected),
        "apt_resolver_binary_matches_signed_package": True,
        "apt_loader_reported_file_objects_from_signed_archives": True,
        "apt_loader_reported_file_object_count": len(APT_ELF_PROVIDERS) + 1,
        "apt_kernel_vdso": {
            "observed": vdso_observed,
            "disk_authenticated": False,
            "reason": "kernel-provided virtual ELF object, not a Debian disk file",
        },
        "apt_post_start_elf_loads_verified": False,
        "complete_builder_toolchain": False,
        "image_built": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--apt-get", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.inrelease, args.packages_index, args.archives,
                                args.apt_get, args.scratch), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False,
                          "image_built": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
