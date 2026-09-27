#!/usr/bin/env python3
"""Check the candidate builder APT plan against one signed Debian snapshot.

This is an offline package-resolution diagnostic. It does not prove the full
set of programs mkosi may invoke, installed file bytes, dynamic libraries,
Python imports, a runnable builder image, or an approved guest image.
"""

import argparse
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
LOCK_BYTES = 56403
LOCK_SHA256 = "0b5c02fabc0279c8e8e8712a62de8249089039c0e0af419a86cbcf8da72d1a4e"
DIRECT_LOCK_BYTES = 3792
# Exact decoded size of the hash-pinned 20260918 Packages.xz, measured before
# using it as APT input. The filename is the one APT derives for that source.
INDEX_BYTES = 56620099
APT_LIST_NAME = "snapshot.debian.org_archive_debian_20260918T000000Z_dists_trixie_main_binary-amd64_Packages"
APT_INSTALL = re.compile(r"Inst ([a-z0-9][a-z0-9+.-]*) \((\S+) snapshot\.debian\.org \[(amd64|all)\]\)(?: .*)?\Z")


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


def apt_get_from_deb(data):
    """Read one regular apt-get file from the hash-checked .deb, without dpkg."""
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
    found = None
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as archive:
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


def apt_plan(index_bytes, scratch, apt_get, resolver, anchors, snapshot):
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
        etc = root / "etc"
        etc.mkdir()
        for name in ("apt.conf", "sources.list", "preferences"):
            (etc / name).write_bytes(b"")
        for name in ("apt.conf.d", "sources.list.d", "preferences.d"):
            (etc / name).mkdir()
        (etc / "sources.list.d/snapshot.sources").write_text(
            "Types: deb\nURIs: " + snapshot.rstrip("/") + "\nSuites: trixie\n"
            "Components: main\nSigned-By: " + str(debian_snapshot.KEYRING.resolve()) + "\n"
        )
        command = [
            str(apt_get), "--simulate", "--no-install-recommends",
            "-o", f"Dir::State::lists={lists}",
            "-o", f"Dir::State::status={root / 'status'}",
            "-o", f"Dir::State::extended_states={root / 'extended_states'}",
            "-o", f"Dir::Cache={cache}/",
            "-o", f"Dir::Etc={etc}/", "-o", "Debug::NoLocking=1",
            "install", *(f'{entry["name"]}={entry["version"]}' for entry in anchors),
        ]
        with debian_snapshot.sealed_reviewed_file(
                apt_get, resolver["executable_sha256"], resolver["executable_size"],
                "APT resolver", executable=True) as (program, fd):
            command[0] = str(program)
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, pass_fds=(fd,),
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root),
                     "APT_CONFIG": str(etc / "apt.conf")},
            )
    return parse_apt_plan(result)


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
    apt_archive = None
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("invalid builder closure package identity")
        name = entry["name"]
        if name in selected:
            raise ValueError("duplicate builder closure package")
        record = records.get((name, entry.get("version"), entry.get("architecture")))
        data = indexed_archive(entry, record, archive_dir, keep_bytes=name == "apt")
        selected[name] = (entry["version"], entry["architecture"])
        if name == "apt":
            apt_archive = data
    if [entry["name"] for entry in entries] != sorted(selected):
        raise ValueError("builder closure package order differs from reviewed lock")
    if any(selected.get(entry["name"]) != (entry["version"], entry["architecture"])
           for entry in anchors):
        raise ValueError("builder closure excludes a direct tool package")
    extracted = apt_get_from_deb(apt_archive)
    if (len(extracted) != resolver["executable_size"]
            or hashlib.sha256(extracted).hexdigest() != resolver["executable_sha256"]):
        raise ValueError("APT resolver executable differs from signed apt archive")
    resolved = apt_plan(index_bytes, scratch, apt_get, resolver, anchors, lock["snapshot"])
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
