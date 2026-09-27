#!/usr/bin/env python3
"""Cache the exact signed-snapshot builder archives without installing them.

Only the source-reviewed closure lock and Debian's signed package index may
select downloads. Existing archives are checked, never replaced. This does not
run package scripts, create a toolchain, build an image, or approve private mode.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

import debian_snapshot
import verify_builder_closure as closure
import verify_builder_packages as direct


CHUNK_BYTES = 1024 * 1024


class SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """Reject a redirect before urllib can issue a request to another origin."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        source = urllib.parse.urlsplit(request.full_url)
        target = urllib.parse.urlsplit(urllib.parse.urljoin(request.full_url, newurl))
        if (target.scheme, target.netloc) != (source.scheme, source.netloc):
            raise ValueError("builder archive redirect escaped signed snapshot")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def open_snapshot_url(request):
    return urllib.request.build_opener(SameOriginRedirects()).open(request)


def authenticated_packages(inrelease, packages_index, *, lock_path=closure.LOCK):
    lock_bytes = debian_snapshot.bounded_regular_bytes(
        lock_path, closure.LOCK_BYTES, "builder closure lock",
    )
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    if len(lock_bytes) != closure.LOCK_BYTES or lock_sha256 != closure.LOCK_SHA256:
        raise ValueError("builder closure differs from source-reviewed candidate")
    lock = json.loads(lock_bytes, object_pairs_hook=direct.unique_object)
    if (not isinstance(lock, dict)
            or lock.get("schema_version") != 1
            or lock.get("status") != "apt-resolved-candidate-unbuilt-unapproved"
            or set(lock) != {"schema_version", "status", "snapshot", "inrelease_sha256",
                             "packages_index_sha256", "signed_release_date_epoch",
                             "direct_lock_sha256", "resolver", "packages"}):
        raise ValueError("unsupported builder closure lock")
    snapshot = urllib.parse.urlsplit(lock["snapshot"])
    if (snapshot.scheme != "https" or snapshot.netloc != "snapshot.debian.org"
            or snapshot.query or snapshot.fragment
            or not re.fullmatch(r"/archive/debian/[0-9]{8}T[0-9]{6}Z/", snapshot.path)):
        raise ValueError("unsupported Debian snapshot URL")
    snapshot_time = datetime.strptime(
        snapshot.path.removeprefix("/archive/debian/").rstrip("/"),
        "%Y%m%dT%H%M%SZ",
    ).replace(tzinfo=timezone.utc)
    debian_snapshot.require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    epoch, (index_sha256, _), index_bytes = debian_snapshot.authenticated_index_bytes(
        inrelease, packages_index, lock["inrelease_sha256"],
    )
    if (epoch != lock["signed_release_date_epoch"]
            or epoch > int(snapshot_time.timestamp())
            or index_sha256 != lock["packages_index_sha256"]):
        raise ValueError("signed builder index differs from source-reviewed candidate")
    records = debian_snapshot.package_records(io.BytesIO(index_bytes))
    packages = lock["packages"]
    if not isinstance(packages, list) or not packages:
        raise ValueError("builder closure package list missing")
    names = []
    for entry in packages:
        if (not isinstance(entry, dict) or set(entry) != closure.PACKAGE_FIELDS
                or not isinstance(entry["name"], str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", entry["name"])
                or not isinstance(entry["version"], str)
                or not isinstance(entry["architecture"], str)
                or entry["architecture"] not in {"amd64", "all"}
                or type(entry["size"]) is not int or entry["size"] <= 0
                or not isinstance(entry["sha256"], str)
                or not debian_snapshot.HEX_SHA256.fullmatch(entry["sha256"])
                or not isinstance(entry["filename"], str)):
            raise ValueError("invalid builder closure package identity")
        filename = PurePosixPath(entry["filename"])
        if (filename.is_absolute() or filename.as_posix() != entry["filename"]
                or not filename.parts or filename.parts[0] != "pool"
                or ".." in filename.parts or filename.suffix != ".deb"):
            raise ValueError("unsafe builder closure package filename")
        record = records.get((entry["name"], entry["version"], entry["architecture"]))
        if record is None or any(str(entry[field]) != record.get(index_field)
                                 for field, index_field in (("filename", "Filename"),
                                                            ("size", "Size"),
                                                            ("sha256", "SHA256"))):
            raise ValueError("builder closure package differs from signed index")
        names.append(entry["name"])
    if names != sorted(set(names)):
        raise ValueError("builder closure package order or identity differs from review")
    return lock, packages, lock_sha256, index_sha256


def verify_cached(directory_fd, entry):
    name = entry["sha256"] + ".deb"
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory_fd)
    except FileNotFoundError:
        return False
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != entry["size"]:
            raise ValueError("existing builder archive differs from signed index")
        if stream.read(8) != b"!<arch>\n":
            raise ValueError("existing builder archive is not a deb")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if digest != entry["sha256"] or identity(before) != identity(after):
            raise ValueError("existing builder archive differs from signed index")
    return True


def download_one(directory_fd, entry, snapshot, *, open_url=None):
    if open_url is None:
        open_url = open_snapshot_url
    url = urllib.parse.urljoin(snapshot, entry["filename"])
    if urllib.parse.urlsplit(url).netloc != "snapshot.debian.org":
        raise ValueError("builder archive URL escaped signed snapshot")
    temporary = ".partial-" + secrets.token_hex(16)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb") as output:
            request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
            with open_url(request) as response:
                final_url = urllib.parse.urlsplit(response.geturl())
                if final_url.scheme != "https" or final_url.netloc != "snapshot.debian.org":
                    raise ValueError("builder archive redirect escaped signed snapshot")
                digest = hashlib.sha256()
                size = 0
                while chunk := response.read(CHUNK_BYTES):
                    size += len(chunk)
                    if size > entry["size"]:
                        raise ValueError("builder archive exceeds signed index size")
                    digest.update(chunk)
                    output.write(chunk)
            if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise ValueError("downloaded builder archive differs from signed index")
            output.flush()
            os.fsync(output.fileno())
        name = entry["sha256"] + ".deb"
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False)
        os.fsync(directory_fd)
    finally:
        os.unlink(temporary, dir_fd=directory_fd)


def fetch(inrelease, packages_index, archives, *, lock_path=closure.LOCK, open_url=None):
    lock, packages, lock_sha256, index_sha256 = authenticated_packages(
        inrelease, packages_index, lock_path=lock_path,
    )
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("builder archive directory missing or redirected")
    directory_fd = os.open(archives, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    reused = downloaded = 0
    try:
        for entry in packages:
            if verify_cached(directory_fd, entry):
                reused += 1
                continue
            download_one(directory_fd, entry, lock["snapshot"], open_url=open_url)
            if not verify_cached(directory_fd, entry):
                raise ValueError("downloaded builder archive missing after publish")
            downloaded += 1
    finally:
        os.close(directory_fd)
    return {
        "status": "builder-archives-matched-signed-snapshot-unbuilt",
        "closure_lock_sha256": lock_sha256,
        "signed_inrelease_sha256": lock["inrelease_sha256"],
        "signed_packages_index_sha256": index_sha256,
        "package_count": len(packages),
        "reused_count": reused,
        "downloaded_count": downloaded,
        "complete_builder_toolchain": False,
        "image_built": False,
        "private_mode_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inrelease", type=Path, required=True)
    parser.add_argument("--packages-index", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.inrelease, args.packages_index, args.archives), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, urllib.error.URLError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "complete_builder_toolchain": False,
                          "image_built": False, "private_mode_approved": False}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
