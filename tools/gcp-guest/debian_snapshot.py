"""Offline Debian archive membership check for a reviewed guest input lock.

GnuPG's gpgv verifies the InRelease signature. This module only parses the
authenticated metadata and compares its hashes to local files. It does not
resolve dependencies or make a staged candidate deployable.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
import io
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess

TRUST = Path(__file__).with_name("trust")
KEYRING = TRUST / "debian-trixie-signers.gpg"
KEYRING_SHA256 = "c042cf3ba41a234f709a6f50053ce3c23031d2d4f109a563ffc1193403b26895"
KEYRING_SIZE = 18360  # reviewed, committed binary keyring
# Debian trixie gpgv 2.4.7-21+deb13u1+b5 amd64, extracted without scripts
# from the package whose archive hash is bound by the signed Packages.xz.
GPGV_SHA256 = "3f29dddc10e4089aeac5b2675313f4e5fe822abe5ab3bf7898d238c32d758304"
GPGV_SIZE = 532840  # /usr/bin/gpgv in that signed Debian package
TRIXIE_ARCHIVE_FINGERPRINT = "04B54C3CDCA79751B16BC6B5225629DF75B188BD"
INDEX_PATH = "main/binary-amd64/Packages.xz"
SOURCE_INDEX_PATH = "main/source/Sources.xz"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Measured from the reviewed 20260918 InRelease and the larger of its two
# index sizes pinned in deploy/gcp/guest/input-identities.json. A new snapshot
# requires explicit review of these limits before it can be consumed.
MAX_INRELEASE_BYTES = 140421
MAX_SIGNED_INDEX_BYTES = 10540436
# Match the managed APT snapshot hold in SUPPLY_CHAIN_HARDENING.md. An
# authenticated archive snapshot is not yet eligible for package consumption.
MIN_SNAPSHOT_AGE = timedelta(days=7)


def require_snapshot_age(snapshot_time, now):
    if now - snapshot_time < MIN_SNAPSHOT_AGE:
        raise ValueError("Debian snapshot has not cleared the seven-day hold")


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bounded_regular_bytes(path, maximum, label):
    """Read at most maximum+1 bytes from one no-follow file descriptor."""
    if path.is_symlink():
        raise ValueError(f"{label} redirected")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError(f"{label} exceeds reviewed size")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(data) > maximum or len(data) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError(f"{label} changed or exceeds reviewed size")
    return data


@contextmanager
def sealed_reviewed_file(path, expected_sha256, expected_size, label, *, executable=False):
    """Hash the exact copied bytes, then keep them immutable for the child.

    This pins the executable and public keyring, not their dynamic libraries.
    The builder's complete toolchain closure remains a separate release gate.
    """
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise ValueError(f"{label} differs from reviewed input identity")
        sealed = os.memfd_create("zrpc-reviewed-input", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            digest = hashlib.sha256()
            remaining = expected_size
            while remaining:
                chunk = os.read(source, min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError(f"{label} changed during verification")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(sealed, view)
                    if written == 0:
                        raise OSError(f"{label} could not be copied into sealed memory")
                    view = view[written:]
                remaining -= len(chunk)
            after = os.fstat(source)
            before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if os.read(source, 1) or before_identity != after_identity:
                raise ValueError(f"{label} changed during verification")
            if digest.hexdigest() != expected_sha256:
                raise ValueError(f"{label} differs from reviewed input identity")
            os.fchmod(sealed, 0o500 if executable else 0o400)
            fcntl.fcntl(sealed, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            yield Path(f"/proc/self/fd/{sealed}"), sealed
        finally:
            os.close(sealed)
    finally:
        os.close(source)


def verify_signature(inrelease, *, pass_fds=()):
    executable = shutil.which("gpgv")
    if executable is None:
        raise ValueError("gpgv is required for Debian archive authentication")
    with sealed_reviewed_file(KEYRING, KEYRING_SHA256, KEYRING_SIZE, "Debian trust keyring") as (keyring, keyring_fd):
        with sealed_reviewed_file(Path(executable), GPGV_SHA256, GPGV_SIZE, "gpgv executable", executable=True) as (program, program_fd):
            result = subprocess.run(
                [str(program), "--status-fd", "1", "--keyring", str(keyring), str(inrelease)],
                capture_output=True, text=True, check=False,
                pass_fds=(*pass_fds, keyring_fd, program_fd),
            )
    signatures = []
    for line in result.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            fields = line.split()
            # VALIDSIG ends with the primary key fingerprint for subkey signatures.
            signatures.append(fields[-1] if len(fields) > 3 else fields[2])
    if result.returncode != 0 or TRIXIE_ARCHIVE_FINGERPRINT not in signatures:
        raise ValueError("Debian InRelease signature or reviewed signer rejected")


@contextmanager
def sealed_inrelease(data):
    """Give gpgv and the Release parser the same immutable Linux file bytes."""
    descriptor = os.memfd_create("zrpc-debian-inrelease", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield Path(f"/proc/self/fd/{descriptor}"), descriptor
    finally:
        os.close(descriptor)


def authenticated_index_bytes(inrelease, index, expected_inrelease_sha256, index_path=INDEX_PATH):
    """Authenticate one immutable input snapshot; never reread source paths."""
    if inrelease.is_symlink() or not inrelease.is_file() or index.is_symlink() or not index.is_file():
        raise ValueError("Debian signed metadata missing or redirected")
    inrelease_bytes = bounded_regular_bytes(inrelease, MAX_INRELEASE_BYTES, "Debian InRelease")
    if hashlib.sha256(inrelease_bytes).hexdigest() != expected_inrelease_sha256:
        raise ValueError("Debian InRelease differs from reviewed snapshot")
    with sealed_inrelease(inrelease_bytes) as (sealed_path, descriptor):
        verify_signature(sealed_path, pass_fds=(descriptor,))
        epoch, (index_hash, index_size) = release_fields(sealed_path, index_path)
    label = "Debian Sources index" if index_path == SOURCE_INDEX_PATH else "Debian package index"
    if index_size <= 0 or index_size > MAX_SIGNED_INDEX_BYTES:
        raise ValueError(f"{label} exceeds reviewed size")
    index_bytes = bounded_regular_bytes(index, index_size, label)
    if len(index_bytes) != index_size or hashlib.sha256(index_bytes).hexdigest() != index_hash:
        raise ValueError(f"{label} differs from signed Release")
    return epoch, (index_hash, index_size), index_bytes


def release_fields(inrelease, index_path=INDEX_PATH):
    data = inrelease.read_text(encoding="utf-8")
    if not data.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
        raise ValueError("not a clear-signed Debian InRelease")
    try:
        signed = data.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    except IndexError as error:
        raise ValueError("malformed Debian InRelease") from error
    lines = signed.splitlines()
    if any(line.startswith("- ") for line in lines):
        # Release metadata does not require dash escaping. Reject it to keep
        # the parsed text byte-for-byte aligned with the signed plain text.
        raise ValueError("unexpected dash escaping in Debian InRelease")
    fields = {}
    current = None
    for line in lines:
        if line.startswith(" "):
            if current is not None:
                fields[current].append(line.strip())
        elif ":" in line:
            key, value = line.split(":", 1)
            if key in fields:
                raise ValueError("duplicate Debian Release field")
            current = key
            fields[key] = [value.strip()] if value.strip() else []
        else:
            raise ValueError("malformed Debian Release field")
    if fields.get("Origin") != ["Debian"] or fields.get("Codename") != ["trixie"]:
        raise ValueError("wrong Debian distribution")
    if "amd64" not in " ".join(fields.get("Architectures", [])).split() or "main" not in " ".join(fields.get("Components", [])).split():
        raise ValueError("Debian amd64 main index absent")
    try:
        date = parsedate_to_datetime(fields["Date"][0])
        if date.tzinfo is None:
            raise ValueError("Debian Release date lacks timezone")
        epoch = int(date.astimezone(timezone.utc).timestamp())
    except (KeyError, IndexError, TypeError) as error:
        raise ValueError("Debian Release date missing") from error
    indexes = {}
    for line in fields.get("SHA256", []):
        parts = line.split()
        if len(parts) != 3 or not HEX_SHA256.fullmatch(parts[0]) or not parts[1].isdigit():
            raise ValueError("malformed Debian Release SHA256 entry")
        if parts[2] in indexes:
            raise ValueError("duplicate Debian index entry")
        indexes[parts[2]] = (parts[0], int(parts[1]))
    if index_path not in (INDEX_PATH, SOURCE_INDEX_PATH) or index_path not in indexes:
        raise ValueError("required Debian index not signed")
    return epoch, indexes[index_path]


def package_records(index):
    records = {}
    with lzma.open(index, "rt", encoding="utf-8") as stream:
        paragraph = {}
        for line in stream:
            if line == "\n":
                if paragraph:
                    identity = (paragraph.get("Package"), paragraph.get("Version"), paragraph.get("Architecture"))
                    if None in identity or identity in records:
                        raise ValueError("invalid or duplicate Debian package record")
                    records[identity] = paragraph
                    paragraph = {}
            elif line.startswith(" "):
                continue  # dependency descriptions are irrelevant to archive membership
            else:
                if ":" not in line:
                    raise ValueError("malformed Debian package index")
                key, value = line.split(":", 1)
                if key in paragraph:
                    raise ValueError("duplicate Debian package field")
                paragraph[key] = value.strip()
        if paragraph:
            identity = (paragraph.get("Package"), paragraph.get("Version"), paragraph.get("Architecture"))
            if None in identity or identity in records:
                raise ValueError("invalid or duplicate Debian package record")
            records[identity] = paragraph
    return records


def verify_snapshot(lock, paths, inputs, manifest):
    """Return signed metadata identity after verifying every listed local .deb."""
    epoch, (index_hash, index_size), index_bytes = authenticated_index_bytes(
        paths["snapshot_inrelease"], paths["packages_index"],
        lock["artifacts"]["snapshot_inrelease"]["sha256"],
    )
    if epoch != lock["source_date_epoch"]:
        raise ValueError("source epoch differs from signed Debian Release date")
    snapshot_time = datetime.strptime(lock["snapshot"].rstrip("/").rsplit("/", 1)[-1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    if epoch > int(snapshot_time.timestamp()):
        raise ValueError("signed Debian Release postdates selected snapshot")
    require_snapshot_age(snapshot_time, datetime.now(timezone.utc))
    records = package_records(io.BytesIO(index_bytes))
    seen = set()
    archives = {}
    for package in manifest:
        if set(package) != {"name", "version", "architecture", "filename", "size", "sha256", "path"}:
            raise ValueError("incomplete Debian package identity")
        identity = (package["name"], package["version"], package["architecture"])
        if identity in seen or package["architecture"] not in {"amd64", "all"}:
            raise ValueError("duplicate or wrong-architecture Debian package")
        seen.add(identity)
        record = records.get(identity)
        if record is None or any(str(package[field]) != record.get(index_field) for field, index_field in (("filename", "Filename"), ("size", "Size"), ("sha256", "SHA256"))):
            raise ValueError("package identity is not in signed Debian index")
        filename = PurePosixPath(package["filename"])
        if filename.is_absolute() or ".." in filename.parts or filename.parts[0] != "pool" or not str(filename).endswith(".deb"):
            raise ValueError("unsafe Debian package index filename")
        if type(package["size"]) is not int or package["size"] <= 0 or not HEX_SHA256.fullmatch(package["sha256"]):
            raise ValueError("invalid Debian package hash or size")
        relative = Path(package["path"])
        if relative.as_posix() != f"debs/{package['sha256']}.deb":
            raise ValueError("Debian package must use content-addressed local path")
        archive = inputs / relative
        if archive.is_symlink() or not archive.is_file() or not archive.resolve().is_relative_to(inputs.resolve()) or archive.stat().st_size != package["size"] or sha256(archive) != package["sha256"]:
            raise ValueError("local Debian package differs from signed index")
        with archive.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                raise ValueError("local Debian package is not a deb archive")
        archives[identity] = archive
    return {"inrelease_sha256": lock["artifacts"]["snapshot_inrelease"]["sha256"], "index_sha256": index_hash, "source_date_epoch": epoch, "package_count": len(archives)}, archives
