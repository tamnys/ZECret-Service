"""Compare the published v0.5.9 archive with the observed Cloud catalog digest.

Offline operator probe only. It neither executes/extracts the image nor grants
private authority. Algorithm: meta-dstack e3655d1390feee3736476f4bda35c4354b4a12fc,
mkimage.sh lines 70-91. Archive hash: official release asset 401364871.
"""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path

ARCHIVE_SHA256 = "f3888f64e215bc1e1af53a1f3d13b4df48fe40d4a3059049bb87d4c7c06aff97"
CATALOG_DIGEST = "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
COMPONENTS = ("ovmf.fd", "bzImage", "initramfs.cpio.gz", "metadata.json")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", type=Path)
args = parser.parse_args()
with args.archive.open("rb") as stream:
    archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
require(archive_hash == ARCHIVE_SHA256, "archive checksum mismatch")

with tarfile.open(args.archive) as archive:
    members = archive.getmembers()

    def read_member(name):
        matches = [m for m in members if m.name == "dstack-0.5.9/" + name]
        require(len(matches) == 1 and matches[0].isfile(), "missing, duplicate or non-regular member")
        return archive.extractfile(matches[0])

    lines = []
    for name in COMPONENTS:
        with read_member(name) as stream:
            component_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{component_hash}  {name}\n")
    computed_manifest = "".join(lines).encode("ascii")
    with read_member("sha256sum.txt") as stream:
        manifest = stream.read()
    require(computed_manifest == manifest, "component manifest mismatch")
    digest = hashlib.sha256(manifest).hexdigest()
    with read_member("digest.txt") as stream:
        archived_digest = stream.read()
    require(archived_digest == (digest + "\n").encode("ascii"), "archived digest mismatch")
    require(digest == CATALOG_DIGEST, "catalog digest mismatch")
    with read_member("metadata.json") as stream:
        metadata = json.load(stream)
    expected = {
        "version": "0.5.9",
        "git_revision": "e3655d1390feee3736476f4bda35c4354b4a12fc",
        "bios": "ovmf.fd",
        "kernel": "bzImage",
        "initrd": "initramfs.cpio.gz",
        "rootfs": "rootfs.img.verity",
    }
    require(all(metadata.get(k) == v for k, v in expected.items()), "metadata identity mismatch")
    require(metadata.get("is_dev") is False and metadata.get("shared_ro") is True, "metadata mode mismatch")

print(json.dumps({
    "archive_sha256": archive_hash,
    "catalog_digest": digest,
    "component_manifest_matches": True,
    "production_metadata_matches": True,
    "rootfs_commitments": [s for s in metadata["cmdline"].split() if s.startswith("dstack.rootfs_")],
    "build_reproduced": False,
    "dm_verity_verified": False,
    "live_attestation_verified": False,
    "private_accepted": False,
}, indent=2))
