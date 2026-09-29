#!/usr/bin/env python3
"""Derive generated /etc entries and credential modes from signed packages.

The caller supplies rows from source_plan(preflight.authenticated_archives(...))
and the verified staged overlay. The raw inspector must compare every returned
field with the final ext4 inode; this helper grants no boot or private-mode
approval.
"""


# In the pinned libc-bin 2.41-12+deb13u4 package, postinst copies this file
# with cp -p when /etc/nsswitch.conf is absent. The package archive is pinned
# by the reviewed closure; these member identities were independently checked
# against its signed data payload.
NSSWITCH_SOURCE = "usr/share/libc-bin/nsswitch.conf"
NSSWITCH_DESTINATION = "etc/nsswitch.conf"
NSSWITCH_SIZE = 494
NSSWITCH_SHA256 = "eec30745bade42a3f3f792e4d4192e57d2bcfe8e472433b1de426fe39a39cddb"

# The pinned systemd 257.13-1~deb13u1 package contains the exact tmpfiles
# rule `L+ /etc/mtab   -    -    -    -  ../proc/self/mounts` in this member.
TMPFILES_SOURCE = "usr/lib/tmpfiles.d/debian.conf"
TMPFILES_SIZE = 651
TMPFILES_SHA256 = "4e7d4abb134ca09007775626bdddcea67badc0ea5fe4b6dde7466edb770927d2"
MTAB_DESTINATION = "etc/mtab"
MTAB_TARGET = "../proc/self/mounts"

# The pinned systemd 257.13-1~deb13u1 archive ships both directories as
# 0755 root:root. Its credstore.conf contains exact `d` rules that change
# them to 0700 root:root when the package postinst runs systemd-tmpfiles.
CREDSTORE_DIRECTORIES = ("etc/credstore", "etc/credstore.encrypted")
CREDSTORE_SOURCE = "usr/lib/tmpfiles.d/credstore.conf"
CREDSTORE_SOURCE_SIZE = 474
CREDSTORE_SOURCE_SHA256 = "2bafed09323dcb75c9c59ffd863510c2d05b6939fbcda267a82198875d1b4ddb"
CREDSTORE_ARCHIVE_MODE = 0o755
CREDSTORE_FINAL_MODE = 0o700


def _source_map(source_rows):
    if type(source_rows) is not list or not source_rows:
        raise ValueError("authenticated generated /etc source rows required")
    source = {}
    for row in source_rows:
        if type(row) is not dict or type(row.get("path")) is not str:
            raise ValueError("authenticated generated /etc source row is malformed")
        path = row["path"]
        if path in source:
            raise ValueError("duplicate authenticated generated /etc source path: " + path)
        source[path] = row
    return source


def _require_package_file(source, overlay, path, package, size, digest):
    row = source.get(path)
    if (row is None or row.get("kind") != "file"
            or row.get("packages") != [package]
            or (row.get("uid"), row.get("gid")) != (0, 0)
            or row.get("source_mode") != 0o644
            or row.get("output_mode") != 0o644
            or row.get("size") != size
            or row.get("sha256") != digest
            or path in overlay):
        raise ValueError("signed generated /etc package source differs: " + path)


def _require_etc_parent(source, verified_overlay):
    etc = source.get("etc")
    if (etc is None or etc.get("kind") != "directory"
            or (etc.get("uid"), etc.get("gid")) != (0, 0)
            or etc.get("output_mode") != 0o755):
        raise ValueError("generated /etc parent differs from authenticated source")
    if "etc" in verified_overlay:
        etc_overlay = verified_overlay["etc"]
        if (type(etc_overlay) is not dict
                or etc_overlay.get("type") != "directory"
                or etc_overlay.get("mode") != 0o755):
            raise ValueError("generated /etc parent is redirected by overlay")


def credential_store_modes(source_rows, verified_overlay):
    """Derive the two systemd credential directory modes from signed data."""
    if type(verified_overlay) is not dict:
        raise ValueError("verified credential store overlay required")
    source = _source_map(source_rows)
    _require_etc_parent(source, verified_overlay)
    _require_package_file(source, verified_overlay, CREDSTORE_SOURCE,
                          "systemd", CREDSTORE_SOURCE_SIZE,
                          CREDSTORE_SOURCE_SHA256)
    for path in CREDSTORE_DIRECTORIES:
        row = source.get(path)
        if (row is None or row.get("kind") != "directory"
                or row.get("packages") != ["systemd"]
                or (row.get("uid"), row.get("gid")) != (0, 0)
                or row.get("source_mode") != CREDSTORE_ARCHIVE_MODE
                or row.get("output_mode") != CREDSTORE_ARCHIVE_MODE):
            raise ValueError("signed credential store directory differs: " + path)
        if path in verified_overlay:
            raise ValueError("source overlay replaces signed credential store directory: " + path)
    return {path: CREDSTORE_FINAL_MODE for path in CREDSTORE_DIRECTORIES}


def expected_entries(source_rows, verified_overlay):
    """Return source-derived nsswitch bytes and the exact mtab symlink."""
    if type(verified_overlay) is not dict:
        raise ValueError("verified generated /etc overlay required")
    source = _source_map(source_rows)
    _require_etc_parent(source, verified_overlay)
    for path in (NSSWITCH_DESTINATION, MTAB_DESTINATION):
        if path in source or path in verified_overlay:
            raise ValueError("generated /etc path collides with source or overlay: " + path)
    _require_package_file(source, verified_overlay, NSSWITCH_SOURCE,
                          "libc-bin", NSSWITCH_SIZE, NSSWITCH_SHA256)
    _require_package_file(source, verified_overlay, TMPFILES_SOURCE,
                          "systemd", TMPFILES_SIZE, TMPFILES_SHA256)
    return {
        NSSWITCH_DESTINATION: {
            "type": "regular", "mode": 0o644, "uid": 0, "gid": 0,
            "size": NSSWITCH_SIZE, "sha256": NSSWITCH_SHA256,
        },
        MTAB_DESTINATION: {
            "type": "symlink", "mode": 0o777, "uid": 0, "gid": 0,
            "size": len(MTAB_TARGET.encode("ascii")), "target": MTAB_TARGET,
        },
    }
