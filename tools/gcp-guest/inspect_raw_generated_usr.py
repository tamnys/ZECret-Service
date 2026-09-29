#!/usr/bin/env python3
"""Derive mkosi's clock-epoch file from reviewed source, never from the image.

The caller supplies the authenticated Debian source plan, the verified staged
overlay, and SourceDateEpoch from the validated production input lock. It must
compare *every* returned field, including mtime_ns, with the raw ext4 inode.
The current component reader does not inspect mtime; this helper alone grants
no raw-root, boot, or private-mode approval.
"""

import hashlib

import fetch_guest_closure as guest
import prepare


# Reviewed mkosi/__init__.py configure_clock(), clamp_mtime(), and build order.
# A source rebase requires a new review of all three before this expectation is
# used. configure_clock() touches an absent file with umask(~0o644), and
# normalize_mtime() clamps its mtime after finalizers to SourceDateEpoch.
MKOSI_CLOCK_SOURCE_COMMIT = "54c625c380ef5500f17460981a3c67b109b6a847"
CLOCK_EPOCH = "usr/lib/clock-epoch"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def expected_entries(source_rows, verified_overlay, source_date_epoch):
    """Return the one exact source-derived entry, including required mtime."""
    if prepare.SOURCE_COMMIT != MKOSI_CLOCK_SOURCE_COMMIT:
        raise ValueError("mkosi clock generation needs source re-review")
    if (type(source_date_epoch) is not int
            or source_date_epoch != guest.SIGNED_RELEASE_EPOCH
            or source_date_epoch <= 0):
        raise ValueError("clock epoch differs from signed production source date")
    if type(source_rows) is not list or not source_rows or type(verified_overlay) is not dict:
        raise ValueError("authenticated source and verified overlay required")
    source = {}
    for row in source_rows:
        if type(row) is not dict or type(row.get("path")) is not str:
            raise ValueError("authenticated source row is malformed")
        path = row["path"]
        if path in source:
            raise ValueError("duplicate authenticated source path: " + path)
        source[path] = row
    if CLOCK_EPOCH in source or CLOCK_EPOCH in verified_overlay:
        raise ValueError("clock epoch collides with authenticated source or overlay")
    for path in ("usr", "usr/lib"):
        row = source.get(path)
        if (row is None or row.get("kind") != "directory"
                or (row.get("uid"), row.get("gid")) != (0, 0)
                or row.get("output_mode") != 0o755):
            raise ValueError("clock epoch parent differs from authenticated source: " + path)
        overlay = verified_overlay.get(path)
        if overlay is not None and (type(overlay) is not dict
                                    or overlay.get("type") != "directory"
                                    or overlay.get("mode") != 0o755):
            raise ValueError("clock epoch parent is redirected by overlay: " + path)
    return {CLOCK_EPOCH: {
        "type": "regular", "mode": 0o644, "uid": 0, "gid": 0,
        "size": 0, "sha256": EMPTY_SHA256,
        "mtime_ns": source_date_epoch * 1_000_000_000,
    }}
