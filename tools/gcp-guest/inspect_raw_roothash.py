#!/usr/bin/env python3
"""Cross-check inspected production UKI boot bytes against its GPT root hash.

The outer runner supplies reports from the source-bound GPT, ESP, and verity
inspectors for one hash-pinned raw disk. This pure check cannot authenticate
caller-supplied reports, verify a UKI signature, or approve private mode.
"""

import re
import uuid

import prepare


HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
STATUS = "diagnostic-uki-roothash-gpt-match-unapproved"
REPORT_STATUSES = (
    "diagnostic-gpt-only-unapproved",
    "diagnostic-esp-uki-sections-unapproved",
    "diagnostic-raw-root-verity-unapproved",
)


def _guid(value):
    if type(value) is not str:
        raise ValueError("GPT partition UUID is malformed")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ValueError("GPT partition UUID is malformed") from error
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("GPT partition UUID is not canonical and nonzero")
    return parsed


def inspect(layout, boot, verity, expected_sha256, expected_bytes):
    """Match one exact UKI command line to GPT UUID halves and verity evidence."""
    if (not isinstance(expected_sha256, str)
            or not HEX_SHA256.fullmatch(expected_sha256)
            or type(expected_bytes) is not int or expected_bytes <= 0):
        raise ValueError("explicit raw disk identity required")
    for report, status in zip((layout, boot, verity), REPORT_STATUSES):
        if (type(report) is not dict or report.get("status") != status
                or type(report.get("raw_disk_sha256")) is not str
                or report.get("raw_disk_sha256") != expected_sha256
                or type(report.get("raw_disk_bytes")) is not int
                or report.get("raw_disk_bytes") != expected_bytes
                or report.get("private_mode_approved") is not False):
            raise ValueError("inspector report status or raw disk identity differs")
    if (type(layout.get("gpt_copies_checked")) is not int
            or layout["gpt_copies_checked"] != 2
            or type(layout.get("sector_size")) is not int
            # The source-reviewed production mkosi.conf pins SectorSize=512.
            or layout["sector_size"] != 512):
        raise ValueError("inspected GPT report is incomplete")
    partitions = layout.get("partitions")
    if type(partitions) is not list or len(partitions) != 3:
        raise ValueError("inspected GPT partition set differs")
    by_type = {}
    for partition in partitions:
        if type(partition) is not dict:
            raise ValueError("inspected GPT partition set differs")
        kind = partition.get("type")
        if (type(kind) is not str or kind in by_type or kind not in
                {"root-x86-64", "root-x86-64-verity", "esp"}):
            raise ValueError("inspected GPT partition set differs")
        by_type[kind] = _guid(partition.get("partition_guid"))
    if (set(by_type) != {"root-x86-64", "root-x86-64-verity", "esp"}
            or len(set(by_type.values())) != 3):
        raise ValueError("inspected GPT partition set differs")
    root = by_type["root-x86-64"]
    hashes = by_type["root-x86-64-verity"]
    roothash = root.hex + hashes.hex
    cmdline = f"roothash={roothash} {prepare.FIXED_KERNEL_CMDLINE}"
    if (type(boot.get("uki_cmdline_for_review")) is not str
            or type(verity.get("uki_cmdline_for_review")) is not str
            or boot.get("uki_cmdline_for_review") != cmdline
            or verity.get("uki_cmdline_for_review") != cmdline):
        raise ValueError("UKI root hash or fixed boot command line differs from GPT")
    uki_sha256 = boot.get("uki_sha256")
    if (not isinstance(uki_sha256, str)
            or not HEX_SHA256.fullmatch(uki_sha256)
            or verity.get("uki_sha256") != uki_sha256):
        raise ValueError("ESP and verity reports describe different UKIs")
    if (verity.get("root_partition_guid") != str(root)
            or verity.get("verity_partition_guid") != str(hashes)
            or verity.get("verity_userspace_verified") is not True):
        raise ValueError("verity report does not match the inspected GPT pair")
    return {
        "status": STATUS,
        "raw_disk_sha256": expected_sha256,
        "raw_disk_bytes": expected_bytes,
        "uki_sha256": uki_sha256,
        "roothash": roothash,
        "root_partition_guid": str(root),
        "verity_partition_guid": str(hashes),
        "fixed_cmdline_matched": True,
        "gpt_roothash_matched": True,
        "signed_uki_checked": False,
        "private_mode_approved": False,
    }
