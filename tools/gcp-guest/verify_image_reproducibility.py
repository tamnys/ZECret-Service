#!/usr/bin/env python3
"""Compare two completed outer-runner candidate disks without approving either.

The caller supplies the JSON stdout from each production outer-image build and
its stage directory. Distinct files and matching receipts do not establish that
mkosi ran independently twice; that provenance must be recorded separately.
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


BUILT_STATUS = "candidate-outer-image-built-unapproved"
MATCH_STATUS = "diagnostic-two-candidate-raws-byte-identical-unapproved"
DIGEST_FIELDS = (
    "input_lock_sha256",
    "candidate_manifest_sha256",
    "secure_boot_certificate_sha256",
    "zebrad_elf_sha256",
    "zebra_release_lock_sha256",
    "reviewed_zebra_provenance_receipt_sha256",
    "mkosi_package_sha256",
    "uki_sha256",
    "raw_disk_sha256",
)
IDENTITY_FIELDS = ("source_commit", *DIGEST_FIELDS[:-1])
TRUE_FIELDS = (
    "mkosi_executed", "image_built", "signed_uki_checked",
    "verity_userspace_verified", "gpt_roothash_matched",
)
FALSE_FIELDS = (
    "boot_verified", "private_mode_approved",
    "zebra_attestation_independently_verified",
)
OPEN_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
OPEN_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_SIZE = 1024 * 1024  # Streaming buffer; it does not limit accepted image size.


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def real_directory(path, stack):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("stage directory must be an absolute real path")
    fd = os.open(path, OPEN_DIRECTORY)
    stack.callback(os.close, fd)
    return fd, os.fstat(fd)


def child_directory(parent_fd, name, stack):
    fd = os.open(name, OPEN_DIRECTORY, dir_fd=parent_fd)
    stack.callback(os.close, fd)
    return fd, os.fstat(fd)


def regular_file(path, stack, *, dir_fd=None):
    fd = os.open(path, OPEN_FILE, dir_fd=dir_fd)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise ValueError("required report or stage artifact is not one nonempty regular file")
    return fd, info


def unchanged(fd, initial):
    if file_identity(os.fstat(fd)) != file_identity(initial):
        raise ValueError("report or stage artifact changed during comparison")


def hash_file(fd, initial):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(fd, "rb", closefd=False) as stream:
        while block := stream.read(READ_SIZE):
            digest.update(block)
            count += len(block)
    unchanged(fd, initial)
    if count != initial.st_size:
        raise ValueError("stage artifact size changed during comparison")
    return count, digest.hexdigest()


def checked_report(fd, initial):
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(fd, "rb", closefd=False) as stream:
        data = stream.read()
    unchanged(fd, initial)
    if len(data) != initial.st_size:
        raise ValueError("outer-runner report size changed during comparison")
    report = json.loads(data, object_pairs_hook=unique_object,
                        parse_constant=reject_constant)
    if type(report) is not dict or type(report.get("schema_version")) is not int \
            or report["schema_version"] != 1 or report.get("status") != BUILT_STATUS:
        raise ValueError("complete production outer-runner report required")
    for field in TRUE_FIELDS:
        if report.get(field) is not True:
            raise ValueError(f"outer-runner report lacks completed {field}")
    for field in FALSE_FIELDS:
        if report.get(field) is not False:
            raise ValueError(f"outer-runner report has unexpected {field}")
    if (type(report.get("raw_disk_bytes")) is not int
            or report["raw_disk_bytes"] <= 0):
        raise ValueError("outer-runner report lacks raw disk size")
    if not isinstance(report.get("source_commit"), str) or \
            re.fullmatch(r"[0-9a-f]{40}", report["source_commit"]) is None:
        raise ValueError("outer-runner report lacks source commit")
    for field in DIGEST_FIELDS:
        if not isinstance(report.get(field), str) or \
                re.fullmatch(r"[0-9a-f]{64}", report[field]) is None:
            raise ValueError(f"outer-runner report lacks {field}")
    return report, hashlib.sha256(data).hexdigest()


def checked_candidate(stage_path, report_path, stack):
    stage_fd, stage_info = real_directory(stage_path, stack)
    output_fd, output_info = child_directory(stage_fd, "output", stack)
    artifacts_fd, artifacts_info = child_directory(stage_fd, "artifacts", stack)
    report_fd, report_info = regular_file(report_path, stack)
    report, report_digest = checked_report(report_fd, report_info)
    files = [(None, report_path, report_fd, report_info)]
    for parent_fd, name, field in (
        (stage_fd, "inputs.lock.json", "input_lock_sha256"),
        (stage_fd, "candidate-manifest.json", "candidate_manifest_sha256"),
        (artifacts_fd, "secure_boot_certificate", "secure_boot_certificate_sha256"),
        (artifacts_fd, "zebra", "zebrad_elf_sha256"),
        (output_fd, "zrpc-gcp.efi", "uki_sha256"),
    ):
        fd, info = regular_file(name, stack, dir_fd=parent_fd)
        files.append((parent_fd, name, fd, info))
        if hash_file(fd, info)[1] != report[field]:
            raise ValueError(f"stage artifact differs from report {field}")
    raw_fd, raw_info = regular_file("zrpc-gcp.raw", stack, dir_fd=output_fd)
    files.append((output_fd, "zrpc-gcp.raw", raw_fd, raw_info))
    return {"stage_path": Path(stage_path), "stage_fd": stage_fd,
            "stage_info": stage_info, "report_fd": report_fd,
            "report_info": report_info, "report": report,
            "report_sha256": report_digest, "raw_fd": raw_fd,
            "raw_info": raw_info, "files": files,
            "directories": ((stage_fd, "output", output_fd, output_info),
                            (stage_fd, "artifacts", artifacts_fd, artifacts_info))}


def unchanged_candidate(candidate):
    stage_path = candidate["stage_path"]
    if (stage_path.resolve(strict=True) != stage_path
            or file_identity(stage_path.lstat()) !=
            file_identity(candidate["stage_info"])):
        raise ValueError("stage directory changed during comparison")
    unchanged(candidate["stage_fd"], candidate["stage_info"])
    for parent_fd, name, fd, initial in candidate["directories"]:
        unchanged(fd, initial)
        if file_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != \
                file_identity(initial):
            raise ValueError("stage directory path changed during comparison")
    for parent_fd, name, fd, initial in candidate["files"]:
        unchanged(fd, initial)
        if file_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != \
                file_identity(initial):
            raise ValueError("report or stage artifact path changed during comparison")


def compare_raws(first, second):
    first_fd, second_fd = first["raw_fd"], second["raw_fd"]
    os.lseek(first_fd, 0, os.SEEK_SET)
    os.lseek(second_fd, 0, os.SEEK_SET)
    digests = (hashlib.sha256(), hashlib.sha256())
    counts = [0, 0]
    equal = True
    with os.fdopen(first_fd, "rb", closefd=False) as left, \
            os.fdopen(second_fd, "rb", closefd=False) as right:
        while True:
            left_bytes = left.read(READ_SIZE)
            right_bytes = right.read(READ_SIZE)
            if not left_bytes and not right_bytes:
                break
            digests[0].update(left_bytes)
            digests[1].update(right_bytes)
            counts[0] += len(left_bytes)
            counts[1] += len(right_bytes)
            equal &= left_bytes == right_bytes
    for candidate, count, digest in zip((first, second), counts, digests):
        unchanged(candidate["raw_fd"], candidate["raw_info"])
        if count != candidate["raw_info"].st_size or \
                count != candidate["report"]["raw_disk_bytes"] or \
                digest.hexdigest() != candidate["report"]["raw_disk_sha256"]:
            raise ValueError("raw disk bytes or SHA-256 differ from outer-runner report")
    if not equal:
        raise ValueError("candidate raw disk bytes differ")


def compare(first_stage, first_report, second_stage, second_report):
    """Return a non-approving report only after two real candidate raws match."""
    first_stage, second_stage = Path(first_stage), Path(second_stage)
    if first_stage == second_stage or first_stage.is_relative_to(second_stage) or \
            second_stage.is_relative_to(first_stage):
        raise ValueError("two disjoint stage directories required")
    with ExitStack() as stack:
        first = checked_candidate(first_stage, first_report, stack)
        second = checked_candidate(second_stage, second_report, stack)
        for label, first_info, second_info in (
            ("stage directories", first["stage_info"], second["stage_info"]),
            ("outer-runner reports", first["report_info"], second["report_info"]),
            ("raw disks", first["raw_info"], second["raw_info"]),
        ):
            if (first_info.st_dev, first_info.st_ino) == \
                    (second_info.st_dev, second_info.st_ino):
                raise ValueError(f"two distinct {label} required")
        for field in IDENTITY_FIELDS:
            if first["report"][field] != second["report"][field]:
                raise ValueError(f"candidate identity differs: {field}")
        if first["report"]["raw_disk_bytes"] != second["report"]["raw_disk_bytes"]:
            raise ValueError("candidate raw disk sizes differ")
        compare_raws(first, second)
        for candidate in (first, second):
            unchanged_candidate(candidate)
        shared = {field: first["report"][field] for field in IDENTITY_FIELDS}
        return {"schema_version": 1, "status": MATCH_STATUS, **shared,
                "raw_disk_sha256": first["report"]["raw_disk_sha256"],
                "raw_disk_bytes": first["report"]["raw_disk_bytes"],
                "first_outer_runner_report_sha256": first["report_sha256"],
                "second_outer_runner_report_sha256": second["report_sha256"],
                "distinct_stage_directories_checked": True,
                "distinct_report_files_checked": True,
                "distinct_raw_files_checked": True,
                "raw_bytes_compared": True,
                "independent_builds_verified": False,
                "boot_verified": False, "private_mode_approved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("compare",))
    parser.add_argument("--first-stage", type=Path, required=True)
    parser.add_argument("--first-report", type=Path, required=True)
    parser.add_argument("--second-stage", type=Path, required=True)
    parser.add_argument("--second-report", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = compare(arguments.first_stage, arguments.first_report,
                         arguments.second_stage, arguments.second_report)
    except (OSError, ValueError, UnicodeError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "raw_bytes_compared": False,
                          "private_mode_approved": False}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
