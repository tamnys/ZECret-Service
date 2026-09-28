#!/usr/bin/env python3
"""Local, no-route handoff to the source-bound GCP outer image runner.

Run under probe_builder_owner_map on a native x86_64 builder. The selected
source, staged signed builder, and scratch must be separate siblings on the
workspace volume. This does not fetch inputs, create keys, deploy, or approve
an image. The full-build caller supplies the independently reviewed inputs and
an already-mounted, private tmpfs signing key.
Before handoff, the bound trees are checked for nested mounts and AF_UNIX
socket paths. The explicit --preflight-only diagnostic exercises the same
signed builder handoff without reading a signing key or starting mkosi. Neither
path establishes that network egress is excluded after the builder starts.
"""

import argparse
import hashlib
import importlib
import json
import lzma
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import tarfile


SCRIPT = "tools/gcp-guest/native_full_image_harness.py"
SIGNING_MOUNT = Path("/run/zrpc-build-signing")
SOURCE_IN_GUEST = Path("/workspace")
SCRATCH_IN_GUEST = SOURCE_IN_GUEST / ".codex-tmp"
INPUT_FILES = ("inputs.lock.json", "zebra-provenance.json")
INPUT_DIRS = ("inputs", "rust-bundle", "metadata", "builder-archives")
PREFLIGHT_INPUT_DIRS = ("metadata", "builder-archives")
STAGED_MOUNT_TARGETS = frozenset({"proc", "dev", "workspace", "zrpc-apt-scratch"})
MOUNT_PATH_ESCAPES = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
       "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}


def real_directory(path, label):
    if not path.is_absolute() or path.is_symlink() or not path.is_dir() or \
            path.resolve(strict=True) != path:
        raise ValueError(f"{label} must be one real absolute directory")
    return path


def checked_layout(workspace, source, scratch, staged, *,
                   input_files=INPUT_FILES, input_dirs=INPUT_DIRS):
    workspace = real_directory(workspace, "workspace volume")
    for path, label in ((source, "selected source"), (scratch, "image scratch"),
                        (staged, "staged builder")):
        real_directory(path, label)
        if path.parent != workspace:
            raise ValueError("source, scratch, and builder must be separate workspace siblings")
    if len({source, scratch, staged}) != 3:
        raise ValueError("source, scratch, and builder must be disjoint")
    for path, label in ((source, "selected source"), (scratch, "image scratch"),
                        (staged, "staged builder")):
        info = path.stat()
        if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{label} must be owned by mapped root")
    if stat.S_IMODE(scratch.stat().st_mode) != 0o700:
        raise ValueError("image scratch must be private")
    overlay = source / ".codex-tmp"
    if overlay.exists() or overlay.is_symlink():
        real_directory(overlay, "source scratch overlay target")
        if os.listdir(overlay):
            raise ValueError("source scratch overlay target must be empty")
    if (scratch / "candidate-stage").exists() or (scratch / "candidate-stage").is_symlink():
        raise ValueError("candidate stage must be fresh")
    for name in input_files:
        path = scratch / name
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
            raise ValueError(f"missing real image input: {name}")
    for name in input_dirs:
        real_directory(scratch / name, f"image input {name}")
    apt = scratch / "apt-scratch"
    if apt.exists() or apt.is_symlink():
        real_directory(apt, "APT scratch")
        if os.listdir(apt):
            raise ValueError("APT scratch must be fresh")
    return overlay, apt


def mountinfo_path(value):
    """Decode the path escaping specified for /proc/self/mountinfo."""
    decoded = []
    index = 0
    while index < len(value):
        if value[index] == "\\":
            escape = value[index + 1:index + 4]
            if escape not in MOUNT_PATH_ESCAPES:
                raise ValueError("malformed mountinfo path escape")
            decoded.append(MOUNT_PATH_ESCAPES[escape])
            index += 4
        else:
            decoded.append(value[index])
            index += 1
    path = "".join(decoded)
    if not path.startswith("/") or os.path.normpath(path) != path:
        raise ValueError("malformed mountinfo path")
    return Path(path)


def checked_bound_mounts(source, scratch, staged, mountinfo=None):
    """Reject every mount rooted at or below a tree passed to the builder."""
    contents = (Path("/proc/self/mountinfo").read_text()
                if mountinfo is None else mountinfo)
    lines = contents.splitlines()
    if not lines:
        raise ValueError("mountinfo is empty")
    roots = (source, scratch, staged)
    for line in lines:
        if line.count(" - ") != 1:
            raise ValueError("malformed mountinfo record")
        left, right = line.split(" - ")
        fields = left.split(" ")
        trailer = right.split(" ")
        if (len(fields) < 6 or len(trailer) < 3
                or any(not field for field in fields + trailer)
                or not fields[0].isdigit() or not fields[1].isdigit()
                or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2])):
            raise ValueError("malformed mountinfo record")
        mountinfo_path(fields[3])
        target = mountinfo_path(fields[4])
        if any(target == root or target.is_relative_to(root) for root in roots):
            raise ValueError("bound builder tree contains a mountpoint: " + str(target))


def checked_bound_sockets(source, scratch, staged):
    """Scan bound trees without following legitimate source or package symlinks."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def walk(directory, relative):
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name
                child = f"{relative}/{name}" if relative else name
                observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISSOCK(observed.st_mode):
                    raise ValueError("bound builder tree contains an AF_UNIX socket: " + child)
                if stat.S_ISDIR(observed.st_mode):
                    descriptor = os.open(name, directory_flags, dir_fd=directory)
                    try:
                        opened = os.fstat(descriptor)
                        if (observed.st_dev, observed.st_ino, observed.st_mode) != \
                                (opened.st_dev, opened.st_ino, opened.st_mode):
                            raise ValueError("bound builder tree changed during socket scan")
                        walk(descriptor, child)
                    finally:
                        os.close(descriptor)

    for root in (source, scratch, staged):
        descriptor = os.open(root, directory_flags)
        try:
            walk(descriptor, str(root))
        finally:
            os.close(descriptor)


def checked_staged_mount_targets(staged, reserved):
    """Validate every directory excluded from the signed builder inventory."""
    if not STAGED_MOUNT_TARGETS <= reserved:
        raise ValueError("staged builder mount target inventory differs")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = os.open(staged, directory_flags)
    try:
        for name in sorted(reserved):
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", name):
                raise ValueError("invalid staged builder mount target")
            try:
                observed = os.stat(name, dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if name not in STAGED_MOUNT_TARGETS:
                raise ValueError("unused staged builder mount target is present: " + name)
            if not stat.S_ISDIR(observed.st_mode):
                raise ValueError("staged builder mount target is not a real directory: " + name)
            descriptor = os.open(name, directory_flags, dir_fd=root)
            try:
                opened = os.fstat(descriptor)
                if ((observed.st_dev, observed.st_ino, observed.st_mode) !=
                        (opened.st_dev, opened.st_ino, opened.st_mode)
                        or os.listdir(descriptor)):
                    raise ValueError("staged builder mount target must be empty: " + name)
            finally:
                os.close(descriptor)
    finally:
        os.close(root)


def git_output(source, *args):
    environment = {**ENV, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    command = ["/usr/bin/git", "-C", str(source), "-c", "core.fsmonitor=false",
               "-c", "core.untrackedCache=false", *args]
    return subprocess.run(command, check=True, capture_output=True,
                          stdin=subprocess.DEVNULL, env=environment).stdout


def checked_source(source, revision):
    """Check local checkout consistency; the exact-commit fetch is the trust root."""
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("exact selected source revision required")
    script = Path(__file__)
    if not script.is_absolute() or script.is_symlink() or script != source / SCRIPT:
        raise ValueError("native handoff must run from the selected checkout")
    if git_output(source, "rev-parse", "--show-toplevel").strip() != os.fsencode(source):
        raise ValueError("selected source is not the checkout root")
    if git_output(source, "rev-parse", "HEAD").strip() != revision.encode():
        raise ValueError("selected source HEAD differs from requested revision")
    status = git_output(source, "status", "--porcelain", "--untracked-files=all",
                        "--ignored").splitlines()
    if any(row != b"!! .codex-tmp/" for row in status):
        raise ValueError("selected source checkout has changed or unreviewed files")
    selected = git_output(source, "show", "--no-ext-diff", "--no-textconv",
                          f"{revision}:{SCRIPT}")
    if script.read_bytes() != selected:
        raise ValueError("native handoff differs from selected HEAD")


def checked_preimport_tree(source, revision):
    """Reject hidden edits, extra bytecode, and cached local code before import."""
    prefixes = ("tools/gcp-guest",)
    locks = ("deploy/gcp/builder-closure.lock.json",
             "deploy/gcp/builder-direct-packages.lock.json")
    selected = {os.fsdecode(name) for name in git_output(
        source, "ls-tree", "-r", "--name-only", "-z", revision, "--", *prefixes,
        *locks).split(b"\0") if name}
    if not set(locks) <= selected or not any(
            name.startswith("tools/gcp-guest/") for name in selected):
        raise ValueError("selected preflight source or builder locks are missing")
    local = set(locks)
    for path in (source / prefixes[0]).rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("preflight source contains an unreviewed entry")
        if path.is_file():
            local.add(path.relative_to(source).as_posix())
    if local != selected:
        raise ValueError("preflight source inventory differs from selected HEAD")
    module_names = {Path(name).stem for name in selected
                    if name.startswith("tools/gcp-guest/") and name.endswith(".py")}
    module_names.discard(Path(SCRIPT).stem)  # This script is already __main__.
    if module_names & sys.modules.keys():
        raise ValueError("local preflight module was cached before source verification")
    for relative in sorted(selected):
        path = source / relative
        if path.read_bytes() != git_output(source, "show", "--no-ext-diff",
                                           "--no-textconv", f"{revision}:{relative}"):
            raise ValueError("preflight source bytes differ from selected HEAD: " + relative)


def checked_signing_mount(mount=SIGNING_MOUNT, mountinfo=None):
    """Check the existing key mount without reading or printing private bytes."""
    if mount != SIGNING_MOUNT or mount.is_symlink() or not mount.is_dir() or \
            not os.path.ismount(mount):
        raise ValueError("fixed signing mount is missing")
    info = mount.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("signing mount is not root-owned private storage")
    lines = (Path("/proc/self/mountinfo").read_text().splitlines()
             if mountinfo is None else mountinfo.splitlines())
    matches = [parts for line in lines if " - " in line
               for parts in [line.split(" - ", 1)]
               if len(parts[0].split()) > 4 and parts[0].split()[4] == str(mount)]
    if len(matches) != 1 or matches[0][1].split()[0] != "tmpfs":
        raise ValueError("signing mount must be an exact tmpfs mount")
    if set(os.listdir(mount)) != {"secure-boot.key"}:
        raise ValueError("signing mount contains unexpected files")
    key = mount / "secure-boot.key"
    descriptor = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        key_info = os.fstat(descriptor)
        if (not stat.S_ISREG(key_info.st_mode) or key_info.st_uid != 0
                or key_info.st_nlink != 1 or key_info.st_size <= 0
                or stat.S_IMODE(key_info.st_mode) & 0o077):
            raise ValueError("signing key is not one private root-owned regular file")
    finally:
        os.close(descriptor)


def checked_namespace(parent):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() != 0:
        raise ValueError("native x86_64 mapped-root builder required")
    for kind in ("user", "mnt", "net", "pid"):
        current = os.readlink(f"/proc/self/ns/{kind}")
        if not re.fullmatch(rf"{kind}:\[[0-9]+\]", parent[kind]) or \
                current == parent[kind]:
            raise ValueError("outer builder namespace differs from required owner-map handoff")
    if (os.readlink("/proc/1/ns/pid") != os.readlink("/proc/self/ns/pid")
            or [tuple(map(int, row.split())) for row in
                Path("/proc/self/uid_map").read_text().splitlines()] != [(0, 0, 1)]
            or sorted(tuple(map(int, row.split())) for row in
                      Path("/proc/self/gid_map").read_text().splitlines()) !=
            [(0, 0, 1), (42, 42, 1)]
            or Path("/proc/self/setgroups").read_text().strip() != "deny"
            or {name for _, name in socket.if_nameindex()} != {"lo"}):
        raise ValueError("mapped owner, PID, or loopback-only interface differs")
    for route_file in ("/proc/net/route", "/proc/net/ipv6_route"):
        lines = Path(route_file).read_text().splitlines()
        if route_file.endswith("/route"):
            if lines and lines[0].split()[:1] != ["Iface"]:
                raise ValueError("outer IPv4 route table is malformed")
            lines = lines[1:]
        if any(len(parts) != (11 if route_file.endswith("/route") else 10)
               or (parts[0] if route_file.endswith("/route") else parts[-1]) != "lo"
               for line in lines for parts in [line.split()]):
            raise ValueError("outer builder has a non-loopback route")
    for descriptor in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        if target.startswith("socket:"):
            raise ValueError("outer builder inherited a socket")


def checked_staged_builder(source, scratch, staged, revision):
    """Check signed-source package bytes before any chrooted executable runs.

    Source-pinned archive hashes authenticate the staged payload here. Debian
    signature and archive membership are rechecked inside that verified tree.
    """
    checked_preimport_tree(source, revision)
    source_modules = str(source / "tools/gcp-guest")
    sys.path.insert(0, source_modules)
    try:
        disk = importlib.import_module("prepare_guest_disk_basetree_profile")
    finally:
        sys.path.remove(source_modules)
    checked_staged_mount_targets(staged, disk.MOUNTED_SCRATCH)
    lock, lock_sha256, _ = disk.builder_fetch.reviewed_lock(
        disk.builder_closure.LOCK)
    archives_fd = disk.guest.open_directory(scratch / "builder-archives",
                                            "builder archives")
    try:
        packages = [(entry["name"], disk.builder.locked_archive(entry, archives_fd))
                    for entry in lock["packages"]]
    finally:
        os.close(archives_fd)
    payloads, expected = disk.builder.payload_entries(packages)
    del payloads, packages
    manifest = {"schema_version": 1, "status": disk.builder.STATUS,
                "builder_closure_lock_sha256": lock_sha256,
                "snapshot": lock["snapshot"],
                "package_count": len(lock["packages"]),
                "entries": [expected[path] for path in sorted(expected)],
                "signed_snapshot_rechecked": False,
                "package_scripts_executed": False,
                "runtime_execution_verified": False,
                "complete_builder_toolchain": False,
                "image_built": False, "private_mode_approved": False}
    encoded = disk.root_profile.canonical_bytes(manifest)
    root_fd = os.open(staged, disk.builder.DIRECTORY_FLAGS)
    try:
        stored = disk.root_profile.verified_file(root_fd, disk.builder.MANIFEST,
                                                len(encoded), mode=0o600)
    finally:
        os.close(root_fd)
    if stored != encoded:
        raise ValueError("staged builder manifest differs from source-pinned packages")
    return disk.inspect_staged_builder(staged, expected)


def mount(*args):
    subprocess.run(["/usr/bin/mount", *map(str, args)], check=True,
                   stdin=subprocess.DEVNULL, env=ENV)


def bind(source, target, *, readonly):
    mount("--bind", source, target)
    if readonly:
        mount("-o", "remount,bind,ro", target)
    checked_bind_mount(target, readonly)


def checked_bind_mount(target, readonly, mountinfo=None):
    """Check the exact mount and its per-mount policy, including same-FS binds."""
    contents = (Path("/proc/self/mountinfo").read_text()
                if mountinfo is None else mountinfo)
    matches = []
    for line in contents.splitlines():
        if line.count(" - ") != 1:
            raise ValueError("malformed builder mountinfo record")
        left, right = line.split(" - ")
        fields = left.split(" ")
        trailer = right.split(" ")
        if (len(fields) < 6 or len(trailer) < 3
                or any(not field for field in fields + trailer)
                or not fields[0].isdigit() or not fields[1].isdigit()
                or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2])):
            raise ValueError("malformed builder mountinfo record")
        mountinfo_path(fields[3])
        if mountinfo_path(fields[4]) == target:
            matches.append(set(fields[5].split(",")))
    expected, unexpected = ("ro", "rw") if readonly else ("rw", "ro")
    if (len(matches) != 1 or expected not in matches[0]
            or unexpected in matches[0]
            or bool(os.statvfs(target).f_flag & os.ST_RDONLY) != readonly):
        raise ValueError("builder bind mount has unexpected write policy")


def mountpoint_directory(path):
    if path.is_symlink():
        raise ValueError("builder mountpoint redirects")
    if path.exists():
        real_directory(path, "builder mountpoint")
    else:
        path.mkdir(mode=0o700)


def run_in_builder(staged, arguments):
    def enter():
        os.chroot(staged)
        os.chdir("/")
    subprocess.run(arguments, check=True, preexec_fn=enter,
                   stdin=subprocess.DEVNULL, env=ENV)


def handoff_json(path, expected_sha256=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600):
            raise ValueError("outer image handoff is not one private regular file")
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                             item.st_nlink, item.st_size, item.st_mtime_ns,
                             item.st_ctime_ns)
    if len(data) != before.st_size or identity(before) != identity(after):
        raise ValueError("outer image handoff changed during read")
    observed_sha256 = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and observed_sha256 != expected_sha256:
        raise ValueError("outer image handoff SHA-256 differs")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate outer image handoff field")
            result[key] = value
        return result
    report = json.loads(data, object_pairs_hook=unique)
    if type(report) is not dict:
        raise ValueError("outer image handoff is not an object")
    return report, observed_sha256


def checked_final_disk(path, expected_sha256, expected_bytes):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size != expected_bytes):
            raise ValueError("postbuild import disk differs from reinspection receipt")
        observed_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                             item.st_nlink, item.st_size, item.st_mtime_ns,
                             item.st_ctime_ns)
    if (identity(before) != identity(after)
            or observed_sha256 != expected_sha256):
        raise ValueError("postbuild import disk differs from reinspection receipt")


def postbuild_import(staged, args):
    """Keep import conversion inside the same checked no-route builder."""
    report_host = args.scratch / "outer-image-report.json"
    report, _ = handoff_json(report_host)
    source_sha256 = report.get("raw_disk_sha256")
    source_bytes = report.get("raw_disk_bytes")
    if (report.get("status") != "candidate-outer-image-built-unapproved"
            or report.get("source_commit") != args.revision
            or report.get("image_built") is not True
            or report.get("signed_uki_checked") is not True
            or report.get("verity_userspace_verified") is not True
            or report.get("gpt_roothash_matched") is not True
            or report.get("private_mode_approved") is not False
            or type(source_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
            or type(source_bytes) is not int or source_bytes <= 0
            or type(report.get("native_rust_manifest_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", report["native_rust_manifest_sha256"])
            or type(report.get("candidate_manifest_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", report["candidate_manifest_sha256"])):
        raise ValueError("verified mkosi report is required before import reinspection")
    import_guest = SCRATCH_IN_GUEST / "import-disk"
    import_host = args.scratch / "import-disk"
    if import_host.exists() or import_host.is_symlink():
        raise ValueError("import reinspection output must be fresh")
    run_in_builder(staged, [
        "/usr/bin/python3", "-I", "-B",
        "/workspace/tools/gcp-guest/outer_image_runner.py", "reinspect-import",
        "--inputs", str(SCRATCH_IN_GUEST / "inputs"),
        "--zebra-receipt", str(SCRATCH_IN_GUEST / "zebra-provenance.json"),
        "--rust-bundle", str(SCRATCH_IN_GUEST / "rust-bundle"),
        "--stage", str(SCRATCH_IN_GUEST / "candidate-stage"),
        "--metadata", str(SCRATCH_IN_GUEST / "metadata"),
        "--builder-archives", str(SCRATCH_IN_GUEST / "builder-archives"),
        "--workspace", str(SCRATCH_IN_GUEST),
        "--import-directory", str(import_guest),
        "--sfdisk", "/usr/sbin/sfdisk",
        "--mkosi-disk-sha256", source_sha256,
        "--mkosi-disk-bytes", str(source_bytes),
        "--native-rust-manifest-sha256", report["native_rust_manifest_sha256"],
        "--revision", args.revision,
        "--parent-network-namespace", args.net,
        "--parent-mount-namespace", args.mnt,
    ])
    finished, reinspection_sha256 = handoff_json(import_host / "reinspection.json")
    raw_sha256 = finished.get("raw_disk_sha256")
    raw_bytes = finished.get("raw_disk_bytes")
    reports = finished.get("reports")
    expected_reports = {"sizing", "gpt", "esp", "verity", "roothash",
                        "rootfs", "uki-digest"}
    if (finished.get("status") != "diagnostic-import-disk-reinspected-unapproved"
            or finished.get("source_commit") != args.revision
            or finished.get("stage_manifest_sha256") != report["candidate_manifest_sha256"]
            or finished.get("input_lock_sha256") != report.get("input_lock_sha256")
            or finished.get("native_rust_manifest_sha256") !=
               report["native_rust_manifest_sha256"]
            or finished.get("mkosi_disk_sha256") != source_sha256
            or finished.get("mkosi_disk_bytes") != source_bytes
            or type(raw_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", raw_sha256)
            or type(raw_bytes) is not int or raw_bytes <= 0
            or raw_bytes % (1024 ** 3) != 0
            or type(finished.get("sfdisk_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", finished["sfdisk_sha256"])
            or type(finished.get("sfdisk_package_archive_sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", finished["sfdisk_package_archive_sha256"])
            or finished.get("sfdisk_archive_membership_rechecked") is not False
            or finished.get("sfdisk_dynamic_runtime_authenticated") is not False
            or finished.get("disk_raw") != str(import_guest / "disk.raw")
            or type(reports) is not dict or set(reports) != expected_reports
            or finished.get("package_diagnostics") != {
                "esp_diagnostic": reports["esp"],
                "uki_digest_diagnostic": reports["uki-digest"],
                "verity_diagnostic": reports["verity"]}
            or finished.get("import_archive_created") is not False
            or finished.get("import_package_ready") is not False
            or finished.get("boot_verified") is not False
            or finished.get("private_mode_approved") is not False):
        raise ValueError("postbuild import receipt differs from verified mkosi output")
    expected_statuses = {
        "sizing": "diagnostic-import-sized-gpt-unapproved",
        "gpt": "diagnostic-gpt-only-unapproved",
        "esp": "diagnostic-esp-uki-sections-unapproved",
        "verity": "diagnostic-raw-root-verity-unapproved",
        "roothash": "diagnostic-uki-roothash-gpt-match-unapproved",
        "rootfs": "diagnostic-raw-root-overlay-bytes-matched-unapproved",
        "uki-digest": "diagnostic-uki-pe-coff-sha384-unapproved",
    }
    host_reports = {}
    observed = {}
    for name in sorted(expected_reports):
        artifact = reports[name]
        guest_path = import_guest / (name + ".json")
        host_path = import_host / (name + ".json")
        if (type(artifact) is not dict or set(artifact) != {"path", "sha256"}
                or artifact["path"] != str(guest_path)
                or type(artifact["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])):
            raise ValueError("import inspector artifact path or identity differs")
        observed[name], _ = handoff_json(host_path, artifact["sha256"])
        if (observed[name].get("status") != expected_statuses[name]
                or observed[name].get("private_mode_approved") is not False):
            raise ValueError("import inspector report status cannot approve private mode")
        host_reports[name] = {"path": str(host_path), "sha256": artifact["sha256"]}
    for name in ("gpt", "esp", "verity", "roothash", "rootfs"):
        if (observed[name].get("raw_disk_sha256") != raw_sha256
                or observed[name].get("raw_disk_bytes") != raw_bytes):
            raise ValueError("import inspector report differs from final disk identity")
    if (observed["sizing"].get("mkosi_disk_sha256") != source_sha256
            or observed["sizing"].get("mkosi_disk_bytes") != source_bytes
            or observed["sizing"].get("raw_disk_sha256") != raw_sha256
            or observed["sizing"].get("raw_disk_bytes") != raw_bytes
            or observed["sizing"].get("sfdisk_sha256") != finished["sfdisk_sha256"]
            or observed["uki-digest"].get("uki_sha256") !=
               observed["esp"].get("uki_sha256")):
        raise ValueError("import sizing or UKI report differs from final disk identity")
    handoff = {
        "schema_version": 1,
        "status": "diagnostic-operator-import-handoff-unapproved",
        "source_commit": args.revision,
        "stage_manifest_sha256": finished["stage_manifest_sha256"],
        "input_lock_sha256": finished["input_lock_sha256"],
        "native_rust_manifest_sha256": finished["native_rust_manifest_sha256"],
        "mkosi_disk_sha256": source_sha256,
        "mkosi_disk_bytes": source_bytes,
        "raw_disk_sha256": raw_sha256,
        "raw_disk_bytes": raw_bytes,
        "sfdisk_sha256": finished["sfdisk_sha256"],
        "sfdisk_package_archive_sha256": finished["sfdisk_package_archive_sha256"],
        "sfdisk_archive_membership_rechecked": False,
        "sfdisk_dynamic_runtime_authenticated": False,
        "disk_raw": str(import_host / "disk.raw"),
        "reinspection_receipt": {"path": str(import_host / "reinspection.json"),
                                 "sha256": reinspection_sha256},
        "review_reports": host_reports,
        "package_diagnostics": {
            "esp_diagnostic": host_reports["esp"],
            "uki_digest_diagnostic": host_reports["uki-digest"],
            "verity_diagnostic": host_reports["verity"]},
        "import_archive_created": False,
        "import_package_ready": False,
        "boot_verified": False,
        "private_mode_approved": False,
    }
    handoff_path = import_host / "operator-handoff.json"
    data = (json.dumps(handoff, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(handoff_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    checked, handoff_sha256 = handoff_json(handoff_path, hashlib.sha256(data).hexdigest())
    if checked != handoff:
        raise ValueError("operator import handoff changed after publication")
    checked_final_disk(import_host / "disk.raw", raw_sha256, raw_bytes)
    return {**handoff, "handoff_artifact": {"path": str(handoff_path),
                                            "sha256": handoff_sha256}}


def build(args, *, preflight_only=False):
    if preflight_only:
        input_files, input_dirs = (), PREFLIGHT_INPUT_DIRS
        overlay, apt = checked_layout(args.workspace, args.source, args.scratch,
                                      args.staged, input_files=input_files,
                                      input_dirs=input_dirs)
    else:
        input_files, input_dirs = INPUT_FILES, INPUT_DIRS
        overlay, apt = checked_layout(args.workspace, args.source, args.scratch, args.staged)
    checked_bound_mounts(args.source, args.scratch, args.staged)
    checked_bound_sockets(args.source, args.scratch, args.staged)
    checked_source(args.source, args.revision)
    checked_namespace(vars(args))
    checked_staged_builder(args.source, args.scratch, args.staged, args.revision)
    if not preflight_only:
        checked_signing_mount()
    if not overlay.exists():
        overlay.mkdir(mode=0o700)
    if not apt.exists():
        apt.mkdir(mode=0o700)
    tmp = apt / "tmp"
    tmp.mkdir(mode=0o700)
    if tmp.stat().st_uid != 0 or stat.S_IMODE(tmp.stat().st_mode) != 0o700:
        raise ValueError("APT scratch is not private mapped-root storage")
    checked_bound_mounts(args.source, args.scratch, args.staged)
    checked_bound_sockets(args.source, args.scratch, args.staged)
    staged = args.staged
    bind(staged, staged, readonly=False)
    for name in ("workspace", "zrpc-apt-scratch", "proc", "dev"):
        mountpoint_directory(staged / name)
    bind(args.source, staged / SOURCE_IN_GUEST.relative_to("/"), readonly=True)
    bind(args.scratch, staged / SCRATCH_IN_GUEST.relative_to("/"), readonly=False)
    bind(apt, staged / "zrpc-apt-scratch", readonly=False)
    for name in input_files + input_dirs:
        path = staged / SCRATCH_IN_GUEST.relative_to("/") / name
        bind(path, path, readonly=True)
    mount("-t", "proc", "proc", staged / "proc")
    for name in ("null", "zero", "full", "random", "urandom", "tty"):
        device = Path("/dev") / name
        target = staged / "dev" / name
        if not stat.S_ISCHR(device.stat().st_mode) or target.exists() or target.is_symlink():
            raise ValueError("builder device mountpoint differs")
        target.touch(mode=0o600)
        mount("--bind", device, target)
    preflight = '''import json,sys
from pathlib import Path
sys.path.insert(0,"/workspace/tools/gcp-guest")
import prepare_guest_disk_basetree_profile as disk
result=disk.verify_execution_context(Path("/workspace/.codex-tmp/metadata"),Path("/workspace/.codex-tmp/builder-archives"),sys.argv[1],Path("/zrpc-apt-scratch"),sys.argv[2],sys.argv[3])
if result["status"]!="diagnostic-signed-staged-builder-no-route" or result["private_mode_approved"] is not False: raise ValueError("signed builder preflight differs")
print(json.dumps(result,sort_keys=True))'''
    run_in_builder(staged, ["/usr/bin/python3", "-I", "-B", "-c", preflight,
                            args.net, args.user, args.pid])
    if preflight_only:
        return {"status": "diagnostic-production-harness-preflight-unapproved",
                "source_commit": args.revision,
                "signed_staged_builder_preflight_executed": True,
                "signing_key_checked": False, "mkosi_executed": False,
                "network_egress_excluded": False,
                "image_built": False, "private_mode_approved": False}
    signing_target = staged / "run" / "zrpc-build-signing"
    real_directory(signing_target.parent, "signed builder run directory")
    if signing_target.exists() or signing_target.is_symlink():
        raise ValueError("builder signing mountpoint already exists")
    signing_target.mkdir(mode=0o700)
    bind(SIGNING_MOUNT, signing_target, readonly=True)
    mount("-o", "remount,bind,ro", staged)
    for path, readonly in ((staged, True), (staged / "workspace", True),
                           (staged / SCRATCH_IN_GUEST.relative_to("/"), False),
                           (signing_target, True)):
        if bool(os.statvfs(path).f_flag & os.ST_RDONLY) != readonly:
            raise ValueError("final builder mount write policy differs")
    run_in_builder(staged, ["/usr/bin/python3", "-I", "-B",
                            "/workspace/tools/gcp-guest/outer_image_runner.py", "build",
                            "--lock", str(SCRATCH_IN_GUEST / "inputs.lock.json"),
                            "--inputs", str(SCRATCH_IN_GUEST / "inputs"),
                            "--zebra-receipt", str(SCRATCH_IN_GUEST / "zebra-provenance.json"),
                            "--rust-bundle", str(SCRATCH_IN_GUEST / "rust-bundle"),
                            "--stage", str(SCRATCH_IN_GUEST / "candidate-stage"),
                            "--metadata", str(SCRATCH_IN_GUEST / "metadata"),
                            "--builder-archives", str(SCRATCH_IN_GUEST / "builder-archives"),
                            "--workspace", str(SCRATCH_IN_GUEST),
                            "--report-path", str(SCRATCH_IN_GUEST / "outer-image-report.json"),
                            "--revision", args.revision,
                            "--parent-network-namespace", args.net,
                            "--parent-mount-namespace", args.mnt])
    return postbuild_import(staged, args)


def main(argv=None):
    if not sys.flags.isolated:
        print(json.dumps({"status": "blocked", "reason": "run with Python -I",
                          "image_built": False, "private_mode_approved": False}))
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("workspace", "source", "scratch", "staged"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--revision", required=True)
    for name in ("user", "mnt", "net", "pid"):
        parser.add_argument("--parent-" + name + "-namespace", dest=name, required=True)
    parser.add_argument("--preflight-only", action="store_true",
                        help="diagnostic signed-builder handoff; no signing key or image build")
    args = parser.parse_args(argv)
    try:
        if args.preflight_only:
            print(json.dumps(build(args, preflight_only=True), sort_keys=True))
        else:
            print(json.dumps(build(args), sort_keys=True))
    except (OSError, ValueError, lzma.LZMAError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
