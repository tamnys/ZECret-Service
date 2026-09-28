#!/usr/bin/env python3
"""Local, no-route handoff to the source-bound GCP outer image runner.

Run under probe_builder_owner_map on a native x86_64 builder. The selected
source, staged signed builder, and scratch must be separate siblings on the
workspace volume. This does not fetch inputs, create keys, deploy, or approve
an image. The caller supplies the independently reviewed inputs and an
already-mounted, private tmpfs signing key.
Only loopback IP state is checked; host AF_UNIX paths or nested mounts in
scratch are not excluded by this diagnostic handoff.
"""

import argparse
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
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
       "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}


def real_directory(path, label):
    if not path.is_absolute() or path.is_symlink() or not path.is_dir() or \
            path.resolve(strict=True) != path:
        raise ValueError(f"{label} must be one real absolute directory")
    return path


def checked_layout(workspace, source, scratch, staged):
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
    for name in INPUT_FILES:
        path = scratch / name
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
            raise ValueError(f"missing real image input: {name}")
    for name in INPUT_DIRS:
        real_directory(scratch / name, f"image input {name}")
    apt = scratch / "apt-scratch"
    if apt.exists() or apt.is_symlink():
        real_directory(apt, "APT scratch")
        if os.listdir(apt):
            raise ValueError("APT scratch must be fresh")
    return overlay, apt


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
    if not os.path.ismount(target) or bool(os.statvfs(target).f_flag & os.ST_RDONLY) != readonly:
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


def build(args):
    overlay, apt = checked_layout(args.workspace, args.source, args.scratch, args.staged)
    checked_source(args.source, args.revision)
    checked_namespace(vars(args))
    checked_staged_builder(args.source, args.scratch, args.staged, args.revision)
    checked_signing_mount()
    if not overlay.exists():
        overlay.mkdir(mode=0o700)
    if not apt.exists():
        apt.mkdir(mode=0o700)
    tmp = apt / "tmp"
    tmp.mkdir(mode=0o700)
    if tmp.stat().st_uid != 0 or stat.S_IMODE(tmp.stat().st_mode) != 0o700:
        raise ValueError("APT scratch is not private mapped-root storage")
    staged = args.staged
    bind(staged, staged, readonly=False)
    for name in ("workspace", "zrpc-apt-scratch", "proc", "dev"):
        mountpoint_directory(staged / name)
    bind(args.source, staged / SOURCE_IN_GUEST.relative_to("/"), readonly=True)
    bind(args.scratch, staged / SCRATCH_IN_GUEST.relative_to("/"), readonly=False)
    bind(apt, staged / "zrpc-apt-scratch", readonly=False)
    for name in INPUT_FILES + INPUT_DIRS:
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
                            "--revision", args.revision,
                            "--parent-network-namespace", args.net,
                            "--parent-mount-namespace", args.mnt])


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
    args = parser.parse_args(argv)
    try:
        build(args)
    except (OSError, ValueError, lzma.LZMAError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error),
                          "image_built": False, "private_mode_approved": False}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
