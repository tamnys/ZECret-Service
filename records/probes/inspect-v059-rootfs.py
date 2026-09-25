"""Offline evidence collection for the exact public dstack v0.5.9 archive.

Uses operator-supplied, independently verified native veritysetup/unsquashfs.
No downloads, mounts, guest execution, deployment, or private-mode approval.
Run only through the managed container. Output must be a new workspace directory.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile


ARCHIVE_SHA256 = "f3888f64e215bc1e1af53a1f3d13b4df48fe40d4a3059049bb87d4c7c06aff97"
CATALOG_DIGEST = "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
META_COMMIT = "e3655d1390feee3736476f4bda35c4354b4a12fc"
DSTACK_COMMIT = "282eeb27d22d8f091ad0fa5a90e638f85cf68751"
ROOT_HASH = "a2d0a2af747ac763d56745f81d6aba93c04112076a6c502a3a5e2b45dd8b7c96"
HASH_OFFSET = 156594176
COMPONENTS = ("ovmf.fd", "bzImage", "initramfs.cpio.gz", "metadata.json")
ROOTFS = "rootfs.img.verity"
ARCHIVE_PREFIX = "dstack-0.5.9/"

# File hashes from the immutable source commits, not attestation measurements.
# Paths are resolved through the image's own symlinks without following host paths.
SOURCE_FILES = {
    "usr/bin/dstack-prepare.sh": (
        "dstack", "basefiles/dstack-prepare.sh",
        "1636030add2dfd5a85272a246939d7d1b472aa2a400e76b158dc39577a9c442a"),
    "usr/lib/systemd/system/dstack-prepare.service": (
        "dstack", "basefiles/dstack-prepare.service",
        "50d727f02033e2d05638f93771e016e88e1c445abaaf29eca6cc160087bd44f2"),
    "usr/lib/systemd/system/dstack-guest-agent.service": (
        "dstack", "basefiles/dstack-guest-agent.service",
        "240b699c476b6adb3a3388801a6b340e1ed505505d528dfb4e6b711b52146b25"),
    "usr/lib/systemd/system/app-compose.service": (
        "dstack", "basefiles/app-compose.service",
        "68898fd5221ef132db072f2943163d0dbb00dc5cbd12b3aeb06a43e227138cad"),
    "etc/systemd/system/docker.service.d/dstack-prepare.conf": (
        "dstack", "basefiles/docker.service.d/dstack-prepare.conf",
        "4ccb304b76e83528bd28449012627feef81ff4f69364574ad09f6265bab07523"),
    "etc/systemd/system/containerd.service.d/dstack-prepare.conf": (
        "dstack", "basefiles/containerd.service.d/dstack-prepare.conf",
        "4ccb304b76e83528bd28449012627feef81ff4f69364574ad09f6265bab07523"),
    "usr/lib/systemd/system/sysbox.service": (
        "meta-dstack", "meta-dstack/recipes-core/dstack-sysbox/files/sysbox.service",
        "dc77d49b191921175a610d9bebae642d0f41fd60016901d46d1d335511a15652"),
    "usr/lib/systemd/system/sysbox-mgr.service": (
        "meta-dstack", "meta-dstack/recipes-core/dstack-sysbox/files/sysbox-mgr.service",
        "6cace5cf44709bd9f78f88eb467f0d92a98675a3dc30191ea1dbdbba54dfe157"),
    "usr/lib/systemd/system/sysbox-fs.service": (
        "meta-dstack", "meta-dstack/recipes-core/dstack-sysbox/files/sysbox-fs.service",
        "145099f20f972acbc0114e9e1aaa4a3363b68cddaddf9a1de6852172bf8a6ca7"),
    "etc/docker/daemon.json": (
        "meta-dstack", "meta-dstack/recipes-core/images/files/docker-daemon.json",
        "55ad47fb2016b3382c73aa2b183f0428dbf3603031552aa3b0687abaece6aec2"),
}

UNIT_PREFIXES = ("etc/systemd/system/", "usr/lib/systemd/system/", "lib/systemd/system/")
ADMIN_NAMES = {
    "sshd", "dropbear", "getty", "agetty", "login", "loginctl", "sulogin",
    "systemd-sulogin-shell", "systemd-getty-generator", "systemd-debug-generator",
    "systemd-tty-ask-password-agent", "systemd-logind", "sshd_config",
}
ADMIN_UNIT = re.compile(r"^(ssh|sshd|dropbear|.*getty|autovt|debug-shell|rescue|emergency|systemd-logind)([.@-]|$)")
CONFIG_PATHS = (
    "etc/fstab", "etc/docker/daemon.json", "etc/containerd/config.toml",
    "etc/zfs/zpool.cache", "etc/securetty", "etc/ssh/sshd_config",
    "usr/bin/app-compose.sh", "usr/bin/wg-checker.sh",
)
DIRECTIVES = {
    "After", "Before", "Requires", "Wants", "BindsTo", "PartOf", "Conflicts",
    "OnFailure", "FailureAction", "DefaultDependencies", "ConditionPathExists",
    "ConditionKernelCommandLine", "ExecCondition", "ExecStartPre", "ExecStart",
    "ExecStartPost", "ExecStop", "ExecStopPost", "EnvironmentFile", "WorkingDirectory",
    "Restart", "KillMode", "Type", "RemainAfterExit", "SuccessExitStatus", "User",
    "Group", "WantedBy", "RequiredBy", "ListenStream", "ListenDatagram",
    "ListenSequentialPacket", "Accept", "SocketMode", "SocketUser", "SocketGroup",
    "What", "Where", "Options",
}


class ProbeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def file_sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_url(repository, path):
    commit = DSTACK_COMMIT if repository == "dstack" else META_COMMIT
    return f"https://github.com/Dstack-TEE/{repository}/blob/{commit}/{path}"


def parse_listing(raw):
    """Read maintained unsquashfs -lls output; never extract image pathnames."""
    entries = {}
    for line in raw.decode("utf-8").splitlines():
        marker = " squashfs-root/"
        if marker not in line:
            continue
        require(re.match(r"^[bcdlps-][rwxStTs-]{9}\s", line) is not None,
                "unrecognized squashfs listing record")
        name = line.split(marker, 1)[1]
        target = None
        if line[0] == "l":
            require(" -> " in name, "symlink target missing from listing")
            name, target = name.split(" -> ", 1)
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and str(path) == name,
                "noncanonical image pathname")
        require(name not in entries, "duplicate image pathname")
        entries[name] = {"kind": line[0], "mode": line[:10]}
        if target is not None:
            entries[name]["target"] = target
    require(entries, "empty squashfs listing")
    return entries


def normalize_guest_path(parts):
    result = []
    for part in parts:
        if part in ("", ".", "/"):
            continue
        if part == "..":
            require(result, "image symlink escapes guest root")
            result.pop()
        else:
            result.append(part)
    return result


def resolve_guest_path(name, entries):
    parts = normalize_guest_path(PurePosixPath(name).parts)
    followed = set()
    while True:
        for index in range(len(parts)):
            prefix = "/".join(parts[:index + 1])
            entry = entries.get(prefix)
            if entry is None:
                return None
            if entry["kind"] == "l":
                require(prefix not in followed, "cyclic image symlink")
                followed.add(prefix)
                target = PurePosixPath(entry["target"])
                parent = [] if target.is_absolute() else parts[:index]
                parts = normalize_guest_path(parent + list(target.parts) + parts[index + 1:])
                break
        else:
            return "/".join(parts)


def unit_directives(data):
    """Expose selected literal directives, not a claim of systemd graph execution."""
    result = {}
    section = ""
    pending = ""
    for line in data.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        pending += stripped
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        line, pending = pending, ""
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif "=" in line:
            key, value = line.split("=", 1)
            if key in DIRECTIVES:
                result.setdefault(f"{section}.{key}", []).append(value)
    require(not pending, "unfinished unit continuation")
    return result


def run_probe(args, report):
    workspace = Path(__file__).resolve().parents[2]
    output = args.output.absolute()
    require(not output.exists() and not output.is_symlink(), "output directory already exists")
    parent = output.parent.resolve(strict=True)
    require(parent.is_relative_to(workspace), "output must be inside this workspace")
    output = parent / output.name
    tools = {}
    for name, supplied in (("veritysetup", args.veritysetup), ("unsquashfs", args.unsquashfs)):
        require(supplied.is_absolute(), "tool paths must be absolute")
        resolved = supplied.resolve(strict=True)
        require(stat.S_ISREG(resolved.stat().st_mode) and os.access(resolved, os.X_OK),
                "tool must be a regular executable")
        tools[name] = resolved
    report["tools"] = {name: {"binary_sha256": file_sha256(path)} for name, path in tools.items()}
    report["tool_provenance"] = "operator must independently verify tool packages and libraries"

    # Keep one archive descriptor throughout hashing and selective member reads.
    report["stage"] = "archive_identity"
    with args.archive.open("rb") as archive_stream:
        digest = hashlib.file_digest(archive_stream, "sha256").hexdigest()
        require(digest == ARCHIVE_SHA256, "archive checksum mismatch")
        report["archive_sha256"] = digest
        archive_stream.seek(0)
        with tarfile.open(fileobj=archive_stream, mode="r:gz") as archive:
            members = archive.getmembers()
            expected = set(COMPONENTS) | {"sha256sum.txt", "digest.txt", ROOTFS}
            regular = {}
            for member in members:
                if member.isdir() and member.name.rstrip("/") == ARCHIVE_PREFIX.rstrip("/"):
                    continue
                require(member.name.startswith(ARCHIVE_PREFIX), "unexpected archive member")
                name = member.name[len(ARCHIVE_PREFIX):]
                require(name in expected and member.isfile() and name not in regular,
                        "unexpected, duplicate or non-regular archive member")
                regular[name] = member
            require(set(regular) == expected, "archive member set mismatch")

            def read_member(name):
                stream = archive.extractfile(regular[name])
                require(stream is not None, "archive member cannot be read")
                return stream

            component_hashes = {}
            for name in COMPONENTS:
                with read_member(name) as stream:
                    component_hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
            manifest = "".join(f"{component_hashes[name]}  {name}\n" for name in COMPONENTS).encode("ascii")
            with read_member("sha256sum.txt") as stream:
                require(stream.read() == manifest, "component manifest mismatch")
            catalog_digest = hashlib.sha256(manifest).hexdigest()
            require(catalog_digest == CATALOG_DIGEST, "catalog digest mismatch")
            with read_member("digest.txt") as stream:
                require(stream.read() == (catalog_digest + "\n").encode("ascii"), "archived digest mismatch")
            with read_member("metadata.json") as stream:
                metadata = json.load(stream)
            expected_metadata = {
                "version": "0.5.9", "git_revision": META_COMMIT, "bios": "ovmf.fd",
                "kernel": "bzImage", "initrd": "initramfs.cpio.gz", "rootfs": ROOTFS,
            }
            require(all(metadata.get(key) == value for key, value in expected_metadata.items()),
                    "metadata identity mismatch")
            require(metadata.get("is_dev") is False and metadata.get("shared_ro") is True,
                    "metadata mode mismatch")
            cmdline = metadata.get("cmdline")
            require(isinstance(cmdline, str), "kernel command line missing")
            commitments = [token for token in cmdline.split() if token.startswith("dstack.rootfs_")]
            require(commitments == [f"dstack.rootfs_hash={ROOT_HASH}", f"dstack.rootfs_size={HASH_OFFSET}"],
                    "rootfs commitments mismatch")
            report.update({"catalog_digest": catalog_digest, "component_sha256": component_hashes,
                           "metadata": metadata, "archive_identity_verified": True})

            # No tar extraction API: only one fixed, verified regular member is copied.
            report["stage"] = "selective_extraction"
            output.mkdir(mode=0o700)
            report["output_created"] = True
            image = output / ROOTFS
            with read_member(ROOTFS) as source, image.open("xb") as destination:
                shutil.copyfileobj(source, destination)
            require(image.stat().st_size == regular[ROOTFS].size, "rootfs extraction size mismatch")
    report["rootfs_file_sha256"] = file_sha256(image)

    # Explicit native tools only; discard ambient preload/startup settings. A local
    # library path supports independently verified, extracted Debian packages.
    environment = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}
    if "LD_LIBRARY_PATH" in os.environ:
        environment["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]

    def invoke(name, arguments):
        result = subprocess.run([str(tools[name]), *arguments], cwd=output,
                                env=environment, capture_output=True, check=False)
        report["last_tool_exit"] = {"tool": name, "exit_code": result.returncode}
        require(result.returncode == 0, f"{name} returned nonzero status")
        return result.stdout

    report["stage"] = "dm_verity"
    dump = invoke("veritysetup", ["dump", ROOTFS, f"--hash-offset={HASH_OFFSET}"])
    # Report only public parameter values, not the tool's absolute device pathname.
    dump_fields = {}
    for line in dump.decode("utf-8").splitlines():
        if ":" in line:
            key, value = (part.strip() for part in line.split(":", 1))
            if key in {"UUID", "Hash type", "Data blocks", "Data block size", "Hash blocks",
                       "Hash block size", "Hash algorithm", "Salt", "Hash device size"}:
                dump_fields[key] = value
    report["verity_parameters"] = dump_fields
    invoke("veritysetup", ["verify", ROOTFS, ROOTFS, ROOT_HASH, f"--hash-offset={HASH_OFFSET}"])
    report["dm_verity_verified"] = True

    report["stage"] = "squashfs_inspection"
    entries = parse_listing(invoke("unsquashfs", ["-lls", ROOTFS]))
    report["image_entry_count"] = len(entries)
    cache = {}

    def read_image_file(name):
        resolved = resolve_guest_path(name, entries)
        if resolved is None or entries[resolved]["kind"] != "-":
            return None
        if resolved not in cache:
            cache[resolved] = invoke("unsquashfs", ["-cat", ROOTFS, resolved])
        return cache[resolved]

    comparisons = []
    for path, (repository, source_path, expected_hash) in SOURCE_FILES.items():
        data = read_image_file(path)
        actual_hash = None if data is None else hashlib.sha256(data).hexdigest()
        comparisons.append({"path": path, "resolved_path": resolve_guest_path(path, entries),
                            "source": source_url(repository, source_path),
                            "expected_sha256": expected_hash, "actual_sha256": actual_hash,
                            "matches": actual_hash == expected_hash})
    report["source_comparisons"] = comparisons
    report["source_comparisons_passed"] = all(item["matches"] for item in comparisons)

    unit_inventory = []
    for path, entry in sorted(entries.items()):
        if not path.startswith(UNIT_PREFIXES):
            continue
        item = {"path": path, **entry}
        if entry["kind"] == "-":
            data = read_image_file(path)
            item["sha256"] = hashlib.sha256(data).hexdigest()
            item["directives"] = unit_directives(data)
        unit_inventory.append(item)
    report["unit_inventory"] = unit_inventory
    report["administrative_path_observations"] = [
        {"path": path, **entry} for path, entry in sorted(entries.items())
        if PurePosixPath(path).name in ADMIN_NAMES
        or (path.startswith(UNIT_PREFIXES) and ADMIN_UNIT.match(PurePosixPath(path).name))
    ]
    report["generator_paths"] = [
        {"path": path, **entry} for path, entry in sorted(entries.items())
        if "/system-generators/" in path or "/user-generators/" in path
    ]
    report["configuration_paths"] = []
    for path in CONFIG_PATHS:
        data = read_image_file(path)
        report["configuration_paths"].append({"path": path,
            "resolved_path": resolve_guest_path(path, entries),
            "regular_file_read": data is not None,
            "sha256": None if data is None else hashlib.sha256(data).hexdigest()})
    report["tmpfiles_paths"] = [
        {"path": path, **entry} for path, entry in sorted(entries.items()) if "/tmpfiles.d/" in path
    ]

    # Never emit password/hash fields from the public guest account databases.
    passwd = read_image_file("etc/passwd")
    shadow = read_image_file("etc/shadow")
    uid_zero = []
    if passwd is not None:
        for line in passwd.decode("utf-8").splitlines():
            fields = line.split(":")
            require(len(fields) == 7, "unrecognized passwd record")
            if fields[2] == "0":
                uid_zero.append({"name": fields[0], "shell": fields[6]})
    root_password_state = "shadow_or_root_entry_missing"
    if shadow is not None:
        for line in shadow.decode("utf-8").splitlines():
            fields = line.split(":")
            require(len(fields) >= 2, "unrecognized shadow record")
            if fields[0] == "root":
                root_password_state = ("empty" if fields[1] == "" else
                                       "locked" if fields[1].startswith(("!", "*")) else
                                       "password_field_present")
    report["account_observations"] = {"uid_zero_accounts": uid_zero,
                                      "root_password_field_state": root_password_state}
    require(report["source_comparisons_passed"], "one or more pinned source comparisons failed")
    report["stage"] = "complete"
    report["status"] = "offline_evidence_collected"
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--veritysetup", type=Path, required=True)
    parser.add_argument("--unsquashfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "dstack-v0.5.9-rootfs-evidence-v1", "status": "failed",
              "stage": "input_validation", "archive_identity_verified": False,
              "dm_verity_verified": False, "source_comparisons_passed": False,
              "guest_executed": False, "guest_admin_absence_demonstrated": False,
              "runtime_guard_demonstrated": False, "build_reproduced": False,
              "live_attestation_verified": False, "private_accepted": False}
    exit_code = 0
    try:
        run_probe(args, report)
    except ProbeError as error:
        report["error"] = str(error)
        exit_code = 1
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError, UnicodeError) as error:
        # Avoid exposing operator filesystem paths or raw tool diagnostics.
        report["error"] = type(error).__name__
        exit_code = 1
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if report.get("output_created"):
        try:
            with (args.output / "report.json").open("x", encoding="utf-8") as stream:
                stream.write(serialized)
        except OSError:
            report["status"] = "failed"
            report["error"] = "cannot write evidence report"
            serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
            exit_code = 1
    print(serialized, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
