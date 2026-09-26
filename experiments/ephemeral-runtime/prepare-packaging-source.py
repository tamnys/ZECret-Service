#!/usr/bin/env python3
"""Generate a source-only packaging overlay from pinned dstack/meta-dstack.

The supplied binaries are checked by explicit SHA-256 and x86_64 ELF header.
Neither check establishes their provenance or behavior. This script does not
run BitBake, build a rootfs, publish an image, or approve private mode.
"""

import argparse
import hashlib
import importlib.util
from io import BytesIO
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys


META_COMMIT = "e3655d1390feee3736476f4bda35c4354b4a12fc"
DSTACK_COMMIT = "282eeb27d22d8f091ad0fa5a90e638f85cf68751"
GUEST_RECIPE = Path("meta-dstack/recipes-core/dstack-guest/dstack-guest.bb")
SYSBOX_RECIPE = Path("meta-dstack/recipes-core/dstack-sysbox/dstack-sysbox_0.6.7.bb")
BASE_RECIPE = Path("meta-dstack/recipes-core/images/dstack-rootfs-base.inc")
PROD_RECIPE = Path("meta-dstack/recipes-core/images/dstack-rootfs-prod.inc")
META_HASHES = {
    GUEST_RECIPE: "427f31f5eae20d02ea20f4975d19954aae2d77cd8bcaa5071480530260180676",
    SYSBOX_RECIPE: "5aac22e115e8e4c653545c07d194ab33b31e44cd993936353f562b6717b59edf",
    BASE_RECIPE: "9a807b6f47b2a7f18e213d5892f7f410dccc6a41a23a63e7cbf7492c4183fb72",
    PROD_RECIPE: "b9ba45c2988c7370f5b715c411da6f8d709c42ff19207e1f843456f2f9f65161",
}
GUARD_NAME = "phala-runtime-guard"
BRIDGE_NAME = "zrpc-quote-proxy"
SERVICE_NAME = "zrpc-quote-proxy.service"
STAGED_ROOT = "staged-source"
SOURCE_FILE_LIST = "zrpc-dstack-files.txt"
SOURCE_CHECKSUMS = "zrpc-dstack.sha256"
SOURCE_MODES = "zrpc-dstack-modes.txt"


class Refusal(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def import_companion(filename: str):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"),
                                                  Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise Refusal("pinned guest recipe anchor missing or ambiguous")
    return source.replace(old, new)


def pinned_meta(meta_repo: Path) -> dict[Path, str]:
    head = subprocess.run(["git", "--no-replace-objects", "-C", str(meta_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
    if head.returncode != 0 or head.stdout.strip() != META_COMMIT:
        raise Refusal("meta-dstack checkout is not at the pinned commit")
    gitlink = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(meta_repo), "ls-tree", META_COMMIT, "dstack"],
        capture_output=True, text=True, check=False)
    if gitlink.returncode != 0 or gitlink.stdout.strip() != (
            f"160000 commit {DSTACK_COMMIT}\tdstack"):
        raise Refusal("pinned meta-dstack dstack gitlink changed")
    originals = {}
    for source_path, expected in META_HASHES.items():
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(meta_repo),
             "show", f"{META_COMMIT}:{source_path}"],
            capture_output=True, check=False)
        if result.returncode != 0 or digest(result.stdout) != expected:
            raise Refusal(f"pinned meta-dstack object unavailable or changed: {source_path}")
        originals[source_path] = result.stdout.decode("utf-8")
    return originals


def verify_meta_contract(originals: dict[Path, str]) -> None:
    guest = originals[GUEST_RECIPE]
    sysbox = originals[SYSBOX_RECIPE]
    base = originals[BASE_RECIPE]
    if ("SRC_DIR = '${REPO_ROOT}/dstack'" not in guest
            or 'rsync -a --exclude="target" ${SRC_DIR}/ ${S}/' not in guest
            or 'install -m 0755 ${S}/basefiles/dstack-prepare.sh ${D}${bindir}' not in guest):
        raise Refusal("guest recipe no longer stages the pinned dstack source tree")
    for unit in ("sysbox", "sysbox-mgr", "sysbox-fs"):
        if (f"install -m 0644 ${{WORKDIR}}/{unit}.service "
                "${D}${systemd_system_unitdir}") not in sysbox:
            raise Refusal(f"separate Sysbox recipe no longer installs {unit}.service")
    if "dstack-guest" not in base or "dstack-sysbox" not in base:
        raise Refusal("production rootfs no longer includes both guest packages")
    if originals[PROD_RECIPE] != 'include dstack-rootfs-base.inc\nIMAGE_FEATURES += "nologin"\n':
        raise Refusal("production rootfs recipe changed")


def verify_binary(path: Path, expected_digest: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise Refusal("binary SHA-256 must be an explicit lowercase 64-hex digest")
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise Refusal("binary input must be a regular file, not a link")
        data = path.read_bytes()
    except OSError as error:
        raise Refusal("binary input cannot be read") from error
    if digest(data) != expected_digest:
        raise Refusal("binary SHA-256 mismatch")
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:7] != b"\x02\x01\x01":
        raise Refusal("binary input lacks a 64-bit little-endian ELF header")
    if struct.unpack_from("<H", data, 16)[0] not in (2, 3):
        raise Refusal("binary ELF type is not executable or shared-object")
    if struct.unpack_from("<H", data, 18)[0] != 62:
        raise Refusal("binary ELF machine is not x86_64")
    if struct.unpack_from("<I", data, 20)[0] != 1:
        raise Refusal("binary ELF version is unsupported")
    return data


def candidate_guest_recipe(source: str, runtime, list_digest: str,
                           checksums_digest: str, modes_digest: str) -> str:
    """Copy only the checked staged dstack tree and install its runtime files."""
    for value in (list_digest, checksums_digest, modes_digest):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise Refusal("staged source manifest digest is invalid")
    source = replace_once(
        source, "    mkdir -p ${S}\n",
        '    [ "${S}" = "${WORKDIR}/dstack" ] || exit 1\n'
        '    [ -d "${S}" ] && [ ! -L "${S}" ] || exit 1\n'
        '    stale_files=$(find "${S}" -mindepth 1 -print -quit) || exit 1\n'
        '    [ -z "$stale_files" ] || exit 1\n',
    )
    source = replace_once(source, 'do_unpack[nostamp] = "1"\n',
                          'do_unpack[cleandirs] = "${WORKDIR}/dstack"\n'
                          'do_unpack[nostamp] = "1"\n')
    source = replace_once(
        source,
        '    rsync -a --exclude="target" ${SRC_DIR}/ ${S}/\n',
        '    [ -d "${SRC_DIR}" ] && [ ! -L "${SRC_DIR}" ] || exit 1\n'
        '    source_links=$(find "${SRC_DIR}" -type l -print -quit) || exit 1\n'
        '    [ -z "$source_links" ] || exit 1\n'
        '    for manifest in ' + SOURCE_FILE_LIST + ' ' + SOURCE_CHECKSUMS
        + ' ' + SOURCE_MODES + '; do\n'
        '        [ -f "${REPO_ROOT}/$manifest" ] && '
        '[ ! -L "${REPO_ROOT}/$manifest" ] || exit 1\n'
        '    done\n'
        '    [ "$(sha256sum -- "${REPO_ROOT}/' + SOURCE_FILE_LIST
        + '" | awk \'{print $1}\')" = "' + list_digest + '" ] || exit 1\n'
        '    [ "$(sha256sum -- "${REPO_ROOT}/' + SOURCE_CHECKSUMS
        + '" | awk \'{print $1}\')" = "' + checksums_digest + '" ] || exit 1\n'
        '    [ "$(sha256sum -- "${REPO_ROOT}/' + SOURCE_MODES
        + '" | awk \'{print $1}\')" = "' + modes_digest + '" ] || exit 1\n'
        '    while IFS="$(printf \'\\t\')" read -r expected_mode relative_path; do\n'
        '        [ -n "$relative_path" ] || exit 1\n'
        '        mode_file="${SRC_DIR}/$relative_path"\n'
        '        [ -f "$mode_file" ] && [ ! -L "$mode_file" ] || exit 1\n'
        '        observed_mode=$(stat -c \'%a\' -- "$mode_file") || exit 1\n'
        '        [ "$observed_mode" = "$expected_mode" ] || exit 1\n'
        '    done < "${REPO_ROOT}/' + SOURCE_MODES + '"\n'
        '    rsync -a --files-from="${REPO_ROOT}/' + SOURCE_FILE_LIST
        + '" "${SRC_DIR}/" "${S}/" || exit 1\n'
        '    copied_links=$(find "${S}" -type l -print -quit) || exit 1\n'
        '    [ -z "$copied_links" ] || exit 1\n'
        '    while IFS="$(printf \'\\t\')" read -r expected_mode relative_path; do\n'
        '        [ -n "$relative_path" ] || exit 1\n'
        '        mode_file="${S}/$relative_path"\n'
        '        [ -f "$mode_file" ] && [ ! -L "$mode_file" ] || exit 1\n'
        '        observed_mode=$(stat -c \'%a\' -- "$mode_file") || exit 1\n'
        '        [ "$observed_mode" = "$expected_mode" ] || exit 1\n'
        '    done < "${REPO_ROOT}/' + SOURCE_MODES + '"\n'
        '    (cd "${S}" && sha256sum -c -- "${REPO_ROOT}/'
        + SOURCE_CHECKSUMS + '") || exit 1\n',
    )
    source = replace_once(source, "inherit systemd\n",
                          'inherit systemd useradd\n\n'
                          'USERADD_PACKAGES = "${PN}"\n'
                          'GROUPADD_PARAM:${PN} = "-r zrpc-wrapper"\n')
    source = replace_once(
        source,
        'DSTACK_SERVICES = "dstack-guest-agent.socket dstack-guest-agent.service '
        'dstack-prepare.service app-compose.service wg-checker.service"\n',
        'DSTACK_SERVICES = "dstack-guest-agent.socket dstack-guest-agent.service '
        'dstack-prepare.service app-compose.service wg-checker.service '
        'zrpc-quote-proxy.service"\n')
    source = replace_once(
        source,
        "    install -m 0755 ${CARGO_BINDIR}/dstack-guest-agent ${D}${bindir}\n",
        "    install -m 0755 ${CARGO_BINDIR}/dstack-guest-agent ${D}${bindir}\n"
        "    install -m 0755 ${S}/zrpc/phala-runtime-guard ${D}${bindir}/phala-runtime-guard\n"
        "    install -m 0755 ${S}/zrpc/zrpc-quote-proxy ${D}${bindir}/zrpc-quote-proxy\n")
    dropins = runtime.dropins()
    lines = [
        "        install -m 0644 ${S}/basefiles/zrpc-quote-proxy.service "
        "${D}${systemd_system_unitdir}/zrpc-quote-proxy.service",
    ]
    package_paths = [
        "${bindir}/phala-runtime-guard", "${bindir}/zrpc-quote-proxy",
        "${systemd_system_unitdir}/zrpc-quote-proxy.service",
    ]
    for source_path in sorted(dropins):
        target_path = "${sysconfdir}/systemd/system/" + str(source_path.relative_to("basefiles"))
        lines.extend((f"        install -d ${{D}}{target_path.rsplit('/', 1)[0]}",
                      f"        install -m 0644 ${{S}}/{source_path} ${{D}}{target_path}"))
        package_paths.append(target_path)
    source = replace_once(
        source,
        "        install -m 0644 ${S}/basefiles/dstack-guest-agent.socket "
        "${D}${systemd_system_unitdir}\n",
        "        install -m 0644 ${S}/basefiles/dstack-guest-agent.socket "
        "${D}${systemd_system_unitdir}\n" + "\n".join(lines) + "\n")
    source += '\nFILES:${PN} += " \\\n' + "".join(
        f"    {package_path} \\\n" for package_path in package_paths) + '"\n'
    return source


def verify_child_manifest(directory: Path, expected_paths: set[Path],
                          source_commit: str, unbuilt_field: str) -> dict:
    manifest_path = directory / "candidate-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    hashes = manifest.get("candidate_sha256")
    if (manifest.get("source_commit") != source_commit
            or manifest.get("source_commit_object_verified") is not True
            or manifest.get("source_tree_verified") is not False
            or manifest.get(unbuilt_field) is not False
            or manifest.get("private_accepted") is not False
            or not isinstance(hashes, dict)
            or set(map(Path, hashes)) != expected_paths):
        raise Refusal("child source overlay manifest is incomplete or accepting")
    for source_path in expected_paths:
        candidate = directory / source_path
        if not stat.S_ISREG(candidate.lstat().st_mode):
            raise Refusal(f"child source overlay is not a regular file: {source_path}")
        if digest(candidate.read_bytes()) != hashes[str(source_path)]:
            raise Refusal(f"child source overlay hash mismatch: {source_path}")
    return manifest


def run_generator(script: Path, arguments: list[str]) -> None:
    result = subprocess.run([sys.executable, str(script), *arguments],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise Refusal(f"{script.name} refused source candidate (exit {result.returncode})")


def output_path(argument: Path) -> Path:
    repo = Path(__file__).resolve().parents[2]
    if not argument.is_absolute() or ".." in argument.parts:
        raise Refusal("output must be an absolute new directory without parent traversal")
    parent = argument.parent.resolve(strict=True)
    output = parent / argument.name
    if not output.is_relative_to(repo) or output.exists() or output.is_symlink():
        raise Refusal("output must be a new directory inside this repository")
    return output


def verify_dstack_checkout(dstack_repo: Path) -> None:
    head = subprocess.run(["git", "--no-replace-objects", "-C", str(dstack_repo),
                           "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
    if head.returncode != 0 or head.stdout.strip() != DSTACK_COMMIT:
        raise Refusal("dstack checkout is not at the pinned meta-dstack gitlink")


def safe_source_path(raw: bytes) -> Path:
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal("Git tree contains a non-UTF-8 path") from error
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or name != path.as_posix()
            or any(part in (".", "..") for part in path.parts)
            or "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise Refusal("Git tree contains an unsafe source path")
    return Path(name)


def git_tree_entries(repo: Path, commit: str) -> tuple[str, dict[Path, tuple[str, str]]]:
    tree = subprocess.run(["git", "--no-replace-objects", "-C", str(repo),
                           "rev-parse", f"{commit}^{{tree}}"],
                          capture_output=True, text=True, check=False)
    if tree.returncode or not re.fullmatch(r"[0-9a-f]{40}", tree.stdout.strip()):
        raise Refusal("pinned source tree object unavailable")
    listing = subprocess.run(["git", "--no-replace-objects", "-C", str(repo),
                              "ls-tree", "-r", "-z", commit],
                             capture_output=True, check=False)
    if listing.returncode or not listing.stdout.endswith(b"\0"):
        raise Refusal("pinned source tree listing unavailable")
    entries = {}
    for row in listing.stdout[:-1].split(b"\0"):
        try:
            metadata, raw_path = row.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as error:
            raise Refusal("malformed pinned source tree entry") from error
        path = safe_source_path(raw_path)
        if (path in entries or mode not in ("100644", "100755", "120000", "160000")
                or kind != ("commit" if mode == "160000" else "blob")
                or not re.fullmatch(r"[0-9a-f]{40}", oid)):
            raise Refusal("unsupported pinned source tree entry")
        entries[path] = (mode, oid)
    if not entries:
        raise Refusal("pinned source tree is empty")
    return tree.stdout.strip(), entries


def git_blobs(repo: Path, entries: dict[Path, tuple[str, str]]) -> dict[str, bytes]:
    oids = list(dict.fromkeys(oid for mode, oid in entries.values() if mode != "160000"))
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(repo),
                             "cat-file", "--batch"],
                            input=("\n".join(oids) + "\n").encode("ascii"),
                            capture_output=True, check=False)
    if result.returncode:
        raise Refusal("pinned source blob unavailable")
    stream = BytesIO(result.stdout)
    blobs = {}
    for oid in oids:
        header = stream.readline().rstrip(b"\n")
        try:
            observed_oid, kind, size_text = header.decode("ascii").split(" ")
            size = int(size_text)
        except (ValueError, UnicodeDecodeError) as error:
            raise Refusal("malformed pinned source blob header") from error
        payload = stream.read(size)
        if (observed_oid != oid or kind != "blob" or size < 0
                or len(payload) != size or stream.read(1) != b"\n"
                or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + payload).hexdigest() != oid):
            raise Refusal("pinned source blob identity mismatch")
        blobs[oid] = payload
    if stream.read():
        raise Refusal("unexpected pinned source blob output")
    return blobs


def stage_git_tree(repo: Path, commit: str, target: Path) -> tuple[str, dict[Path, tuple[str, str]]]:
    head = subprocess.run(["git", "--no-replace-objects", "-C", str(repo),
                           "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
    if head.returncode or head.stdout.strip() != commit:
        raise Refusal("source checkout is not at the pinned commit")
    tree_oid, entries = git_tree_entries(repo, commit)
    blobs = git_blobs(repo, entries)
    target.mkdir(parents=True, exist_ok=False)
    links = []
    for path, (mode, oid) in entries.items():
        if mode == "160000":
            continue
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise Refusal("pinned source tree paths overlap")
        payload = blobs[oid]
        if mode == "120000":
            try:
                link = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise Refusal("pinned source symlink target is not UTF-8") from error
            joined = posixpath.normpath(posixpath.join(path.parent.as_posix(), link))
            if (not link or link.startswith("/") or "\\" in link
                    or any(ord(char) < 32 or ord(char) == 127 for char in link)
                    or joined == ".." or joined.startswith("../")
                    or Path(joined) not in entries):
                raise Refusal("pinned source symlink escapes or is unresolved")
            links.append((destination, link))
        else:
            destination.write_bytes(payload)
            destination.chmod(0o755 if mode == "100755" else 0o644)
    for destination, link in links:
        destination.symlink_to(link)
    return tree_oid, entries


def apply_overlay(overlay: Path, target: Path, paths: set[Path]) -> None:
    for path in sorted(paths):
        safe_source_path(str(path).encode("utf-8"))
        source = overlay / path
        destination = target / path
        if destination.is_symlink():
            raise Refusal("overlay destination is a symbolic link")
        destination.parent.mkdir(parents=True, exist_ok=True)
        old_mode = destination.stat().st_mode if destination.exists() else None
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o755 if old_mode is not None and old_mode & stat.S_IXUSR else 0o644)


def staged_file_inventory(root: Path) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
    files = {}
    links = {}
    for candidate in sorted(root.rglob("*")):
        relative = str(candidate.relative_to(root))
        mode = candidate.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            links[relative] = candidate.readlink().as_posix()
        elif stat.S_ISREG(mode):
            files[relative] = {
                "sha256": digest(candidate.read_bytes()),
                "mode": "100755" if mode & stat.S_IXUSR else "100644",
            }
        else:
            raise Refusal("staged source contains an unsupported file type")
    return files, links


def dstack_copy_manifests(staged_root: Path) -> tuple[str, str, str]:
    dstack = staged_root / "dstack"
    if dstack.is_symlink() or not dstack.is_dir():
        raise Refusal("staged dstack is not a regular directory")
    files, links = staged_file_inventory(dstack)
    if links:
        raise Refusal("staged dstack contains symbolic links")
    names = sorted(files)
    listing = "".join(name + "\n" for name in names).encode()
    checksums = "".join(f"{files[name]['sha256']}  {name}\n" for name in names).encode()
    modes = "".join(
        f"{format(stat.S_IMODE((dstack / name).stat().st_mode), 'o')}\t{name}\n"
        for name in names).encode()
    if any(stat.S_IMODE((dstack / name).stat().st_mode) not in (0o644, 0o755)
           for name in names):
        raise Refusal("staged dstack file mode is not a pinned regular-file mode")
    (staged_root / SOURCE_FILE_LIST).write_bytes(listing)
    (staged_root / SOURCE_CHECKSUMS).write_bytes(checksums)
    (staged_root / SOURCE_MODES).write_bytes(modes)
    return digest(listing), digest(checksums), digest(modes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dstack_source_git_dir", type=Path)
    parser.add_argument("meta_source_git_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--runtime-guard", type=Path, required=True)
    parser.add_argument("--runtime-guard-sha256", required=True)
    parser.add_argument("--quote-proxy", type=Path, required=True)
    parser.add_argument("--quote-proxy-sha256", required=True)
    parser.add_argument("--launch-config", type=Path)
    parser.add_argument("--sys-config", type=Path)
    args = parser.parse_args()
    try:
        originals = pinned_meta(args.meta_source_git_dir)
        verify_meta_contract(originals)
        verify_dstack_checkout(args.dstack_source_git_dir)
        guard = verify_binary(args.runtime_guard, args.runtime_guard_sha256)
        bridge = verify_binary(args.quote_proxy, args.quote_proxy_sha256)
        output = output_path(args.output_dir)
        runtime = import_companion("prepare-image-source.py")
        output.mkdir(mode=0o700)
        dstack_overlay = output / "dstack"
        meta_overlay = output / "meta"
        image_arguments = [str(args.dstack_source_git_dir), str(dstack_overlay)]
        if args.launch_config is not None:
            image_arguments += ["--launch-config", str(args.launch_config)]
        if args.sys_config is not None:
            image_arguments += ["--sys-config", str(args.sys_config)]
        run_generator(Path(__file__).with_name("prepare-image-source.py"), image_arguments)
        run_generator(Path(__file__).with_name("prepare-rootfs-source.py"),
                      [str(args.meta_source_git_dir), str(meta_overlay)])
        baseline = json.loads(Path(__file__).with_name(
            "candidate-manifest.json").read_text())
        guest_paths = {Path(name) for name in baseline["candidate_sha256"]}
        guest_manifest = verify_child_manifest(
            dstack_overlay, guest_paths, DSTACK_COMMIT, "built_image")
        rootfs_manifest = verify_child_manifest(
            meta_overlay, {PROD_RECIPE}, META_COMMIT, "rootfs_built")
        staged_root = output / STAGED_ROOT
        meta_tree_oid, meta_entries = stage_git_tree(
            args.meta_source_git_dir, META_COMMIT, staged_root)
        gitlinks = {str(path): oid for path, (mode, oid) in meta_entries.items()
                    if mode == "160000"}
        if gitlinks.get("dstack") != DSTACK_COMMIT:
            raise Refusal("staged meta-dstack gitlink is not the pinned dstack commit")
        dstack_tree_oid, dstack_entries = stage_git_tree(
            args.dstack_source_git_dir, DSTACK_COMMIT, staged_root / "dstack")
        if any(mode == "160000" for mode, _ in dstack_entries.values()):
            raise Refusal("pinned dstack source has unresolved gitlinks")
        apply_overlay(dstack_overlay, staged_root / "dstack", guest_paths)
        apply_overlay(meta_overlay, staged_root, {PROD_RECIPE})
        for name, payload in ((GUARD_NAME, guard), (BRIDGE_NAME, bridge)):
            for root in (dstack_overlay, staged_root / "dstack"):
                target = root / "zrpc" / name
                target.write_bytes(payload)
                target.chmod(0o755)
        list_digest, checksums_digest, modes_digest = dstack_copy_manifests(staged_root)
        recipe = candidate_guest_recipe(
            originals[GUEST_RECIPE], runtime, list_digest, checksums_digest,
            modes_digest)
        recipe_path = meta_overlay / GUEST_RECIPE
        recipe_path.parent.mkdir(parents=True, exist_ok=True)
        recipe_path.write_text(recipe)
        staged_recipe_path = staged_root / GUEST_RECIPE
        staged_recipe_path.write_text(recipe)
        staged_files, staged_links = staged_file_inventory(staged_root)
        files = {}
        links = {}
        for candidate in sorted(output.rglob("*")):
            mode = candidate.lstat().st_mode
            if stat.S_ISREG(mode):
                files[str(candidate.relative_to(output))] = digest(candidate.read_bytes())
            elif stat.S_ISLNK(mode):
                links[str(candidate.relative_to(output))] = candidate.readlink().as_posix()
            elif not stat.S_ISDIR(mode):
                raise Refusal("generated candidate contains an unsupported file type")
        (output / "packaging-manifest.json").write_text(json.dumps({
            "meta_source_commit": META_COMMIT,
            "dstack_source_commit": DSTACK_COMMIT,
            "meta_source_tree_oid": meta_tree_oid,
            "dstack_source_tree_oid": dstack_tree_oid,
            "meta_gitlinks": gitlinks,
            "materialized_meta_gitlinks": {"dstack": DSTACK_COMMIT},
            "unresolved_meta_gitlinks": {name: oid for name, oid in gitlinks.items()
                                         if name != "dstack"},
            "source_identity_scope": "pinned_meta_tracked_blobs_and_gitlinks_pinned_dstack_blobs_checked_overlays",
            "staged_source": STAGED_ROOT,
            "staged_tracked_blob_tree_verified": True,
            "bitbake_dependency_closure_verified": False,
            "staged_source_files": staged_files,
            "staged_source_symlinks": staged_links,
            "dstack_file_list_sha256": list_digest,
            "dstack_checksums_sha256": checksums_digest,
            "dstack_modes_sha256": modes_digest,
            "meta_source_sha256": {str(name): value for name, value in META_HASHES.items()},
            "runtime_guard_sha256": digest(guard),
            "quote_proxy_sha256": digest(bridge),
            "binary_check": "explicit_sha256_and_x86_64_elf_header_only",
            "binary_provenance_verified": False,
            "runtime_path_baseline_sha256": digest(
                Path(__file__).with_name("candidate-manifest.json").read_bytes()),
            "guest_launch_profile_bound": guest_manifest["launch_profile_bound"],
            "rootfs_recipe_source_verified": rootfs_manifest["source_commit_object_verified"],
            "output_sha256": files,
            "output_symlinks": links,
            "overlay_only": True,
            "bitbake_executed": False,
            "rootfs_built": False,
            "guest_boot_tested": False,
            "admin_absence_demonstrated": False,
            "phala_admission_verified": False,
            "private_accepted": False,
        }, indent=2, sort_keys=True) + "\n")
    except (Refusal, ValueError, OSError, KeyError) as error:
        parser.error(str(error))
    print("Source-only packaging overlay; no built image, boot or private acceptance.")


if __name__ == "__main__":
    main()
