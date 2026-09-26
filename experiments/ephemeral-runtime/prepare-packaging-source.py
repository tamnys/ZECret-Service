#!/usr/bin/env python3
"""Generate a source-only packaging overlay from pinned dstack/meta-dstack.

The supplied binaries are checked by explicit SHA-256 and x86_64 ELF header.
Neither check establishes their provenance or behavior. This script does not
run BitBake, build a rootfs, publish an image, or approve private mode.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
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
    head = subprocess.run(["git", "-C", str(meta_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
    if head.returncode != 0 or head.stdout.strip() != META_COMMIT:
        raise Refusal("meta-dstack checkout is not at the pinned commit")
    gitlink = subprocess.run(
        ["git", "-C", str(meta_repo), "ls-tree", META_COMMIT, "dstack"],
        capture_output=True, text=True, check=False)
    if gitlink.returncode != 0 or gitlink.stdout.strip() != (
            f"160000 commit {DSTACK_COMMIT}\tdstack"):
        raise Refusal("pinned meta-dstack dstack gitlink changed")
    originals = {}
    for source_path, expected in META_HASHES.items():
        result = subprocess.run(
            ["git", "-C", str(meta_repo), "show", f"{META_COMMIT}:{source_path}"],
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


def candidate_guest_recipe(source: str, runtime) -> str:
    """Install every generated runtime file from the recipe's rsynced dstack tree."""
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
    head = subprocess.run(["git", "-C", str(dstack_repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
    if head.returncode != 0 or head.stdout.strip() != DSTACK_COMMIT:
        raise Refusal("dstack checkout is not at the pinned meta-dstack gitlink")


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
        recipe = candidate_guest_recipe(originals[GUEST_RECIPE], runtime)
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
        for name, payload in ((GUARD_NAME, guard), (BRIDGE_NAME, bridge)):
            target = dstack_overlay / "zrpc" / name
            target.write_bytes(payload)
            target.chmod(0o755)
        recipe_path = meta_overlay / GUEST_RECIPE
        recipe_path.parent.mkdir(parents=True, exist_ok=True)
        recipe_path.write_text(recipe)
        files = {}
        for candidate in sorted(output.rglob("*")):
            if candidate.is_file():
                if not stat.S_ISREG(candidate.lstat().st_mode):
                    raise Refusal("generated candidate contains a symbolic link")
                files[str(candidate.relative_to(output))] = digest(candidate.read_bytes())
        (output / "packaging-manifest.json").write_text(json.dumps({
            "meta_source_commit": META_COMMIT,
            "dstack_source_commit": DSTACK_COMMIT,
            "source_identity_scope": "pinned_meta_objects_and_pinned_dstack_overlay_objects",
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
