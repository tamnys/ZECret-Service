"""Derive an unbuilt production-rootfs recipe candidate from pinned meta-dstack.

This removes observed local rescue, debug and mutable boot-command paths. It
does not integrate the dstack runtime overlay, build an image, or prove that
Phala admits the resulting image/KMS pair.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SOURCE_COMMIT = "e3655d1390feee3736476f4bda35c4354b4a12fc"
PROD = Path("meta-dstack/recipes-core/images/dstack-rootfs-prod.inc")
BASE = Path("meta-dstack/recipes-core/images/dstack-rootfs-base.inc")
SOURCE_HASHES = {
    PROD: "b9ba45c2988c7370f5b715c411da6f8d709c42ff19207e1f843456f2f9f65161",
    BASE: "9a807b6f47b2a7f18e213d5892f7f410dccc6a41a23a63e7cbf7492c4183fb72",
}

# Present in the verity-verified v0.5.9 stock rootfs inspection. A missing
# required path in a later build is a source/layout change requiring review.
ADMIN_FILES = (
    "/usr/lib/systemd/system/emergency.service",
    "/usr/lib/systemd/system/emergency.target",
    "/usr/lib/systemd/system/rescue.service",
    "/usr/lib/systemd/system/rescue.target",
    "/usr/lib/systemd/system-generators/systemd-debug-generator",
    "/usr/lib/systemd/system-generators/systemd-run-generator",
    "/usr/lib/systemd/system-generators/systemd-system-update-generator",
    "/usr/lib/systemd/system-generators/systemd-rc-local-generator",
    "/usr/lib/systemd/system-generators/systemd-sysv-generator",
    "/usr/lib/systemd/system-generators/systemd-hibernate-resume-generator",
    "/usr/lib/systemd/system-generators/zfs-mount-generator",
    "/usr/lib/systemd/systemd-sulogin-shell",
    "/usr/sbin/sulogin",
)
OPTIONAL_FILES = ("/usr/sbin/sulogin.util-linux",)
MASK_UNITS = (
    "emergency.service", "emergency.target", "rescue.service", "rescue.target",
    "debug-shell.service", "suspend.target", "hibernate.target",
    "hybrid-sleep.target", "suspend-then-hibernate.target", "system-update.target",
)


def pinned_source(repo: Path, path: Path) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{SOURCE_COMMIT}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"pinned source object unavailable: {path}")
    if hashlib.sha256(result.stdout).hexdigest() != SOURCE_HASHES[path]:
        raise ValueError(f"pinned source mismatch: {path}")
    return result.stdout


def candidate_prod(production: str, base: str) -> str:
    if production != 'include dstack-rootfs-base.inc\nIMAGE_FEATURES += "nologin"\n':
        raise ValueError("production recipe anchor changed")
    if "disable_login() {" not in base or 'IMAGE_FEATURES += "nologin"' not in production:
        raise ValueError("base login-removal contract changed")
    required = " ".join(ADMIN_FILES)
    optional = " ".join(OPTIONAL_FILES)
    masks = " ".join(MASK_UNITS)
    return production + f'''
# Source-only private-profile candidate. The stock production recipe removes
# getty/login, but the inspected image retains rescue, sulogin and generators.
ROOTFS_POSTPROCESS_COMMAND += "zrpc_strip_local_admin;"

zrpc_strip_local_admin() {{
    # BitBake expands these recipe variables before running the shell task.
    # Canonicalize and constrain them before touching the image tree.
    [ ! -L "${{IMAGE_ROOTFS}}" ] || return 1
    root=$(realpath -e -- "${{IMAGE_ROOTFS}}") || return 1
    workdir=$(realpath -e -- "${{WORKDIR}}") || return 1
    [ "$workdir" != "/" ] || return 1
    case "$root" in
        "$workdir"/*) ;;
        *) return 1 ;;
    esac
    [ "$root" != "$workdir" ] || return 1
    # A symlink in a parent component can redirect rm/install/ln outside root.
    for dir in /usr /usr/lib /usr/lib/systemd /usr/lib/systemd/system /usr/lib/systemd/system-generators /usr/sbin /etc /etc/systemd /etc/systemd/system; do
        if [ -L "$root$dir" ] || {{ [ -e "$root$dir" ] && [ ! -d "$root$dir" ]; }}; then
            echo "Unsafe rootfs parent: $dir" >&2
            return 1
        fi
    done
    for path in {required}; do
        if [ ! -e "$root$path" ] && [ ! -L "$root$path" ]; then
            echo "Pinned local admin path missing: $path" >&2
            return 1
        fi
    done
    for unit in {masks}; do
        target="$root/etc/systemd/system/$unit"
        if [ -e "$target" ] || [ -L "$target" ]; then
            echo "Unexpected preexisting unit override: $unit" >&2
            return 1
        fi
    done
    install -d "$root/etc/systemd/system"
    for path in {required} {optional}; do
        rm -f -- "$root$path" || return 1
    done
    for unit in {masks}; do
        ln -s /dev/null "$root/etc/systemd/system/$unit" || return 1
    done
}}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_git_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    head = subprocess.run(
        ["git", "-C", str(args.source_git_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if head.returncode != 0 or head.stdout.strip() != SOURCE_COMMIT:
        parser.error("source checkout is not at the pinned meta-dstack commit")
    try:
        originals = {
            path: pinned_source(args.source_git_dir, path).decode("utf-8")
            for path in SOURCE_HASHES
        }
        candidate = candidate_prod(originals[PROD], originals[BASE])
    except ValueError as error:
        parser.error(str(error))
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    target = args.output_dir / PROD
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(candidate)
    (args.output_dir / "candidate-manifest.json").write_text(json.dumps({
        "source_commit": SOURCE_COMMIT,
        "source_commit_object_verified": True,
        "source_tree_verified": False,
        "source_identity_scope": "two_recipe_files_from_pinned_git_commit",
        "source_sha256": {str(path): digest for path, digest in SOURCE_HASHES.items()},
        "candidate_sha256": {str(PROD): hashlib.sha256(candidate.encode()).hexdigest()},
        "rootfs_built": False,
        "admin_absence_demonstrated": False,
        "private_accepted": False,
    }, indent=2, sort_keys=True) + "\n")
    print("Production rootfs recipe source only; no image, boot or admin-access proof.")


if __name__ == "__main__":
    main()
