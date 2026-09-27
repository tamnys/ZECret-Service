#!/usr/bin/env python3
"""Check fetched dstack Git objects before a locked native Cargo fetch.

This reads the reviewed commit and tree through Git without checking out or
executing upstream files. The separate live source and registry preflights must
pass first. Matching these objects does not approve a guest image or private mode.
"""

import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tomllib


GATE = runpy.run_path(str(Path(__file__).with_name("check-cargo-git-source.py")))
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class Refusal(Exception):
    pass


def git(repository, *arguments):
    if not repository.is_dir() or repository.is_symlink():
        raise Refusal("fetched Git repository must be a regular directory")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refusal("fetched Git object inspection failed") from error
    return result.stdout


def manifest_version(path, manifest, manifests):
    package = manifest.get("package")
    if not isinstance(package, dict):
        return None
    version = package.get("version")
    if isinstance(version, str):
        return version
    if version != {"workspace": True}:
        return None
    parents = path.split("/")[:-1]
    for depth in range(len(parents), -1, -1):
        ancestor = "/".join([*parents[:depth], "Cargo.toml"])
        workspace = manifests.get(ancestor, {}).get("workspace")
        if not isinstance(workspace, dict):
            continue
        inherited = workspace.get("package")
        if isinstance(inherited, dict) and isinstance(inherited.get("version"), str):
            return inherited["version"]
    return None


def check_fetched_tree(repository, commit, expected_tree, packages):
    if (not isinstance(commit, str) or not HEX40.fullmatch(commit)
            or not isinstance(expected_tree, str) or not HEX40.fullmatch(expected_tree)
            or not isinstance(packages, dict) or not packages):
        raise Refusal("unreviewed Git object or package identity")
    git(repository, "fsck", "--strict", "--no-reflogs", "--no-progress")
    if git(repository, "rev-parse", "--verify", f"{commit}^{{commit}}").strip() != commit.encode():
        raise Refusal("fetched Git commit differs from review")
    actual_tree = git(repository, "rev-parse", "--verify", f"{commit}^{{tree}}").strip()
    if actual_tree != expected_tree.encode():
        raise Refusal("fetched Git tree differs from review")

    manifests = {}
    identities = {}
    for record in git(repository, "ls-tree", "-r", "-z", commit).split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, raw_oid = metadata.split(b" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise Refusal("malformed fetched Git tree entry") from error
        if path != "Cargo.toml" and not path.endswith("/Cargo.toml"):
            continue
        if mode != b"100644" or kind != b"blob" or not HEX40.fullmatch(raw_oid.decode("ascii")):
            raise Refusal("Cargo manifest is not a regular Git blob")
        if path in manifests:
            raise Refusal("duplicate Cargo manifest path")
        try:
            manifests[path] = tomllib.loads(git(repository, "cat-file", "blob", raw_oid.decode()).decode("utf-8"))
        except (UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
            raise Refusal("malformed fetched Cargo manifest") from error

    for path, manifest in manifests.items():
        package = manifest.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not isinstance(name, str) or name not in packages:
            continue
        version = manifest_version(path, manifest, manifests)
        if name in identities or version != packages[name]:
            raise Refusal("fetched Git package identity differs from review")
        identities[name] = {"manifest_path": path, "version": version}
    if set(identities) != set(packages):
        raise Refusal("reviewed Cargo package missing from fetched Git tree")
    return dict(sorted(identities.items()))


def verify(root, repository):
    lock_sha256 = GATE["check_local_inputs"](root)
    identities = check_fetched_tree(repository, GATE["COMMIT"], GATE["TREE"], GATE["PACKAGES"])
    return {
        "status": "diagnostic-reviewed-git-objects-and-manifests-matched",
        "cargo_lock_sha256": lock_sha256,
        "source_commit": GATE["COMMIT"],
        "source_tree": GATE["TREE"],
        "package_manifests": identities,
        "git_object_fetched_and_checked_locally": True,
        "cargo_fetch_executed": False,
        "cargo_build_executed": False,
        "guest_image_built": False,
        "private_mode_approved": False,
    }


def main(arguments):
    if len(arguments) != 2:
        print("usage: check-cargo-fetched-git-source.py PROJECT_ROOT FETCHED_GIT_REPO", file=sys.stderr)
        return 2
    try:
        report = verify(Path(arguments[0]), Path(arguments[1]))
    except (Refusal, GATE["Refusal"], OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"git_object_fetched_and_checked_locally": False,
                          "reason": str(error), "cargo_fetch_executed": False,
                          "cargo_build_executed": False, "guest_image_built": False,
                          "private_mode_approved": False}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
