#!/usr/bin/env python3
"""Build an unsigned, exact committed scaffold twice without downloading inputs.

Run inside the reviewed Linux build environment. Output is create-new and stays
inside the checkout's real directory; failed builds are retained for inspection.
This script grants no release approval, attestation acceptance or cloud authority.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tomllib


class Refusal(Exception):
    pass


# Keep every project executable in one reviewed artifact set. A matching pair
# of builds must account for all of them before delivery.
ARTIFACTS = (
    ("zrpc-cli", "zrpc"),
    ("zrpc-server", "zrpc-wrapper"),
    ("zrpc-server", "zrpc-node-wrapper"),
    ("zrpc-server", "zrpc-quote-proxy"),
    ("zrpc-server", "zrpc-gcp-quote-broker"),
    ("zrpc-server", "zrpc-gcp-guard"),
    ("zrpc-server", "zrpc-gcp-disk-id"),
    ("zrpc-server", "zrpc-gcp-cookie"),
    ("zrpc-server", "zrpc-gcp-early-init"),
    ("zrpc-lifecycle", "zrpc-gcp-lifecycle"),
    ("zrpc-lifecycle", "zrpc-gcp-import-producer"),
    ("zrpc-uki-digest", "zrpc-uki-digest"),
    ("zrpc-wallet-reference", "zrpc-wallet-reference"),
)
PAYMENT_HELPER = ("zrpc-payment-crypto", "zrpc-payment-crypto")
ALL_ARTIFACTS = (*ARTIFACTS, PAYMENT_HELPER)

STATIC_IMPORT_PRODUCER = "zrpc-gcp-import-producer"


def check_project_artifacts(source):
    """Refuse a new workspace binary until it joins the compared artifact set."""
    workspace = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]
    found = set()
    for member in workspace["members"]:
        package_root = source / member
        manifest = tomllib.loads((package_root / "Cargo.toml").read_text())
        package = manifest["package"]
        name = package["name"]
        explicit = manifest.get("bin", [])
        if not isinstance(explicit, list):
            raise Refusal("project binary inventory requires review")
        explicit_paths = set()
        for binary in explicit:
            if not isinstance(binary, dict) or not isinstance(binary.get("name"), str):
                raise Refusal("project binary inventory requires review")
            found.add((name, binary["name"]))
            if "path" in binary:
                explicit_paths.add(binary["path"])
        if package.get("autobins", True) is not False:
            if (package_root / "src/main.rs").is_file() and "src/main.rs" not in explicit_paths:
                found.add((name, name))
            bin_root = package_root / "src/bin"
            if bin_root.is_dir():
                found.update((name, path.stem) for path in bin_root.glob("*.rs")
                             if path.relative_to(package_root).as_posix() not in explicit_paths)
                found.update((name, path.parent.name) for path in bin_root.glob("*/main.rs")
                             if path.relative_to(package_root).as_posix() not in explicit_paths)
    if found != set(ARTIFACTS) or len(ARTIFACTS) != len(found):
        raise Refusal("project Rust binary inventory differs from double build")


def check_payment_helper(source):
    """The separately locked Privacy Pass helper must remain a local binary."""
    root = source / "tools/payment-crypto"
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if (manifest.get("package", {}).get("name") != PAYMENT_HELPER[0]
            or manifest.get("workspace") != {}
            or manifest.get("dependencies", {}).get("blind-rsa-signatures") != "=0.17.2"
            or not (root / "Cargo.lock").is_file()
            or not (root / "src/main.rs").is_file()):
        raise Refusal("separately locked payment helper differs from review")


def check_guest_artifacts(source):
    """The exported image profile must not require an unbuilt project binary."""
    profile = source / "tools/gcp-guest/prepare.py"
    tree = ast.parse(profile.read_text())
    assignments = {name: [statement.value for statement in tree.body
                          if isinstance(statement, ast.Assign)
                          and len(statement.targets) == 1
                          and isinstance(statement.targets[0], ast.Name)
                          and statement.targets[0].id == name]
                   for name in ("BINARIES", "EARLY_INIT_ROLE")}
    if any(len(values) != 1 for values in assignments.values()):
        raise Refusal("GCP guest executable inventory is unavailable")
    try:
        binaries = ast.literal_eval(assignments["BINARIES"][0])
        early_init_role = ast.literal_eval(assignments["EARLY_INIT_ROLE"][0])
    except (ValueError, TypeError, SyntaxError, MemoryError) as error:
        raise Refusal("GCP guest executable inventory requires review") from error
    if (not isinstance(binaries, dict) or not binaries
            or any(not isinstance(role, str) or not isinstance(name, str) or not name
                   for role, name in binaries.items())
            or len(set(binaries.values())) != len(binaries.values())
            or binaries.get("zebra") != "zebrad"
            or early_init_role != "early_init"):
        raise Refusal("GCP guest executable inventory requires review")
    # Zebra is a separately authenticated upstream release. Every project
    # executable that the image stages must be compared in both native builds.
    project_binaries = [name for name in binaries.values() if name != "zebrad"]
    project_binaries.append("zrpc-gcp-early-init")
    missing = sorted(name for name in project_binaries
                     if ("zrpc-server", name) not in ARTIFACTS)
    if missing:
        raise Refusal("GCP guest executable missing from double build: " + ", ".join(missing))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_source_script(source, invoking_sha256, manifest):
    """Reproduction rules must be the rules committed in the selected tree."""
    source_script = source / "scripts/reproduce-release.py"
    if not source_script.is_file() or source_script.is_symlink():
        raise Refusal("selected commit lacks its exact reproduction script")
    manifest["script_in_source_sha256"] = digest(source_script)
    manifest["script_matches_source"] = (
        manifest["script_in_source_sha256"] == invoking_sha256
    )
    if not manifest["script_matches_source"]:
        raise Refusal("invoking reproduction script differs from selected commit")


def command(args, *, cwd, env, stdout=subprocess.PIPE):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=stdout,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise Refusal(f"{Path(args[0]).name} inspection failed (exit {result.returncode})")
    return result.stdout.decode("utf-8").strip() if result.stdout is not None else None


def tool(name, cwd, env, *version_args):
    selected = shutil.which(name, path=env["PATH"])
    if selected is None:
        raise Refusal(f"required tool unavailable: {name}")
    path = Path(selected).resolve(strict=True)
    return {"path": selected, "resolved_path": str(path), "sha256": digest(path),
            "version": command([selected, *version_args], cwd=cwd, env=env)}


def base_environment():
    # Retain managed/package/network policy. Clear caller Git redirection and
    # compilation controls; never dump the inherited environment into the report.
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("GIT_"):
            del env[name]
    for name in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
                 "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"):
        if env.get(name):
            raise Refusal("inherited compiler wrapper requires review; it is not bypassed")
    compilation = {"RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_BOOTSTRAP",
                   "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
                   "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTDOC",
                   "CARGO_BUILD_TARGET", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_INCREMENTAL",
                   "CC", "CXX", "AR", "CFLAGS", "CXXFLAGS", "ARFLAGS", "CPPFLAGS", "LDFLAGS",
                   "HOST_CC", "HOST_CXX", "HOST_AR", "HOST_CFLAGS", "HOST_CXXFLAGS", "HOST_ARFLAGS",
                   "TARGET_CC", "TARGET_CXX", "TARGET_AR", "TARGET_CFLAGS", "TARGET_CXXFLAGS", "TARGET_ARFLAGS"}
    prefixes = ("CARGO_PROFILE_", "CARGO_TARGET_", "CC_", "CXX_", "AR_", "CFLAGS_", "CXXFLAGS_", "ARFLAGS_")
    for name in list(env):
        if name in compilation or name.startswith(prefixes):
            del env[name]
    if not env.get("PATH") or not env.get("HOME"):
        raise Refusal("PATH and HOME are required by the existing toolchain")
    env.update({"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "CARGO_NET_OFFLINE": "true",
                "CARGO_INCREMENTAL": "0", "CODEX_SCCACHE": "0",
                "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "",
                "CCACHE_DISABLE": "1", "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "CARGO_TERM_COLOR": "never"})
    return env


def output_path(value, repository):
    supplied = Path(value)
    if not supplied.is_absolute() or ".." in supplied.parts:
        raise Refusal("output directory must be an absolute path without parent traversal")
    parent = supplied.parent.resolve(strict=True)
    output = parent / supplied.name
    if not output.is_relative_to(repository) or output == repository:
        raise Refusal("output directory must stay inside the real repository directory")
    if "CODEX_WORKSPACE_DIR" in os.environ:
        workspace = Path(os.environ["CODEX_WORKSPACE_DIR"]).resolve(strict=True)
        if not output.is_relative_to(workspace):
            raise Refusal("output directory must stay on the managed workspace volume")
    if output.exists() or output.is_symlink():
        raise Refusal("output already exists; reuse, replacement and cleanup are forbidden")
    return output


def extract_source(archive, destination):
    destination.mkdir()
    with tarfile.open(archive, mode="r:") as source:
        for member in source:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts:
                raise Refusal("source archive contains an unsafe path")
            target = destination.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source.extractfile(member)
                if stream is None:
                    raise Refusal("source archive file is unavailable")
                with stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
                os.utime(target, (member.mtime, member.mtime))
            else:
                # Do not follow symlinks, hard links, devices or submodule-like
                # entries outside the immutable, self-contained input tree.
                raise Refusal("source archive requires unsupported nonregular input")


def build_environment(base, source, target, temporary, toolchain, tools, epoch):
    env = base.copy()
    env.update({"SOURCE_DATE_EPOCH": str(epoch), "CARGO_TARGET_DIR": str(target),
                "TMPDIR": str(temporary), "RUSTUP_TOOLCHAIN": toolchain,
                "GIT_CEILING_DIRECTORIES": str(source.parent),
                "CC": tools["cc"]["path"], "AR": tools["ar"]["path"]})
    cargo_home = Path(env.get("CARGO_HOME", str(Path(env["HOME"]) / ".cargo"))).resolve()
    prefixes = [(source, "/zrpc/source"), (target, "/zrpc/target"),
                (temporary, "/zrpc/tmp"), (cargo_home, "/zrpc/cargo")]
    if "RUSTUP_HOME" in env:
        prefixes.append((Path(env["RUSTUP_HOME"]).resolve(), "/zrpc/rustup"))
    flags = [f"--remap-path-prefix={original}={replacement}" for original, replacement in prefixes]
    flags += ["-C", f"linker={tools['cc']['path']}"]
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    cflags = [f"-ffile-prefix-map={original}={replacement}" for original, replacement in prefixes]
    env["CFLAGS"] = shlex.join(cflags)
    return env, {"rust_flags": flags, "c_flags": cflags,
                 "source_date_epoch": epoch, "incremental": False,
                 "compiler_wrappers": None, "compiler_cache": False,
                 "locale": "C", "timezone": "UTC", "offline": True,
                 "profile": "release; committed manifests and hashed Cargo configuration",
                 "target": "native rustc host"}


def config_hashes(source, env):
    # Cargo reads ancestor and CARGO_HOME config. Hash their bytes without
    # exporting possibly secret registry credentials or configuration contents.
    cargo_home = Path(env.get("CARGO_HOME", str(Path(env["HOME"]) / ".cargo")))
    locations = {cargo_home / name for name in ("config", "config.toml")}
    for parent in (source, *source.parents):
        locations.update(parent / ".cargo" / name for name in ("config", "config.toml"))
    hashes = {}
    for path in sorted(locations):
        if path.is_file():
            data = tomllib.loads(path.read_text())
            build = data.get("build", {})
            if any(build.get(key) for key in ("rustc-wrapper", "rustc-workspace-wrapper")):
                raise Refusal("configured compiler wrapper requires review; it is not bypassed")
            hashes[str(path)] = digest(path)
    return hashes


def reproduce(args):
    if platform.system() != "Linux":
        raise Refusal("build reproduction requires the reviewed Linux environment")
    if platform.machine() != "x86_64":
        raise Refusal("native x86_64 build host required")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", args.revision):
        raise Refusal("revision must be an exact full lowercase Git commit object ID")
    env = base_environment()
    script = Path(__file__).resolve(strict=True)
    repository = Path(command(["git", "rev-parse", "--show-toplevel"],
                              cwd=script.parent, env=env)).resolve(strict=True)
    if command(["git", "rev-parse", "HEAD"], cwd=repository, env=env) != args.revision:
        raise Refusal("selected revision must be the exact checkout HEAD")
    output = output_path(args.output_directory, repository)
    if command(["git", "cat-file", "-t", args.revision], cwd=repository, env=env) != "commit":
        raise Refusal("revision must name a commit, not a tag or other object")
    tree = command(["git", "show", "-s", "--format=%T", args.revision], cwd=repository, env=env)
    epoch = int(command(["git", "show", "-s", "--format=%ct", args.revision], cwd=repository, env=env))
    pin = tomllib.loads(command(["git", "show", f"{args.revision}:rust-toolchain.toml"],
                               cwd=repository, env=env))["toolchain"]["channel"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pin):
        raise Refusal("source requires an exact installed stable Rust release")
    # Listing installed toolchains never installs one. An explicit installed
    # full name prevents rustup from trying to fetch an absent default target.
    selected_toolchain = pin
    if shutil.which("rustup", path=env["PATH"]):
        installed = command(["rustup", "toolchain", "list"], cwd=repository, env=env)
        candidates = [line.split()[0] for line in installed.splitlines()
                      if line.split() and (line.split()[0] == pin or line.split()[0].startswith(pin + "-"))]
        if len(candidates) != 1:
            raise Refusal("exact Rust release must have one existing installed toolchain; no installation is attempted")
        selected_toolchain = candidates[0]
    env["RUSTUP_TOOLCHAIN"] = selected_toolchain
    tools = {name: tool(name, repository, env, *options) for name, options in
             {"rustc": ["-vV"], "cargo": ["--version", "--verbose"],
              "cc": ["--version"], "ar": ["--version"], "ld": ["--version"],
              "readelf": ["--version"],
              "git": ["--version"]}.items()}
    release = re.search(r"^release: (.+)$", tools["rustc"]["version"], re.MULTILINE)
    if release is None or release.group(1) != pin:
        raise Refusal("actual rustc release differs from the committed toolchain pin")
    if re.search(r"^host: x86_64-unknown-linux-gnu$", tools["rustc"]["version"], re.MULTILINE) is None:
        raise Refusal("installed Rust host must be native x86_64 Linux")
    if shutil.which("rustup", path=env["PATH"]):
        for name in ("rustc", "cargo"):
            installed_binary = Path(command(["rustup", "which", "--toolchain", selected_toolchain, name],
                                            cwd=repository, env=env)).resolve(strict=True)
            tools[name]["installed_binary"] = {"path": str(installed_binary), "sha256": digest(installed_binary)}
    compiler_linker = command([tools["cc"]["path"], "-print-prog-name=ld"], cwd=repository, env=env)
    tools["cc"]["selected_linker"] = compiler_linker
    tools["ldd"] = tool("ldd", repository, env, "--version") if shutil.which("ldd", path=env["PATH"]) else None
    output.mkdir(mode=0o700)
    manifest = {"schema_version": 1, "artifact_kind": "unsigned_native_scaffold",
                "milestone": "M0", "compiled_artifacts_are_synthetic": False,
                "simulation_available": True, "approved_release": False,
                "private_accepted": False, "deployment_enabled": False,
                "published": False, "signed": False, "reproducible": False,
                "selected_binaries": [{"package": package, "name": name}
                                      for package, name in ALL_ARTIFACTS],
                "source_commit": args.revision, "source_tree": tree,
                "source_commit_timestamp": epoch, "script_sha256": digest(script),
                "script_in_source_sha256": None, "script_matches_source": None,
                "tools": tools, "builds": [],
                "limitations": ["Equality is measured within this recorded Linux environment, not across independent toolchain builds.",
                                "System compiler, linker, libc, sysroot and existing Cargo configuration remain build inputs.",
                                "Checksums are integrity identifiers, not signatures, release approval or attestation measurements.",
                                "Cargo offline mode prevents dependency fetches; it is not a network sandbox for reviewed build scripts."]}
    os_release = Path("/etc/os-release")
    manifest["os_release"] = {"sha256": digest(os_release), "text": os_release.read_text()} if os_release.is_file() else None
    try:
        archive = output / "source.tar"
        with archive.open("xb") as stream:
            command(["git", "archive", "--format=tar", args.revision],
                    cwd=repository, env=env, stdout=stream)
        manifest["source_archive_sha256"] = digest(archive)
        for label in ("build-a", "build-b"):
            root = output / label
            root.mkdir()
            source, target, temporary = root / "source", root / "target", root / "tmp"
            extract_source(archive, source)
            require_source_script(source, manifest["script_sha256"], manifest)
            check_project_artifacts(source)
            check_payment_helper(source)
            check_guest_artifacts(source)
            target.mkdir()
            temporary.mkdir()
            inputs = [source / "Cargo.lock", source / "rust-toolchain.toml",
                      source / "tools/payment-crypto/Cargo.lock"]
            inputs += list(source.rglob("Cargo.toml"))
            inputs += [p for p in (source / "ui" / "local").rglob("*") if p.is_file()]
            input_hashes = {str(p.relative_to(source)): digest(p) for p in sorted(set(inputs))}
            if "input_sha256" in manifest and manifest["input_sha256"] != input_hashes:
                raise Refusal("independent source exports differ")
            manifest["input_sha256"] = input_hashes
            build_env, settings = build_environment(env, source, target, temporary, selected_toolchain, tools, epoch)
            argv = [tools["cargo"]["path"], "build", "--locked", "--offline", "--release"]
            for package, name in ARTIFACTS:
                argv.extend(("-p", package, "--bin", name))
            record = {"directory": label, "command": argv, "settings": settings,
                      "cargo_configuration_sha256": config_hashes(source, build_env)}
            manifest["builds"].append(record)
            print(f"Building {label}; diagnostics: {root / 'build.log'}", flush=True)
            with (root / "build.log").open("xb") as log:
                result = subprocess.run(argv, cwd=source, env=build_env, stdout=log,
                                        stderr=subprocess.STDOUT, check=False)
            record["exit_code"] = result.returncode
            if result.returncode:
                raise Refusal(f"{label} failed (exit {result.returncode}); retained build.log has diagnostics")
            static_argv = [tools["cargo"]["path"], "rustc", "--locked", "--offline",
                           "--release", "-p", "zrpc-lifecycle", "--bin",
                           STATIC_IMPORT_PRODUCER, "--", "-C", "target-feature=+crt-static"]
            record["static_import_producer_command"] = static_argv
            print(f"Building static import producer for {label}; diagnostics: {root / 'static-import.log'}", flush=True)
            with (root / "static-import.log").open("xb") as log:
                result = subprocess.run(static_argv, cwd=source, env=build_env, stdout=log,
                                        stderr=subprocess.STDOUT, check=False)
            record["static_import_producer_exit_code"] = result.returncode
            if result.returncode:
                raise Refusal(f"{label} static import producer failed (exit {result.returncode}); retained static-import.log has diagnostics")
            helper_argv = [tools["cargo"]["path"], "build", "--locked", "--offline",
                           "--release", "--manifest-path",
                           "tools/payment-crypto/Cargo.toml", "--bin", PAYMENT_HELPER[1]]
            record["payment_helper_command"] = helper_argv
            print(f"Building payment helper for {label}; diagnostics: {root / 'payment-helper.log'}", flush=True)
            with (root / "payment-helper.log").open("xb") as log:
                result = subprocess.run(helper_argv, cwd=source, env=build_env,
                                        stdout=log, stderr=subprocess.STDOUT, check=False)
            record["payment_helper_exit_code"] = result.returncode
            if result.returncode:
                raise Refusal(f"{label} payment helper failed (exit {result.returncode}); retained payment-helper.log has diagnostics")
            static_binary = target / "release" / STATIC_IMPORT_PRODUCER
            segments = command([tools["readelf"]["path"], "--wide", "--program-headers",
                                str(static_binary)], cwd=source, env=build_env)
            dynamic = command([tools["readelf"]["path"], "--wide", "--dynamic",
                               str(static_binary)], cwd=source, env=build_env)
            if "INTERP" in segments or "NEEDED" in dynamic:
                raise Refusal(f"{label} import producer retains a dynamic loader or shared library")
            record["static_import_producer_no_dynamic_loader"] = True
            record["artifact_sha256"] = {name: digest(target / "release" / name)
                                          for _, name in ALL_ARTIFACTS}
        first, second = manifest["builds"]
        if first["artifact_sha256"] != second["artifact_sha256"]:
            raise Refusal("independent binary checksums differ; outputs retained, reproducibility not established")
        artifacts = output / "artifacts"
        artifacts.mkdir()
        for name in first["artifact_sha256"]:
            with (output / "build-a" / "target" / "release" / name).open("rb") as source:
                with (artifacts / name).open("xb") as destination:
                    shutil.copyfileobj(source, destination)
            (artifacts / name).chmod(0o755)
        with (output / "SHA256SUMS").open("x") as checksums:
            for name, value in sorted(first["artifact_sha256"].items()):
                checksums.write(f"{value}  artifacts/{name}\n")
        manifest["reproducible"] = True
        manifest["artifact_sha256"] = first["artifact_sha256"]
        if command(["git", "rev-parse", "HEAD"], cwd=repository, env=env) != args.revision:
            raise Refusal("checkout HEAD changed during reproduction")
    except (Refusal, OSError, ValueError, tarfile.TarError, KeyboardInterrupt) as error:
        manifest["failure"] = str(error) if isinstance(error, Refusal) else type(error).__name__
        raise
    finally:
        with (output / "manifest.json").open("x") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(f"Matching unsigned scaffold binaries: {output / 'SHA256SUMS'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="Exact full committed source object ID; working-tree edits are excluded")
    parser.add_argument("--output-directory", required=True, help="New absolute output directory inside the real checkout; parent must already exist")
    args = parser.parse_args()
    try:
        reproduce(args)
    except Refusal as error:
        print(f"Release reproduction refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        print(f"Release reproduction failed: {type(error).__name__}; retained outputs are not reused or removed", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Release reproduction interrupted; outputs retained", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
