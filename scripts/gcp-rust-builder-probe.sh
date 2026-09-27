#!/usr/bin/env bash
# Diagnostic input for the pinned, networkless x86_64 Rust base. No Cargo command runs.
set -euo pipefail

printf '%s\n' \
  'probe_kind=diagnostic_pinned_rust_base_only' \
  'full_managed_image_verified=false' \
  'cargo_dependency_closure_verified=false' \
  'cargo_fetch_executed=false' \
  'cargo_build_executed=false' \
  'guest_image_built=false' \
  'approved_release=false' \
  'private_mode_approved=false'

expected_version="${1-}"
if [[ "$expected_version" != 1.94.1 ]]; then
  echo 'Refusing unreviewed Rust version' >&2
  exit 1
fi
if [[ "$(uname -m)" != x86_64 ]]; then
  echo 'Refusing non-x86_64 container' >&2
  exit 1
fi
for interface in /sys/class/net/*; do
  if [[ "${interface##*/}" != lo ]]; then
    echo 'Refusing container with non-loopback network interface' >&2
    exit 1
  fi
done

printf 'container_architecture=%s\n' "$(uname -m)"
printf 'container_memtotal_kib=%s\n' "$(awk '$1 == "MemTotal:" { print $2 }' /proc/meminfo)"
if [[ -r /sys/fs/cgroup/memory.max ]]; then
  printf 'container_cgroup_memory_max=%s\n' "$(cat /sys/fs/cgroup/memory.max)"
fi
df -B1 /tmp

failures=()
record_tool() {
  local name="$1" path resolved checksum
  if ! path="$(command -v "$name")"; then
    printf 'tool_%s=missing\n' "$name"
    return 1
  fi
  resolved="$(readlink -f "$path")"
  checksum="$(sha256sum "$resolved")"
  printf 'tool_%s_path=%s\ntool_%s_sha256=%s\n' \
    "$name" "$resolved" "$name" "${checksum%% *}"
}

for name in rustup rustc cargo cc ar ld git python3; do
  record_tool "$name" || failures+=("missing:$name")
done
for name in c++ protoc pkg-config; do
  record_tool "$name" || :
done

if command -v rustup >/dev/null && command -v rustc >/dev/null && command -v cargo >/dev/null; then
  for name in rustc cargo; do
    if installed="$(rustup which --toolchain 1.94.1-x86_64-unknown-linux-gnu "$name")"; then
      checksum="$(sha256sum "$installed")"
      printf 'installed_%s_path=%s\ninstalled_%s_sha256=%s\n' \
        "$name" "$installed" "$name" "${checksum%% *}"
    else
      failures+=("installed-toolchain:$name")
    fi
  done
  if rustc_info="$(rustc -vV)"; then
    printf '%s\n' "$rustc_info"
    rustc_release="$(printf '%s\n' "$rustc_info" | sed -n 's/^release: //p')"
    rustc_host="$(printf '%s\n' "$rustc_info" | sed -n 's/^host: //p')"
    [[ "$rustc_release" == "$expected_version" ]] || failures+=("rustc-release:$rustc_release")
    [[ "$rustc_host" == x86_64-unknown-linux-gnu ]] || failures+=("rustc-host:$rustc_host")
  else
    failures+=(rustc-invocation)
  fi
  if cargo_version="$(cargo --version)"; then
    printf 'cargo_version=%s\n' "$cargo_version"
    [[ "$cargo_version" == "cargo $expected_version "* ]] || failures+=("cargo-version:$cargo_version")
  else
    failures+=(cargo-invocation)
  fi
fi

if command -v cc >/dev/null && command -v ar >/dev/null && command -v ld >/dev/null; then
  printf 'int main(void) { return 0; }\n' > /tmp/zrpc-cc-probe.c
  if cc /tmp/zrpc-cc-probe.c -o /tmp/zrpc-cc-probe; then
    echo 'c_compile_and_link=true'
  else
    echo 'c_compile_and_link=false'
    failures+=(c-compile-and-link)
  fi
fi
if command -v python3 >/dev/null; then
  if python3 -c 'import sys, tomllib; sys.exit(sys.version_info < (3, 11))'; then
    printf 'python_version=%s\n' "$(python3 --version)"
  else
    failures+=(python-version-or-tomllib)
  fi
fi

# These describe managed-image parity; absence does not fail the Rust-only build probe.
# The selected Rust crate graph uses cc, while Zebra's later build has separate inputs.
if command -v protoc >/dev/null; then
  printf 'protobuf_compiler_version=%s\n' "$(protoc --version)"
else
  echo 'protobuf_compiler=missing_optional_for_rust_only_probe'
fi
if command -v pkg-config >/dev/null; then
  for module in protobuf openssl libudev; do
    if pkg-config --exists "$module"; then
      printf 'pkg_config_%s_version=%s\n' "$module" "$(pkg-config --modversion "$module")"
    else
      printf 'pkg_config_%s=missing_optional_for_rust_only_probe\n' "$module"
    fi
  done
else
  echo 'pkg_config_modules=unavailable_optional_for_rust_only_probe'
fi

if (( ${#failures[@]} )); then
  printf 'hard_prerequisite_failure=%s\n' "${failures[*]}" >&2
  exit 1
fi
echo 'hard_prerequisites_for_rust_only_probe=present'
