"""Check offline verifier, TLS and Zcash parser features/pins and fixture hashes."""
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
lock = tomllib.loads((root / "Cargo.lock").read_text())
qvl_lock = next(p for p in lock["package"] if p["name"] == "dcap-qvl")
assert qvl_lock["version"] == "0.6.3"
assert qvl_lock["checksum"] == "384b16fc9cbca8ec2a1302205487f29c421c51cdf7351f91c41f5ccbd1d1d17d"
host = next(line.removeprefix("host: ") for line in subprocess.check_output(
    ["rustc", "-vV"], text=True, cwd=root
).splitlines() if line.startswith("host: "))
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", host
], cwd=root))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
qvl = next(p for p in packages.values() if p["name"] == "dcap-qvl")
features = set(nodes[qvl["id"]]["features"])
# Derived from the reviewed v0.6.3 Cargo.toml: std's JSON helpers, ring's
# _anycrypto marker, and the maintained X.509 backend. No default/report/override.
allowed = {"std", "ring", "default-x509", "_anycrypto", "serde_json", "urlencoding"}
assert features <= allowed, f"unreviewed QVL feature: {features - allowed}"
assert {"std", "ring", "default-x509"} <= features
seen = set()
def visit(package_id):
    if package_id in seen:
        return
    seen.add(package_id)
    for dep in nodes[package_id]["deps"]:
        # Metadata otherwise includes development and unrelated target edges
        # that do not form part of the native verifier dependency graph.
        if any(kind["kind"] in (None, "build") for kind in dep["dep_kinds"]):
            visit(dep["pkg"])
verifier = next(p for p in packages.values() if p["name"] == "zrpc-verifier")
visit(verifier["id"])
# Feature control is the primary invariant. These are the upstream fetcher's
# known clients/transports/resolvers, checked transitively as a regression guard.
forbidden = {"reqwest", "hyper", "hyper-util", "hickory-resolver", "hickory-proto", "tokio", "ureq"}
assert not (forbidden & {packages[p]["name"] for p in seen})
dstack_lock = next(p for p in lock["package"] if p["name"] == "cc-eventlog")
assert dstack_lock["version"] == "0.5.9"
assert dstack_lock["source"] == "git+https://github.com/Dstack-TEE/dstack?rev=282eeb27d22d8f091ad0fa5a90e638f85cf68751#282eeb27d22d8f091ad0fa5a90e638f85cf68751"
sdk_types = next(p for p in lock["package"] if p["name"] == "dstack-sdk-types")
assert sdk_types["version"] == "0.1.2" and sdk_types["source"] == dstack_lock["source"]
# Only maintained wire types are needed by the bounded Unix adapter. Adding the
# full SDK would introduce unrelated signer and HTTP-fetch implementations.
assert not any(p["name"] == "dstack-sdk" for p in packages.values())
for name, version, checksum in [
    ("ez-hash", "1.1.0", "42b3b3adc5fbbc9e21416d5b721b1bccb501a87d7b32ac89f2c7cea229d40772"),
    ("tokio-socks", "0.5.3", "a7e2948f60dbe26b35f2c7fb74ac2854c1fddded0fe9d7548fcc674a246f7615"),
    ("rustls", "0.23.45", "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634"),
    ("tokio-rustls", "0.26.5", "b0c85f2c3ef0b1cd58b36682f4b17aaa995f0e5db534d85692b4903abce21f67"),
    ("rustls-webpki", "0.103.15", "f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2"),
    ("rcgen", "0.14.10", "8774e05a7d0de114588e6a28fe7e71694b82614ed569d86d8b389dfbc98b8ad8"),
    ("zcash_primitives", "0.30.1", "403d5be1e96339534be098e3377fb8a78d68ca7585b1780133d884b810277418"),
    ("zcash_protocol", "0.10.5", "314329b91ec4bbb517441840e47d0b2029bf0b946f086980c96c889c2d92dc5d"),
]:
    package = next(p for p in lock["package"] if p["name"] == name)
    assert package["version"] == version and package["checksum"] == checksum
for name, reviewed_features in [
    ("rustls", {"ring", "std"}),
    ("tokio-rustls", {"ring"}),
    ("rustls-webpki", {"alloc", "ring", "std"}),
    ("rcgen", {"crypto", "ring", "zeroize"}),
]:
    package = next(p for p in packages.values() if p["name"] == name)
    assert set(nodes[package["id"]]["features"]) == reviewed_features, f"unreviewed {name} features"
# The maintained decoding/hash APIs need no crate features. In particular do not
# add proof generation, transparent spending, test graphs or multicore execution.
for name in ("zcash_primitives", "zcash_protocol", "orchard", "sapling-crypto",
             "zcash_transparent", "equihash"):
    package = next(p for p in packages.values() if p["name"] == name)
    assert not nodes[package["id"]]["features"], f"unreviewed {name} parser features"
parser_receipt = json.loads((root / "records/protocol-dependency-receipt.json").read_text())
locked_packages = {(p["name"], p["version"]): p for p in lock["package"]}
for item in parser_receipt["packages"]:
    package = locked_packages[(item["name"], item["version"])]
    assert package["checksum"] == item["sha256"], "parser dependency review no longer matches lock"
listener_receipt = json.loads((root / "records/listener-dependency-receipt.json").read_text())
for item in listener_receipt["packages"]:
    package = locked_packages[(item["name"], item["version"])]
    assert package["checksum"] == item["sha256"], "listener dependency review no longer matches lock"
# Metadata includes inactive optional package edges. Cargo tree resolves the
# actual native normal/build graph used by this executable.
listener_tree = subprocess.check_output([
    "cargo", "tree", "--locked", "-p", "zrpc-server", "--target", host,
    "-e", "normal,build", "--prefix", "none", "--format", "{p}"
], cwd=root, text=True)
listener_packages = {line.split()[0] for line in listener_tree.splitlines()}
assert not ({"x509-parser", "aws-lc-rs", "aws-lc-sys", "pem"} & listener_packages)
for family in ("dcap", "dstack", "tls"):
    fixture_dir = root / "tests/fixtures" / family
    provenance = json.loads((fixture_dir / "provenance.json").read_text())
    for name, item in provenance["files"].items():
        assert hashlib.sha256((fixture_dir / name).read_bytes()).hexdigest() == item["sha256"]
zcash_dir = root / "tests/fixtures/zcash"
zcash_manifest = json.loads((zcash_dir / "manifest.json").read_text())
for name, item in zcash_manifest["fixtures"].items():
    assert hashlib.sha256((zcash_dir / name).read_bytes()).hexdigest() == item["file_sha256"]
for upstream in ("librustzcash", "zebra"):
    source = zcash_manifest["sources"][f"license_{upstream}"]
    assert hashlib.sha256((zcash_dir / f"LICENSE-MIT-{upstream}").read_bytes()).hexdigest() == source["source_sha256"]
print(f"Verifier/TLS/parser guard passed ({host}): exact pins and fixture hashes; offline verifier has no fetch/override feature or known network client; reviewed Ring-only TLS and decoding-only Zcash features.")
