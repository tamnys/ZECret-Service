"""Verify the pinned QVL has no collateral-fetch/override feature in this build."""
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
visit(qvl["id"])
# Feature control is the primary invariant. These are the upstream fetcher's
# known clients/transports/resolvers, checked transitively as a regression guard.
forbidden = {"reqwest", "hyper", "hyper-util", "hickory-resolver", "hickory-proto", "tokio", "ureq"}
assert not (forbidden & {packages[p]["name"] for p in seen})
fixture_dir = root / "tests/fixtures/dcap"
provenance = json.loads((fixture_dir / "provenance.json").read_text())
for name, item in provenance["files"].items():
    assert hashlib.sha256((fixture_dir / name).read_bytes()).hexdigest() == item["sha256"]
print(f"Offline QVL guard passed ({host}): exact package/checksums; no fetch or dangerous override feature; no known network client in its native dependency graph.")
