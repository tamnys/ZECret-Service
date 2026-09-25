"""Local CLI contract checks. No cloud calls and no live query material."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/zrpc"

def run(*args, data=None, success=True):
    proc = subprocess.run([str(BIN), *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
    assert (proc.returncode == 0) == success, (args, proc.returncode)
    assert not proc.stderr
    return json.loads(proc.stdout)

assert run("doctor")["deployment_enabled"] is False
for args in [("verify",), ("verify", "--policy", "config/release-policy.example.json"), ("query",), ("query", "--stdin")]:
    report = run(*args, data=b"SYNTHETIC_PRIVATE_MARKER", success=False)
    assert report["private_accepted"] is False
    assert report["query_sent"] is False
    assert report["serialized_rpc_bodies"] == 0
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(report)

for request in json.loads((ROOT / "tests/fixtures/requests.json").read_text()):
    report = run("query", "--simulate", "--stdin", data=json.dumps(request).encode())
    assert report["simulation"] and report["fixture_dispatched"]
    assert not report["query_sent"] and not report["private_accepted"]
for scenario in ["unknown-release", "wrong-key", "invalid-nonce", "stale-nonce", "altered-event-log", "expired-collateral", "unacceptable-tcb", "debug-image", "tor-unavailable"]:
    report = run("query", "--simulate", "--scenario", scenario, success=False)
    assert not report["fixture_dispatched"] and not report["query_sent"]
    assert report["error"]
report = run("query", "--simulate", "--stdin", data=b'{"jsonrpc":"2.0","id":1,"method":"getblockcount","viewing_key":"SYNTHETIC_SECRET_MARKER"}', success=False)
assert "SYNTHETIC_SECRET_MARKER" not in json.dumps(report)
assert not report["fixture_dispatched"]
plan = run("plan", "--input", "deploy/plan.fixture.json")
assert plan["projected_total_microusd"] == 40_844_160
assert plan["deployment_enabled"] is False
assert run("deploy", success=False)["deployment_enabled"] is False
assert run("teardown", "--simulate", "--manifest", "deploy/manifest.fixture.json")["provider_action_performed"] is False
manifest = json.loads((ROOT / "deploy/manifest.fixture.json").read_text())
assert run("watchdog", "--manifest", "deploy/manifest.fixture.json", "--now", str(manifest["deletion_deadline_unix_seconds"]), "--accrued-microusd", "0")["action"] == "delete_all"
print("CLI checks passed: fixtures, private refusal, negative scenarios, sanitized errors, exact plan, disabled deployment, deletion decisions.")

# The authentic upstream fixture has expired collateral at today's clock. A
# historical-time override is intentionally absent from the production CLI.
report = run("inspect-quote", "--quote", "tests/fixtures/dcap/tdx_quote.exact.bin", "--collateral", "tests/fixtures/dcap/tdx_quote_collateral.json", success=False)
assert report["hardware_authenticity"] == "rejected"
assert report["time_source"] == "system_clock"
assert not report["private_accepted"] and not report["network_used"] and not report["query_sent"]
assert report["issue"] == "cryptographic_or_validity_check_failed"
run("inspect-quote", "--quote", "tests/fixtures/dcap/tdx_quote.exact.bin", "--collateral", "tests/fixtures/dcap/tdx_quote_collateral.json", "--time", "1752919234", success=False)
print("Offline inspection CLI checks passed: expired evidence rejected; no historical-time override.")
