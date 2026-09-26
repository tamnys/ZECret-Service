"""Local CLI contract checks. No cloud calls and no live query material."""
import json
import subprocess
import tempfile
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

# Provider observation commands have no implicit initialization, clock override,
# provider URL, mutation, or secret-on-argv option. These rejection paths need
# neither actual credentials nor a live provider.
help_result = subprocess.run([str(BIN), "lifecycle", "--help"], capture_output=True, cwd=ROOT)
assert help_result.returncode == 0 and not help_result.stderr
assert b"--original-binding" in help_result.stdout and b"--api-key-file" in help_result.stdout
assert b"observe|reconcile" in help_result.stdout and b"no deletion retry authority" in help_result.stdout
for args in [("lifecycle",), ("lifecycle", "delete-tracked"), ("lifecycle", "initialize"),
             ("lifecycle", "observe"), ("lifecycle", "observe", "--api-key", "SYNTHETIC_CREDENTIAL_MARKER"),
             ("lifecycle", "reconcile"), ("lifecycle", "reconcile", "--api-key", "SYNTHETIC_CREDENTIAL_MARKER")]:
    report = run(*args, success=False)
    assert not report["private_accepted"] and not report["query_sent"] and not report["deployment_enabled"]
    assert "SYNTHETIC_CREDENTIAL_MARKER" not in json.dumps(report)
print("Provider observation CLI checks passed: explicit help, incomplete input and unsupported mutations rejected.")

# The real deletion entrypoint must be selected explicitly with an exact target
# and generation. These parser and unavailable-file paths perform no HTTP I/O.
help_result = subprocess.run([str(BIN), "lifecycle", "delete-tracked", "--help"], capture_output=True, cwd=ROOT)
assert help_result.returncode == 0 and not help_result.stderr
assert b"REAL provider deletion" in help_result.stdout and b"--expected-generation" in help_result.stdout
with tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp") as temporary:
    directory = Path(temporary)
    delete_args = ["lifecycle", "delete-tracked", "--original-binding", str(directory / "absent-original.json"),
                   "--expected-generation", "0", "--cvm-id", "SYNTHETIC_CVM",
                   "--api-key-file", str(directory / "absent-key"), "--trust-root", str(directory / "absent-root.der"),
                   "--invocation-budget-ms", "1", "--max-response-bytes", "1", "--max-input-file-bytes", "1"]
    for args in [delete_args, *[delete_args + [flag, "SYNTHETIC_CREDENTIAL_MARKER"] for flag in
                               ("--api-key", "--endpoint", "--now", "--retry", "--initialize", "--simulate")]]:
        report = run(*args, success=False)
        assert not report["private_accepted"] and not report["query_sent"] and not report["deployment_enabled"]
        assert "SYNTHETIC_CREDENTIAL_MARKER" not in json.dumps(report)
    assert not list(directory.iterdir())
print("Tracked deletion CLI checks passed: explicit help, no implicit initialization, sanitized refusal, no live provider calls.")

# The authentic upstream fixture has expired collateral at today's clock. A
# historical-time override is intentionally absent from the production CLI.
report = run("inspect-quote", "--quote", "tests/fixtures/dcap/tdx_quote.exact.bin", "--collateral", "tests/fixtures/dcap/tdx_quote_collateral.json", success=False)
assert report["hardware_authenticity"] == "rejected"
assert report["time_source"] == "system_clock"
assert not report["private_accepted"] and not report["network_used"] and not report["query_sent"]
assert report["issue"] == "cryptographic_or_validity_check_failed"
run("inspect-quote", "--quote", "tests/fixtures/dcap/tdx_quote.exact.bin", "--collateral", "tests/fixtures/dcap/tdx_quote_collateral.json", "--time", "1752919234", success=False)
print("Offline inspection CLI checks passed: expired evidence rejected; no historical-time override.")

# Synthetic policy values are rejection-test inputs, never release measurements.
with tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp") as temporary:
    directory = Path(temporary)
    policy = {"schema_version": 1,
              **{key: "00" * 48 for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2")},
              **{key: "00" * 32 for key in ("os_image_hash", "compose_hash", "mr_kms")},
              **{key: "00" * 20 for key in ("app_id", "instance_id")},
              "storage_fs": "ext4", "key_provider": {"name": "kms", "id": "SYNTHETIC_ONLY"}}
    (directory / "policy.json").write_text(json.dumps(policy))
    (directory / "events.json").write_text("[]")
    (directory / "app-compose.json").write_text('{"synthetic":true}')
    args = ("inspect-workload", "--quote", "tests/fixtures/dcap/tdx_quote.exact.bin",
            "--collateral", "tests/fixtures/dcap/tdx_quote_collateral.json",
            "--event-log", str(directory / "events.json"),
            "--app-compose", str(directory / "app-compose.json"),
            "--policy", str(directory / "policy.json"))
    report = run(*args, success=False)
    assert report["operation"] == "offline_workload_inspection"
    assert report["hardware_authenticity"] == "rejected"
    assert report["runtime_event_integrity"] == report["workload_policy"] == "not_checked"
    assert report["policy_source"] == "explicit_local_input_not_release_approval"
    assert not report["private_accepted"] and not report["query_sent"] and not report["network_used"]
    run(*args, "--time", "1752919234", success=False)
    (directory / "policy.json").write_text('{"verified":true,"secret":"SYNTHETIC_PRIVATE_MARKER"}')
    report = run(*args, success=False)
    assert report["error"] == "workload policy rejected"
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(report)
print("Workload CLI checks passed: expired evidence cannot reach policy checks; malformed policy and time override reject.")
