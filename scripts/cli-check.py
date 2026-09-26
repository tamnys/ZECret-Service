"""Local CLI contract checks. No cloud calls and no live query material."""
import json
import subprocess
import tempfile
import time
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
for args in [("lifecycle",), ("lifecycle", "delete-tracked"), ("lifecycle", "retry-tracked"), ("lifecycle", "initialize"),
             ("lifecycle", "observe"), ("lifecycle", "observe", "--api-key", "SYNTHETIC_CREDENTIAL_MARKER"),
             ("lifecycle", "reconcile"), ("lifecycle", "reconcile", "--api-key", "SYNTHETIC_CREDENTIAL_MARKER")]:
    report = run(*args, success=False)
    assert not report["private_accepted"] and not report["query_sent"] and not report["deployment_enabled"]
    assert "SYNTHETIC_CREDENTIAL_MARKER" not in json.dumps(report)
print("Provider observation CLI checks passed: explicit help, incomplete input and unsupported mutations rejected.")

# Real deletion entrypoints must be selected explicitly with an exact target
# and generation. Retry also requires the prior intent generation. These parser
# and unavailable-file paths perform no HTTP I/O.
for command in ("delete-tracked", "retry-tracked"):
    help_result = subprocess.run([str(BIN), "lifecycle", command, "--help"], capture_output=True, cwd=ROOT)
    assert help_result.returncode == 0 and not help_result.stderr
    assert b"REAL provider deletion" in help_result.stdout and b"--expected-generation" in help_result.stdout
    if command == "retry-tracked":
        assert b"--prior-intent-generation" in help_result.stdout and b"no automatic retry" in help_result.stdout
with tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp") as temporary:
    directory = Path(temporary)
    delete_args = ["lifecycle", "delete-tracked", "--original-binding", str(directory / "absent-original.json"),
                   "--expected-generation", "0", "--cvm-id", "SYNTHETIC_CVM",
                   "--api-key-file", str(directory / "absent-key"), "--trust-root", str(directory / "absent-root.der"),
                   "--invocation-budget-ms", "1", "--max-response-bytes", "1", "--max-input-file-bytes", "1"]
    retry_args = delete_args.copy()
    retry_args[1] = "retry-tracked"
    retry_args.extend(["--prior-intent-generation", "1"])
    for base in (delete_args, retry_args):
        for args in [base, *[base + [flag, "SYNTHETIC_CREDENTIAL_MARKER"] for flag in
                            ("--api-key", "--endpoint", "--now", "--retry", "--automatic", "--retry-count",
                             "--readback", "--evidence", "--initialize", "--simulate")]]:
            report = run(*args, success=False)
            assert not report["private_accepted"] and not report["query_sent"] and not report["deployment_enabled"]
            assert "SYNTHETIC_CREDENTIAL_MARKER" not in json.dumps(report)
    for args in (retry_args[:-2], retry_args[:-1] + ["0"], delete_args + ["--prior-intent-generation", "1"]):
        report = run(*args, success=False)
        assert not report["private_accepted"] and not report["query_sent"] and not report["deployment_enabled"]
    assert not list(directory.iterdir())
print("Tracked deletion CLI checks passed: explicit first/retry selection, required prior intent, sanitized refusal, no live provider calls.")

# Prospective local bookkeeping uses actual process time and caller assertions;
# no provider credentials or network configuration exist on this command path.
help_result = subprocess.run([str(BIN), "lifecycle", "ledger", "--help"], capture_output=True, cwd=ROOT)
assert help_result.returncode == 0 and not help_result.stderr
assert b"discard-draft" in help_result.stdout and b"no network request" in help_result.stdout
with tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp") as temporary:
    directory = Path(temporary)
    original, store = directory / "original.json", directory / "store"
    deadline = int(time.time()) + 168 * 3600  # Design's maximum, used only in this local fixture.
    init = ("lifecycle", "ledger", "init", "--original-binding", str(original), "--store-directory", str(store),
            "--experiment-id", "SYNTHETIC_CLI_ONLY", "--workspace-id", "SYNTHETIC_WORKSPACE",
            "--deletion-deadline", str(deadline), "--initial-cost-microusd", "17")
    report = run(*init)
    assert report["inspection"]["reference"]["generation"] == 0
    binding = report["inspection"]["ledger"]["binding"]
    assert binding["deletion_deadline_unix_seconds"] == deadline
    assert binding["total_ceiling_microusd"] == 50_000_000
    assert binding["delete_threshold_microusd"] == 45_000_000
    run(*init, success=False)  # Never overwrite or silently resume initialization.
    common = ("--original-binding", str(original))
    attempt = ("lifecycle", "ledger", "record-attempt", *common, "--expected-generation", "0", "--attempt-id", "first")
    report = run(*attempt)
    assert report["inspection"]["reference"]["generation"] == 1
    run(*attempt, success=False)
    created = int(time.time())
    track = ("lifecycle", "ledger", "record-cvm", *common, "--expected-generation", "1", "--attempt-id", "first",
             "--cvm-id", "SYNTHETIC_CVM", "--app-id", "SYNTHETIC_APP", "--instance-id", "SYNTHETIC_INSTANCE",
             "--created-at", str(created), "--compute-and-disk-microusd-per-hour", "243120")
    report = run(*track)
    assert report["inspection"]["reference"]["generation"] == 2
    assert report["inspection"]["ledger"]["resources"]["SYNTHETIC_CVM"]["cvm"]["created_at_unix_seconds"] == created
    assert report["inspection"]["ledger"]["binding"] == binding
    for field in ("provider_authenticated", "network_used", "provider_mutations_performed", "private_accepted",
                  "query_sent", "deployment_enabled", "deletion_retry_authorized", "billing_reconciled", "cleanup_complete"):
        assert report[field] is False
    assert report["operator_assertions_only"] is True
    def retained_bytes():
        return {str(path): path.read_bytes() for path in directory.rglob("*") if path.is_file()}
    before = retained_bytes()
    inspected = run("lifecycle", "ledger", "inspect", *common)
    assert inspected["inspection"]["reference"]["generation"] == 2
    assert retained_bytes() == before
    pending = store / "pending.json"
    # Even a complete-looking draft cannot be promoted by recovery.
    pending.write_bytes(Path(report["inspection"]["reference"]["snapshot_path"]).read_bytes())
    inspected = run("lifecycle", "ledger", "inspect", *common)
    assert inspected["inspection"]["has_uncommitted_draft"] is True
    run("lifecycle", "ledger", "discard-draft", *common, "--expected-generation", "1", success=False)
    assert pending.exists()
    recovered = run("lifecycle", "ledger", "discard-draft", *common, "--expected-generation", "2")
    assert recovered["pending_draft_discarded"] is True
    assert recovered["inspection"]["reference"]["generation"] == 2
    assert not recovered["inspection"]["has_uncommitted_draft"]
    assert retained_bytes() == before
    for flag in ("--now", "--started-at", "--reset", "--api-key", "--ledger-json"):
        failed = run("lifecycle", "ledger", "inspect", *common, flag, "SENSITIVE_MARKER", success=False)
        assert "SENSITIVE_MARKER" not in json.dumps(failed)
        assert retained_bytes() == before
print("Local ledger CLI checks passed: create-new setup, generation-bound recording, read-only inspection and discard-only recovery.")

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
