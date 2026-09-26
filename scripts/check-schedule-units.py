#!/usr/bin/env python3
"""Generate synthetic units and validate with systemd-analyze; never start them."""
import json
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/zrpc"
version = subprocess.run(["systemd-analyze", "--version"], capture_output=True, text=True, check=True)
major = int(version.stdout.splitlines()[0].split()[1])
if major < 257:
    raise SystemExit("systemd 257 or later is required to check the selected unit contract")
if not BIN.is_file():
    raise SystemExit("build zrpc-cli with cargo build --locked -p zrpc-cli before this check")
base = ROOT / ".codex-tmp"
base.mkdir(exist_ok=True)
directory = Path(tempfile.mkdtemp(prefix="schedule-units-", dir=base))


def run(*arguments):
    result = subprocess.run([str(BIN), *arguments], cwd=ROOT, capture_output=True, text=True, check=True)
    assert not result.stderr, result.stderr
    return json.loads(result.stdout)


# The extra punctuation exercises literal systemd argument encoding. Inputs are
# synthetic; missing provider files prevent live work even if mistakenly invoked.
original = directory / "original %n ${HOME} ' quote\".json"
experiment = "SYNTHETIC %n $HOME ; quoted\" \\ experiment"
run("lifecycle", "ledger", "init", "--original-binding", str(original),
    "--store-directory", str(directory / "ledger"), "--experiment-id", experiment,
    "--workspace-id", "SYNTHETIC_ONLY", "--initial-cost-microusd", "17",
    "--deletion-deadline", str(int(time.time()) + 168 * 3600))
before = {path: path.read_bytes() for path in directory.rglob("*") if path.is_file()}
output = directory / "bundle"
# Same arithmetic fixture as the unit tests; none is an operational default.
bundle = run("lifecycle", "export-watchdog", "--original-binding", str(original),
    "--experiment-id", experiment, "--api-key-file", str(directory / "absent key $HOME"),
    "--trust-root", str(directory / "absent root %n.der"),
    "--invocation-budget-ms", "3000", "--max-response-bytes", "1", "--max-input-file-bytes", "1",
    "--inventory-page-size", "30", "--usage-page-size", "500",
    "--max-inventory-records", "1", "--max-usage-records-per-app", "1",
    "--maximum-detection-interval-ms", "120000", "--deletion-latency-upper-bound-ms", "60000",
    "--scheduler-delay-allowance-ms", "60000", "--reconciliation-budget-ms", "1000",
    "--deletion-dispatch-budget-ms", "2000", "--fee-upper-bounds-microusd", "0",
    "--executable", str(BIN), "--service-user", "1000", "--unit-name", "synthetic-watchdog",
    "--process-runtime-bound-ms", "5000", "--manager-delay-allowance-ms", "1000",
    "--output-directory", str(output))
verification = subprocess.run(
    ["systemd-analyze", "verify", "--man=no", *(str(output / name) for name in sorted(bundle["files"]))],
    cwd=ROOT, capture_output=True, text=True,
)
(directory / "systemd-version.txt").write_text(version.stdout)
(directory / "systemd-verify.txt").write_text(verification.stdout + verification.stderr)
if verification.returncode or verification.stderr:
    raise SystemExit(f"systemd verification did not pass cleanly; inspect {directory / 'systemd-verify.txt'}")
assert all(path.read_bytes() == value for path, value in before.items())
assert json.loads((output / "manifest.json").read_text()) == bundle
assert bundle["jobs_installed"] is False and bundle["credentials_read"] is False
print(json.dumps({
    "mode": "synthetic_offline_unit_parser_check",
    "systemd_version": version.stdout.splitlines()[0],
    "artifact_directory": str(directory), "unit_files_verified": len(bundle["files"]),
    "ledger_unchanged": True, "jobs_started": False, "network_used": False,
    "timing_verified": False, "private_accepted": False,
}, indent=2))
