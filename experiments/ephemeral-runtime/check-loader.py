"""Local Bash/jq fault injection. No mounts, daemons, hardware or cloud calls."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
LOADER = Path(__file__).with_name("checked-init.bash").read_text()
HARNESS = r'''set -e
WORK_DIR=$PWD
log() { :; }
dstack-util() { :; }
mktemp() {
    if [ "$FAULT" = tempfile ]; then return 1; fi
    command mktemp "$@"
}
jq() {
    if [ "$FAULT" = empty_extraction ]; then return 137; fi
    if [ "$FAULT" = extraction ]; then
        printf '%s\n' 'printf "%s\n" UNCHECKED_PARTIAL_SCRIPT'
        return 137
    fi
    command jq "$@"
}
''' + LOADER + '\nprintf "ENV:%s\\n" "${HOOK_STATE-}"\nprintf "%s\\n" PREPARATION_CONTINUED\n'

cases = [
    ("normal", {"init_script": "HOOK_STATE=preserved; printf '%s\\n' HOOK_RAN\n\n"}, "", True),
    ("missing", {}, "", False),
    ("null", {"init_script": None}, "", False),
    ("empty", {"init_script": ""}, "", False),
    ("array", {"init_script": ["true"]}, "", False),
    ("number", {"init_script": 1}, "", False),
    ("malformed", b"{", "", False),
    ("tempfile_failure", {"init_script": "true"}, "tempfile", False),
    ("empty_extraction_failure", {"init_script": "true"}, "empty_extraction", False),
    ("partial_extraction_failure", {"init_script": "true"}, "extraction", False),
    ("hook_failure", {"init_script": "false"}, "", False),
    ("hook_failure_then_success", {"init_script": "false; printf '%s\\n' MASKED"}, "", False),
    ("hook_signal", {"init_script": 'kill -TERM "$BASHPID"'}, "", False),
]
with tempfile.TemporaryDirectory(dir=ROOT / ".codex-tmp") as temporary:
    directory = Path(temporary)
    for name, config, fault, expected in cases:
        (directory / "app-compose.json").write_bytes(
            config if isinstance(config, bytes) else json.dumps(config).encode()
        )
        result = subprocess.run(
            ["bash", "-s"], input=HARNESS, text=True, capture_output=True,
            cwd=directory, env={**os.environ, "FAULT": fault},
        )
        continued = "PREPARATION_CONTINUED" in result.stdout.splitlines()
        assert (result.returncode == 0) == expected, (name, result.returncode)
        assert continued == expected, name
        assert "UNCHECKED_PARTIAL_SCRIPT" not in result.stdout, name
        assert "MASKED" not in result.stdout, name
        if expected:
            assert "HOOK_RAN" in result.stdout.splitlines()
            assert "ENV:preserved" in result.stdout.splitlines()
        print(json.dumps({"case": name, "exit": result.returncode, "continued": continued}))

    # Explicitly demonstrate the boundary: trusted hook code can exit the shell
    # successfully before preparation finishes. Loader exit status is not readiness.
    (directory / "app-compose.json").write_text(json.dumps({"init_script": "exit 0"}))
    result = subprocess.run(
        ["bash", "-s"], input=HARNESS, text=True, capture_output=True,
        cwd=directory, env={**os.environ, "FAULT": ""},
    )
    assert result.returncode == 0 and "PREPARATION_CONTINUED" not in result.stdout
    print(json.dumps({"case": "exit_zero_is_not_readiness", "exit": 0, "continued": False,
                      "runtime_guard_required": True, "private_accepted": False}))
