#!/usr/bin/env python3
"""Local synthetic CLI contract checks. No network, hardware or release approval."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug/zrpc"
BLOCK = {"height": 42, "hash": "a" * 64}


def query(method, params, expected=None):
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    if expected is not None:
        request["expected_block"] = expected
    run = subprocess.run([str(CLI), "query", "--simulate", "--stdin"],
                         input=json.dumps(request), text=True, capture_output=True)
    report = json.loads(run.stdout)
    assert report["simulation"] is True and report["private_accepted"] is False
    assert report["query_sent"] is False
    return run.returncode, report


for method, params in [
    ("getblockchaininfo", []), ("getblockcount", []),
    ("getaddressbalance", [{"addresses": ["tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3"]}]),
]:
    for expected in [None, BLOCK]:
        code, report = query(method, params, expected)
        assert code == 0 and report["error"] is None
        assert report["result"]["chain_context"] == BLOCK
    for expected in [{"height": 41, "hash": "a" * 64}, {"height": 42, "hash": "b" * 64}]:
        code, report = query(method, params, expected)
        assert code != 0 and report["error"]["code"] == "block_mismatch"
        assert report["result"] is None

code, report = query("getblockhash", [42], BLOCK)
assert code != 0 and report["error"]["code"] == "invalid_parameters"
print("Block-context CLI checks passed: actual context, exact match, older height, reorg hash, unsupported method; simulation only.")
