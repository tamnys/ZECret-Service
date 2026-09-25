"""Derive a local source candidate; never install, boot or deploy it."""
import argparse
import hashlib
from pathlib import Path

EXPECTED_SHA256 = "1636030add2dfd5a85272a246939d7d1b472aa2a400e76b158dc39577a9c442a"
OLD = '''if [ $(jq 'has("init_script")' app-compose.json) == true ]; then
\tlog "Running init script"
\tdstack-util notify-host -e "boot.progress" -d "init-script" || true
\tsource <(jq -r '.init_script' app-compose.json)
fi
'''
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
original = args.source.read_bytes()
if hashlib.sha256(original).hexdigest() != EXPECTED_SHA256:
    parser.error("source does not match the pinned dstack v0.5.9 preparation script")
text = original.decode()
if text.count(OLD) != 1:
    parser.error("expected hook block is absent or ambiguous")
replacement = Path(__file__).with_name("checked-init.bash").read_text()
# Exclusive creation protects source and existing experiments from overwrite.
with args.output.open("x") as output:
    output.write(text.replace(OLD, replacement))
print("Experimental source created; no runtime policy or deployment approval.")
