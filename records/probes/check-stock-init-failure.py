"""Reproduce stock hook invocation semantics; never mount, boot or contact a CVM.

The Bash branch follows dstack 40eaf35e6b3f112998d01569f2a26110baab123b
basefiles/dstack-prepare.sh lines 282-288. jq is a fault-injection function.
Exit 137 is an injected process failure, not a reproduced kernel OOM event.
Passing this probe confirms the finding; it does not approve an init script.
"""
import json
import subprocess

SCRIPT = r'''set -e
FAILURE=$1
jq() {
    case "$*" in
    'has("init_script") app-compose.json')
        [ "$FAILURE" = condition ] && return 137
        printf '%s\n' true
        ;;
    '-r .init_script app-compose.json')
        [ "$FAILURE" = extraction ] && return 137
        printf '%s\n' "printf '%s\\n' HOOK_RAN"
        ;;
    '-r .runner app-compose.json')
        printf '%s\n' docker-compose
        ;;
    *) return 2 ;;
    esac
}
if [ $(jq 'has("init_script")' app-compose.json) == true ]; then
    source <(jq -r '.init_script' app-compose.json)
fi
RUNNER=$(jq -r '.runner' app-compose.json)
printf 'PREPARATION_CONTINUED:%s\n' "$RUNNER"
'''

for case in ("none", "condition", "extraction"):
    result = subprocess.run(
        ["bash", "-s", "--", case], input=SCRIPT, capture_output=True, text=True
    )
    hook_ran = "HOOK_RAN" in result.stdout.splitlines()
    continued = "PREPARATION_CONTINUED:docker-compose" in result.stdout.splitlines()
    assert result.returncode == 0 and continued
    assert hook_ran == (case == "none")
    print(json.dumps({
        "injected_failure": case,
        "preparation_exit": result.returncode,
        "hook_ran": hook_ran,
        "preparation_continued": continued,
    }))

# Current upstream next, 0fb3b24bbd94c18d4af2900b41cd82bcd1c0c284,
# os/common/rootfs/dstack-prepare.sh lines 315-334 uses mapfile instead.
# Reproduce the producer failure and resulting empty script list; this is not
# an execution of the full boot script or proof of an account's deployed image.
NEXT_SCRIPT = r'''set -e
jq() { return 137; }
mapfile -t init_scripts < <(
    jq -r '
        .init_script?
        | if type == "array" then .[] elif type == "string" then . else empty end
        | @base64
    ' app-compose.json
)
if ((${#init_scripts[@]} > 0)); then
    printf '%s\n' HOOK_LOOP_ENTERED
fi
printf 'PREPARATION_CONTINUED:%s\n' "${#init_scripts[@]}"
'''
result = subprocess.run(["bash", "-s"], input=NEXT_SCRIPT, capture_output=True, text=True)
assert result.returncode == 0
assert result.stdout.splitlines() == ["PREPARATION_CONTINUED:0"]
print(json.dumps({
    "upstream_next_injected_failure": "mapfile_producer",
    "preparation_exit": result.returncode,
    "hook_loop_entered": False,
    "preparation_continued": True,
}))
