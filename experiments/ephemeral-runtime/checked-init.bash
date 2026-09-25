# Experimental replacement for the v0.5.9 init_script block only.
# Source at top level under dstack-prepare.sh's set -e; never in a conditional.
# Requires the POC's measured nonempty string hook. This is not a runtime guard.
INIT_SCRIPT_FILE=$(mktemp "$WORK_DIR/init-script.XXXXXX") || exit 1
if ! jq -e -j '.init_script | if type == "string" and length > 0 then . else error("nonempty init_script required") end' app-compose.json > "$INIT_SCRIPT_FILE"; then
	log "Init script extraction failed"
	exit 1
fi
log "Running init script"
dstack-util notify-host -e "boot.progress" -d "init-script" || true
source "$INIT_SCRIPT_FILE"
rm -f -- "$INIT_SCRIPT_FILE"
unset INIT_SCRIPT_FILE
