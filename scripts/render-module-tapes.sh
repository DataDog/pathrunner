#!/usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.

set -euo pipefail

# render-module-tapes.sh — render a "use <id> → show payloads" GIF for every
# registered exploit module (or a filtered subset).
#
# Each GIF shows the REPL workflow of selecting a module and browsing its
# compatible payloads — AWS-free and credential-free, run through the docs
# sandbox against synthetic fixtures.
#
# GIFs are written to docs/reference/gifs/modules/<id>.gif.
# Tape files are generated on the fly into a temp directory and cleaned up after
# rendering — only the rendered GIFs are committed.
#
# Usage:
#   ./scripts/render-module-tapes.sh                  # render all modules
#   ./scripts/render-module-tapes.sh lambda-001       # render one module by ID
#   ./scripts/render-module-tapes.sh lambda           # render all lambda-* modules
#   ./scripts/render-module-tapes.sh iam ec2 lambda   # render multiple services
#
# Requirements:
#   - vhs on PATH (https://github.com/charmbracelet/vhs)
#   - a built ./pathrunner binary (run 'make build' first)
#   - jq on PATH (for parsing the reference JSON)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REFERENCE_JSON="$PROJECT_DIR/docs/reference/pathrunner-reference.json"
GIFS_DIR="$PROJECT_DIR/docs/reference/gifs/modules"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

ok()   { echo -e "${GREEN}  ok${RESET}  $*"; }
warn() { echo -e "${YELLOW}  warn${RESET} $*"; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
cd "$PROJECT_DIR"

if ! command -v vhs >/dev/null 2>&1; then
    echo "error: vhs not found on PATH (install: brew install vhs)" >&2
    exit 1
fi
if [[ ! -x "./pathrunner" ]]; then
    echo "error: ./pathrunner not built — run 'make build' first" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq not found on PATH (install: brew install jq)" >&2
    exit 1
fi
if [[ ! -f "$REFERENCE_JSON" ]]; then
    echo "error: $REFERENCE_JSON not found — run 'make docs' first" >&2
    exit 1
fi

mkdir -p "$GIFS_DIR"

# ---------------------------------------------------------------------------
# Build the module ID list
# ---------------------------------------------------------------------------
all_ids=$(jq -r '.modules[].id' "$REFERENCE_JSON")

if [[ $# -eq 0 ]]; then
    # No args — render everything.
    module_ids="$all_ids"
else
    # Filter: each arg is either an exact ID (e.g. lambda-001) or a service
    # prefix (e.g. lambda), matched as a prefix against all IDs.
    module_ids=""
    for arg in "$@"; do
        matched=$(echo "$all_ids" | grep -E "^${arg}(-[0-9]+)?$" || true)
        if [[ -z "$matched" ]]; then
            echo "error: no modules match '${arg}'" >&2
            exit 1
        fi
        module_ids="${module_ids}${matched}"$'\n'
    done
    # Deduplicate while preserving order.
    module_ids=$(echo "$module_ids" | awk '!seen[$0]++' | grep -v '^$')
fi

total=$(echo "$module_ids" | grep -c .)
echo -e "\n${BOLD}Rendering ${total} module GIF(s) → docs/reference/gifs/modules/${RESET}\n"

# ---------------------------------------------------------------------------
# Temp directory for generated tape files (cleaned up on exit)
# ---------------------------------------------------------------------------
TAPE_TMP=$(mktemp -d)
cleanup() { rm -rf "$TAPE_TMP"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Render each module
# ---------------------------------------------------------------------------
count=0
failed=()

while IFS= read -r module_id; do
    [[ -z "$module_id" ]] && continue
    count=$((count + 1))

    tape_file="$TAPE_TMP/${module_id}.tape"
    # VHS Output directive requires a relative path (absolute paths with leading /
    # are not supported — VHS splits on / and misparses them as tokens).
    gif_relative="docs/reference/gifs/modules/${module_id}.gif"

    # Read cliSteps from the reference JSON and convert to tape commands.
    # We stop before "pathrunner exploit" — the sandbox has no real AWS credentials
    # so the exploit would fail. The code block on the site (from cliSteps JSON)
    # already documents the full workflow including exploit.
    cli_steps=$(jq -r --arg id "$module_id" \
        '.modules[] | select(.id == $id) | .cliSteps[] | select(. != "pathrunner exploit")' \
        "$REFERENCE_JSON")

    # Each cliStep is "pathrunner <command> [args]". Strip the "pathrunner " prefix
    # so it becomes a bare REPL command typed into the sandbox REPL session.
    tape_commands=""
    while IFS= read -r step; do
        [[ -z "$step" ]] && continue
        repl_cmd="${step#pathrunner }"
        tape_commands+="Type \"${repl_cmd}\""$'\n'
        tape_commands+="Enter"$'\n'
        tape_commands+="Sleep 2s"$'\n'
        tape_commands+=""$'\n'
    done <<< "$cli_steps"

    # Estimate a reasonable terminal height: 280px base + 40px per REPL command.
    step_count=$(echo "$cli_steps" | grep -c . || true)
    height=$(( 280 + step_count * 40 ))
    # Clamp to a sensible range (400–760).
    [[ $height -lt 400 ]] && height=400
    [[ $height -gt 760 ]] && height=760

    # Generate the tape for this module.
    cat > "$tape_file" <<TAPE
Output ${gif_relative}

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height ${height}
Set Padding 20
Set Theme "Dracula"

Type "./scripts/docs-sandbox.sh"
Enter
Sleep 2s

${tape_commands}Type "exit"
Enter
Sleep 1s
TAPE

    printf "  [%3d/%d] %s ... " "$count" "$total" "$module_id"
    if vhs "$tape_file" >/dev/null 2>&1; then
        echo -e "${GREEN}ok${RESET}"
    else
        echo -e "${YELLOW}FAILED${RESET}"
        failed+=("$module_id")
    fi

done <<< "$module_ids"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
succeeded=$((total - ${#failed[@]}))
echo -e "${BOLD}Done: ${succeeded}/${total} rendered to docs/reference/gifs/modules/${RESET}"

if [[ ${#failed[@]} -gt 0 ]]; then
    warn "Failed modules (re-run individually to see vhs output):"
    for id in "${failed[@]}"; do
        echo "    $id"
    done
    echo ""
    warn "To debug a single module:"
    echo "    vhs <(./scripts/gen-module-tape.sh <id>)"
fi

echo ""
echo "Stage the new GIFs with:"
echo "  git add docs/reference/gifs/modules/"
echo ""
