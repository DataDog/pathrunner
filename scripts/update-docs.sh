#!/usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.

set -euo pipefail

# update-docs.sh — regenerate the pathrunner reference JSON, re-render documentation
# GIFs, and stage all updated docs artifacts for commit.
#
# Run this after any change to commands, flags, modules, or payloads. It handles the
# mechanical steps; updating tape content (the Type lines) when CLI syntax changes is
# a manual or Claude-assisted step — do that before running this script.
#
# Usage:
#   ./scripts/update-docs.sh                    # regen JSON + render ALL tapes
#   ./scripts/update-docs.sh identity-switch    # regen JSON + render one tape by name
#   ./scripts/update-docs.sh identity-switch workspace-list   # render multiple tapes
#
# Requirements:
#   - vhs on PATH (https://github.com/charmbracelet/vhs) — only needed if rendering tapes
#   - a built ./pathrunner binary — run 'make build' first

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TAPES_DIR="$PROJECT_DIR/docs/reference/tapes"
GIFS_DIR="$PROJECT_DIR/docs/reference/gifs"
REFERENCE_JSON="$PROJECT_DIR/docs/reference/pathrunner-reference.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

step() { echo -e "\n${BOLD}==> $*${RESET}"; }
ok()   { echo -e "${GREEN}  ok${RESET}  $*"; }
warn() { echo -e "${YELLOW}  warn${RESET} $*"; }
fail() { echo -e "${RED}  fail${RESET} $*" >&2; exit 1; }

cd "$PROJECT_DIR"

# ---------------------------------------------------------------------------
# Step 1: Regenerate the JSON reference
# ---------------------------------------------------------------------------
step "Regenerating docs reference (make docs)"

if [[ ! -x "./pathrunner" ]]; then
    warn "pathrunner binary not found — running make build first"
    make build
fi

make docs

# Show a summary of what changed in the JSON so you know which tapes may need editing.
if git diff --quiet "$REFERENCE_JSON" 2>/dev/null; then
    ok "docs/reference/pathrunner-reference.json — no changes"
else
    echo ""
    echo "  Changes to the reference JSON (commands/flags that changed):"
    # Show only the lines that changed, skipping context, trimmed for readability.
    git diff "$REFERENCE_JSON" \
        | grep '^[+-]' \
        | grep -v '^---\|^+++' \
        | grep -E '"name"|"path"|"usage"|"flags"' \
        | head -40 \
        | sed 's/^/    /'
    echo ""
    warn "Review the diff above — if any command name, flag, or subcommand changed,"
    warn "edit the matching tape(s) in docs/reference/tapes/ before the next step."
    echo ""
    read -r -p "  Press Enter when tape edits are done (or to skip tape rendering): " _
fi

# ---------------------------------------------------------------------------
# Step 2: Render tapes
# ---------------------------------------------------------------------------
step "Rendering documentation GIFs"

if ! command -v vhs >/dev/null 2>&1; then
    warn "vhs not found on PATH — skipping GIF rendering (install: brew install vhs)"
    warn "Run './scripts/render-docs-tapes.sh' manually when vhs is available."
else
    mkdir -p "$GIFS_DIR"

    if [[ $# -gt 0 ]]; then
        # Render only the named tapes.
        for name in "$@"; do
            tape="$TAPES_DIR/${name%.tape}.tape"   # accept with or without .tape suffix
            if [[ ! -f "$tape" ]]; then
                fail "tape not found: $tape"
            fi
            echo "  Rendering $(basename "$tape")..."
            vhs "$tape"
            ok "$(basename "$tape")"
        done
    else
        # Render every CI-safe tape.
        for tape in "$TAPES_DIR"/*.tape; do
            echo "  Rendering $(basename "$tape")..."
            vhs "$tape"
            ok "$(basename "$tape")"
        done
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: Stage all updated docs artifacts
# ---------------------------------------------------------------------------
step "Staging updated docs artifacts"

git add docs/reference/

staged=$(git diff --cached --name-only | grep '^docs/reference/' || true)
if [[ -z "$staged" ]]; then
    ok "Nothing new to stage in docs/reference/"
else
    echo "$staged" | sed 's/^/    staged: /'
fi

# ---------------------------------------------------------------------------
# Step 4: Reminder
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}Done.${RESET} Commit the staged changes, then after merging to main:"
echo ""
echo "  # From pathfinding.cloud/:"
echo "  make generate-pathrunner"
echo "  # (or: python scripts/generate-pathrunner-json.py --source-dir ../pathrunner)"
echo ""
echo "  This pulls the updated JSON + GIFs and emits the split per-entry files."
echo "  Commit the result and deploy."
echo ""
echo "Note: module GIFs (use + show payloads per exploit module) are rendered separately:"
echo "  make render-module-tapes            # all 81 modules (~15 min)"
echo "  make render-module-tapes MODULE=lambda   # one service"
echo ""
