#!/usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.

set -euo pipefail

# render-docs-tapes.sh — render the CI-safe documentation GIFs from the VHS tapes
# under docs/reference/tapes/. These tapes are either AWS-free (metadata commands)
# or run through scripts/docs-sandbox.sh against synthetic fixtures, so NONE of
# them need credentials, make AWS calls, or touch the operator's ~/.pathrunner.
#
# It does NOT render exploit / AWS-calling command GIFs — those are captured
# separately against a deployed pathfinding-lab via scripts/test-module.sh and
# redacted with pathfinding-labs/scripts/redact_transcripts.py. See
# docs/reference/tapes/README.md.
#
# Requirements:
#   - vhs on PATH            (https://github.com/charmbracelet/vhs)
#   - a built ./pathrunner   (run 'make build' first)
#
# Usage:
#   ./scripts/render-docs-tapes.sh            # render every CI-safe tape
#   ./scripts/render-docs-tapes.sh help.tape  # render a single tape by name

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TAPES_DIR="$PROJECT_DIR/docs/reference/tapes"
GIFS_DIR="$PROJECT_DIR/docs/reference/gifs"

if ! command -v vhs >/dev/null 2>&1; then
    echo "error: vhs not found on PATH (see https://github.com/charmbracelet/vhs)" >&2
    exit 1
fi
if [[ ! -x "$PROJECT_DIR/pathrunner" ]]; then
    echo "error: ./pathrunner not built (run 'make build' first)" >&2
    exit 1
fi

mkdir -p "$GIFS_DIR"
cd "$PROJECT_DIR"

if [[ $# -gt 0 ]]; then
    tapes=("$TAPES_DIR/$1")
else
    tapes=("$TAPES_DIR"/*.tape)
fi

for tape in "${tapes[@]}"; do
    echo "Rendering $(basename "$tape")..."
    vhs "$tape"
done

echo "Done. GIFs written to $GIFS_DIR"
