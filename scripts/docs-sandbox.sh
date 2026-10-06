#!/usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.

set -euo pipefail

# docs-sandbox.sh — run a pathrunner command (or drop into the REPL) against
# synthetic documentation fixtures in a throwaway HOME, so documentation output
# never contains real credentials, accounts, or the operator's ~/.pathrunner state.
#
# It seeds a temp HOME from docs/fixtures/ and sets PATHRUNNER_WORKSPACE=demo so
# the "demo" workspace fixture is loaded. The operator's real ~/.pathrunner is
# never touched (this relies on pathrunner resolving all state from $HOME, the
# same seam the integration tests use via t.TempDir()).
#
# Usage:
#   ./scripts/docs-sandbox.sh [pathrunner-args...]
#
# Examples:
#   ./scripts/docs-sandbox.sh identity list
#   ./scripts/docs-sandbox.sh show options
#   ./scripts/docs-sandbox.sh                 # REPL in the sandbox
#
# Environment:
#   PATHRUNNER_BIN   path to the pathrunner binary (default: ./pathrunner)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$PROJECT_DIR/docs/fixtures"
PATHRUNNER_BIN="${PATHRUNNER_BIN:-$PROJECT_DIR/pathrunner}"

if [[ ! -x "$PATHRUNNER_BIN" ]]; then
    echo "error: pathrunner binary not found at $PATHRUNNER_BIN (run 'make build' first)" >&2
    exit 1
fi

if [[ ! -d "$FIXTURES_DIR" ]]; then
    echo "error: fixtures dir not found at $FIXTURES_DIR" >&2
    exit 1
fi

# Throwaway HOME, cleaned up on exit.
SANDBOX_HOME="$(mktemp -d)"
cleanup() { rm -rf "$SANDBOX_HOME"; }
trap cleanup EXIT

mkdir -p "$SANDBOX_HOME/.pathrunner/sessions"
cp "$FIXTURES_DIR"/sessions/*.json "$SANDBOX_HOME/.pathrunner/sessions/"
if [[ -f "$FIXTURES_DIR/attacker_identity.json" ]]; then
    cp "$FIXTURES_DIR/attacker_identity.json" "$SANDBOX_HOME/.pathrunner/attacker_identity.json"
fi

HOME="$SANDBOX_HOME" PATHRUNNER_WORKSPACE="demo" "$PATHRUNNER_BIN" "$@"
