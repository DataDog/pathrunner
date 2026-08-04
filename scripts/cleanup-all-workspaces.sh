#!/usr/bin/env bash
# Run workspace cleanup for every pathrunner workspace.
# Switches into each workspace, runs cleanup --all --yes, then moves on.

set -euo pipefail

SESSIONS_DIR="${HOME}/.pathrunner/sessions"
PATHRUNNER="$(dirname "$0")/../pathrunner"

if [[ ! -f "$PATHRUNNER" ]]; then
  echo "pathrunner binary not found at $PATHRUNNER — run 'make build' first"
  exit 1
fi

# Collect workspace names by stripping .json extension
workspaces=()
while IFS= read -r f; do
  name="$(basename "$f" .json)"
  workspaces+=("$name")
done < <(find "$SESSIONS_DIR" -maxdepth 1 -name "*.json" | sort)

if [[ ${#workspaces[@]} -eq 0 ]]; then
  echo "No workspaces found in $SESSIONS_DIR"
  exit 0
fi

echo "Found ${#workspaces[@]} workspace(s): ${workspaces[*]}"
echo

for ws in "${workspaces[@]}"; do
  echo "========================================="
  echo "Workspace: $ws"
  echo "========================================="

  # Switch into the workspace
  switch_out=$("$PATHRUNNER" workspace switch "$ws" 2>&1)
  echo "$switch_out"

  # Run cleanup (--all skips the resource selection prompt, --yes skips confirmation)
  "$PATHRUNNER" workspace cleanup --all --yes 2>&1
  echo
done

echo "All workspaces processed."
