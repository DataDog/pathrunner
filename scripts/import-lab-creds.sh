#!/usr/bin/env bash
set -euo pipefail

# import-lab-creds.sh — Pull a deployed pathfinding-labs scenario's starting
# credentials via `plabs credentials` and register them in the pathrunner
# identity store, keyed by scenario ID.
#
# The lab starting credentials are IAM user access keys (static, don't expire
# on their own — different from the SSO profiles handled by check-sso.sh).
#
# Usage:
#   ./scripts/import-lab-creds.sh <scenario-id> [--switch]
#   ./scripts/import-lab-creds.sh batch <scenario-id> [<scenario-id>...]
#
# Idempotent: if an identity with the same name already exists, re-imports
# with fresh credentials (in case terraform recreated them) and switches
# to it only when --switch is passed.
#
# Env:
#   PLABS_DIR       (default: ../pathfinding-labs)
#   PATHRUNNER_BIN  (default: ./pathrunner)
#
# Exit codes:
#   0  success (import + optional switch)
#   1  usage error
#   3  plabs credentials fetch failed (scenario likely not deployed)
#   4  pathrunner identity add failed

PLABS_DIR="${PLABS_DIR:-../pathfinding-labs}"
PATHRUNNER_BIN="${PATHRUNNER_BIN:-./pathrunner}"

# -----------------------------------------------------------------------------
# Core import
# -----------------------------------------------------------------------------

import_one() {
  local scenario_id="$1"
  local do_switch="${2:-false}"

  echo "[creds] fetching for $scenario_id..."
  local creds_json
  if ! creds_json=$( (cd "$PLABS_DIR" && ./plabs credentials "$scenario_id" --format=json) 2>&1); then
    echo "[creds] FAIL: plabs credentials $scenario_id: $creds_json" >&2
    return 3
  fi

  local access_key secret_key session_token
  access_key=$(echo "$creds_json" | jq -r '.access_key_id // empty')
  secret_key=$(echo "$creds_json" | jq -r '.secret_access_key // empty')
  session_token=$(echo "$creds_json" | jq -r '.session_token // empty')

  if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
    echo "[creds] FAIL: plabs returned no access_key_id/secret_access_key for $scenario_id" >&2
    echo "$creds_json" >&2
    return 3
  fi

  echo "[creds] got ${access_key:0:12}... for $scenario_id"

  # Check if the identity already exists — pathrunner has no direct "get" so
  # we probe via list-then-grep. If present, we clear it before re-adding so
  # a re-provisioned lab (new keys) doesn't collide with stale entries.
  local existing
  existing=$("$PATHRUNNER_BIN" identity list 2>/dev/null | grep -E "^ *${scenario_id}\b" || true)
  if [ -n "$existing" ]; then
    echo "[creds] identity '$scenario_id' already exists — refreshing"
    # Clear the old one; ignore failure if it doesn't exist or is currently active.
    "$PATHRUNNER_BIN" identity clear "$scenario_id" >/dev/null 2>&1 || true
  fi

  local add_args=(--access "$access_key" --secret "$secret_key" --name "$scenario_id")
  [ -n "$session_token" ] && add_args+=(--token "$session_token")
  [ "$do_switch" = "true" ] && add_args+=(--switch)

  if ! "$PATHRUNNER_BIN" identity add "${add_args[@]}" 2>&1; then
    echo "[creds] FAIL: pathrunner identity add for $scenario_id" >&2
    return 4
  fi

  if [ "$do_switch" = "true" ]; then
    echo "[creds] imported and switched to identity: $scenario_id"
  else
    echo "[creds] imported identity: $scenario_id"
  fi
}

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------

cmd_import() {
  local scenario_id="$1"; shift
  local do_switch="false"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --switch) do_switch="true"; shift ;;
      *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
  done
  import_one "$scenario_id" "$do_switch"
}

cmd_batch() {
  if [ "$#" -lt 1 ]; then
    echo "usage: import-lab-creds.sh batch <scenario-id>..." >&2
    exit 1
  fi
  local fails=0
  for sid in "$@"; do
    if ! import_one "$sid" "false"; then
      fails=$((fails + 1))
    fi
  done
  if [ "$fails" -gt 0 ]; then
    echo "[creds] $fails scenario(s) failed to import" >&2
    exit 3
  fi
}

# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

if [ "$#" -lt 1 ]; then
  cat >&2 <<EOF
usage: $(basename "$0") <scenario-id> [--switch]
       $(basename "$0") batch <scenario-id>...

Env:
  PLABS_DIR=$PLABS_DIR
  PATHRUNNER_BIN=$PATHRUNNER_BIN
EOF
  exit 1
fi

case "$1" in
  batch)
    shift; cmd_batch "$@" ;;
  -h|--help)
    exec "$0" ;;  # falls into the usage above via no-args
  *)
    cmd_import "$@" ;;
esac
