#!/usr/bin/env bash
set -euo pipefail

# check-sso.sh — Verify that AWS profiles are alive before running commands that
# need them. Both pathfinding-labs and (typically) pathrunner's attacker identity
# use short-term SSO profiles that expire silently; catching this up front is
# far cheaper than watching a 3-minute `plabs apply` die halfway through.
#
# Usage:
#   ./scripts/check-sso.sh check <profile> [<profile>...]  # probe specific profiles
#   ./scripts/check-sso.sh plabs                           # probe all plabs-configured profiles
#   ./scripts/check-sso.sh preflight [--attacker <name>]   # plabs + optional pathrunner attacker
#
# Exit codes:
#   0  all profiles are alive
#   1  usage error
#   2  one or more profiles are expired or broken (details on stderr/stdout)
#
# Env:
#   PLABS_CONFIG (default: $HOME/.plabs/plabs.yaml)

PLABS_CONFIG="${PLABS_CONFIG:-${HOME}/.plabs/plabs.yaml}"

# -----------------------------------------------------------------------------
# Core probe
# -----------------------------------------------------------------------------

# check_profile <name>
#   Returns 0 if `aws sts get-caller-identity --profile <name>` succeeds.
#   Prints a one-line status per profile.
check_profile() {
  local profile="$1"
  local out rc arn

  # -f fails on HTTP errors for the sso token endpoint; we rely on the CLI
  # itself to return non-zero on token failure.
  if out=$(aws sts get-caller-identity --profile "$profile" --output json 2>&1); then
    arn=$(echo "$out" | jq -r '.Arn // "(no arn)"')
    printf '  ok    %-40s %s\n' "$profile" "$arn"
    return 0
  fi

  rc=$?
  local reason="unknown error (aws cli rc=$rc)"
  # Match the CLI's messaging for expired SSO sessions vs. other failures.
  if echo "$out" | grep -qiE 'sso session .* expired|token has expired|error loading sso token|refreshwithtoken failed'; then
    reason="EXPIRED — run: aws sso login --profile $profile"
  elif echo "$out" | grep -qiE 'could not connect to the endpoint url|unable to locate credentials|profile .* not found'; then
    reason="broken: $(echo "$out" | head -1 | tr -d '\r')"
  else
    reason="$(echo "$out" | head -1 | tr -d '\r')"
  fi
  printf '  FAIL  %-40s %s\n' "$profile" "$reason" >&2
  return 1
}

# -----------------------------------------------------------------------------
# Discovery helpers
# -----------------------------------------------------------------------------

plabs_active_workspace() {
  # Print the active plabs workspace name (default "default").
  if [ ! -f "$PLABS_CONFIG" ]; then
    echo "default"
    return 0
  fi
  yq '.active_workspace // "default"' "$PLABS_CONFIG"
}

plabs_profiles() {
  # Print the list of AWS profiles for plabs' active workspace, one per line.
  # Only accounts whose profile is actually set are returned (skips unset ones).
  if [ ! -f "$PLABS_CONFIG" ]; then
    echo "check-sso: plabs config not found at $PLABS_CONFIG" >&2
    return 1
  fi
  if ! command -v yq >/dev/null 2>&1; then
    echo "check-sso: yq is required to read plabs config; brew install yq" >&2
    return 1
  fi
  # yq we're using is mikefarah (Go); it has no --arg, so interpolate the
  # workspace name directly. Names come from the config itself, not user args.
  local active
  active=$(plabs_active_workspace)
  yq ".workspaces.${active}.aws
        | to_entries[]
        | select(.value.profile != null and .value.profile != \"\")
        | .value.profile" "$PLABS_CONFIG" | sort -u
}

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------

cmd_check() {
  if [ "$#" -lt 1 ]; then
    echo "usage: check-sso.sh check <profile> [<profile>...]" >&2
    exit 1
  fi
  local fails=0
  echo "AWS SSO profile check:"
  for p in "$@"; do
    check_profile "$p" || fails=$((fails + 1))
  done
  [ "$fails" -eq 0 ] || exit 2
}

cmd_plabs() {
  echo "plabs profiles (workspace: $(plabs_active_workspace 2>/dev/null || echo unknown)):"
  local profiles
  profiles=$(plabs_profiles)
  if [ -z "$profiles" ]; then
    echo "  (no profiles configured — has plabs init been run?)" >&2
    exit 2
  fi
  local fails=0
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    check_profile "$p" || fails=$((fails + 1))
  done <<< "$profiles"
  [ "$fails" -eq 0 ] || exit 2
}

cmd_preflight() {
  # Combined check for what the batch-modules workflow (and a manual create-module
  # session) needs alive before starting work.
  local attacker_profile=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --attacker)
        [ "$#" -ge 2 ] || { echo "--attacker needs a profile name" >&2; exit 1; }
        attacker_profile="$2"
        shift 2 ;;
      *)
        echo "unknown flag: $1" >&2; exit 1 ;;
    esac
  done

  local fails=0

  echo "── preflight: plabs profiles ──"
  local profiles
  profiles=$(plabs_profiles 2>/dev/null || true)
  if [ -z "$profiles" ]; then
    echo "  (no plabs profiles configured; skipping)"
  else
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      check_profile "$p" || fails=$((fails + 1))
    done <<< "$profiles"
  fi

  if [ -n "$attacker_profile" ]; then
    echo "── preflight: pathrunner attacker profile ──"
    check_profile "$attacker_profile" || fails=$((fails + 1))
  fi

  echo
  if [ "$fails" -eq 0 ]; then
    echo "preflight: all profiles alive"
    return 0
  fi
  echo "preflight: $fails profile(s) need attention. Refresh SSO logins and re-run." >&2
  exit 2
}

# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

if [ "$#" -lt 1 ]; then
  cat >&2 <<EOF
usage: $(basename "$0") <command> [args]

Commands:
  check <profile>...             Probe one or more specific profiles
  plabs                          Probe all AWS profiles configured for plabs' active workspace
  preflight [--attacker <name>]  plabs profiles + optional pathrunner attacker profile

Env:
  PLABS_CONFIG=$PLABS_CONFIG

Exit codes:
  0  all alive
  2  one or more expired/broken
EOF
  exit 1
fi

cmd="$1"
shift
case "$cmd" in
  check)      cmd_check "$@" ;;
  plabs)      cmd_plabs ;;
  preflight)  cmd_preflight "$@" ;;
  *)
    echo "unknown command: $cmd" >&2
    exit 1 ;;
esac
