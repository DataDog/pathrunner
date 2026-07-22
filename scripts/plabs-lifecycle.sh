#!/usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.

set -euo pipefail

# plabs-lifecycle.sh — Enable/disable pathfinding-labs scenarios while serializing
# terraform applies through a shared lock.
#
# Concurrent agents (batch module creation, workflows) can call this safely — the
# lock ensures at most one `plabs apply` runs at a time. Read-only commands
# (status, lock-info) do NOT take the lock.
#
# Usage:
#   ./scripts/plabs-lifecycle.sh enable  <scenario-id>...
#   ./scripts/plabs-lifecycle.sh disable <scenario-id>...
#   ./scripts/plabs-lifecycle.sh swap    [--add <id>]... [--remove <id>]...
#   ./scripts/plabs-lifecycle.sh status
#   ./scripts/plabs-lifecycle.sh lock-info
#   ./scripts/plabs-lifecycle.sh force-unlock
#
# Global env vars:
#   PLABS_DIR             (default: ../pathfinding-labs)   Path to labs repo
#   PLABS_LOCK_DIR        (default: /tmp/pathrunner-plabs.lock.d) Lock directory
#   PLABS_LOCK_TIMEOUT    (default: 3600)   Max seconds to wait for lock
#   PLABS_LOCK_LEASE_MAX  (default: 1800)   Reclaim stale lock after N seconds
#                                            when owner PID is gone
#
# Exit codes:
#   0  success
#   1  usage error
#   2  lock acquisition timed out
#   3  plabs command failed

PLABS_DIR="${PLABS_DIR:-../pathfinding-labs}"
PLABS_LOCK_DIR="${PLABS_LOCK_DIR:-/tmp/pathrunner-plabs.lock.d}"
PLABS_LOCK_TIMEOUT="${PLABS_LOCK_TIMEOUT:-3600}"
PLABS_LOCK_LEASE_MAX="${PLABS_LOCK_LEASE_MAX:-1800}"

# SSO / credential automation. Set SKIP_SSO_CHECK=1 to bypass the preflight
# (e.g., when running against a mocked provider). Set SKIP_CREDS_IMPORT=1 to
# skip the automatic pathrunner identity import after enable/swap.
SKIP_SSO_CHECK="${SKIP_SSO_CHECK:-0}"
SKIP_CREDS_IMPORT="${SKIP_CREDS_IMPORT:-0}"
PATHRUNNER_BIN="${PATHRUNNER_BIN:-./pathrunner}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------------
# Lock primitives — atomic-mkdir with PID + timestamp lease
# -----------------------------------------------------------------------------

lock_owner_info() {
  # Prints "pid|acquired_epoch|hostname|command" if lock is held; empty otherwise.
  [ -f "$PLABS_LOCK_DIR/owner" ] || return 0
  cat "$PLABS_LOCK_DIR/owner" 2>/dev/null || true
}

lock_is_stale() {
  # A lock is considered stale if:
  #   - It's older than PLABS_LOCK_LEASE_MAX seconds, AND
  #   - Its recorded PID is not alive on this host
  local info pid acquired age now
  info=$(lock_owner_info)
  [ -n "$info" ] || return 1  # No owner file → not stale (probably in-flight acquire)
  pid=$(echo "$info" | cut -d'|' -f1)
  acquired=$(echo "$info" | cut -d'|' -f2)
  now=$(date +%s)
  age=$((now - acquired))
  [ "$age" -gt "$PLABS_LOCK_LEASE_MAX" ] || return 1
  # Age exceeded — check if PID is still alive
  if kill -0 "$pid" 2>/dev/null; then
    return 1  # Still running, not stale
  fi
  return 0
}

acquire_lock() {
  local purpose="${1:-unspecified}"
  local deadline=$(($(date +%s) + PLABS_LOCK_TIMEOUT))
  local waited=0
  local info

  while true; do
    if mkdir "$PLABS_LOCK_DIR" 2>/dev/null; then
      printf '%s|%s|%s|%s\n' "$$" "$(date +%s)" "$(hostname)" "$purpose" > "$PLABS_LOCK_DIR/owner"
      # Ensure the lock is released on exit / interrupt
      trap 'release_lock' EXIT INT TERM
      if [ "$waited" -gt 0 ]; then
        echo "[lock] acquired after ${waited}s wait (purpose: $purpose)"
      else
        echo "[lock] acquired (purpose: $purpose)"
      fi
      return 0
    fi

    # Lock is held; check for staleness
    if lock_is_stale; then
      info=$(lock_owner_info)
      echo "[lock] reclaiming stale lock (owner gone): $info" >&2
      rm -rf "$PLABS_LOCK_DIR"
      continue
    fi

    if [ "$(date +%s)" -ge "$deadline" ]; then
      info=$(lock_owner_info)
      echo "[lock] timeout after ${PLABS_LOCK_TIMEOUT}s; held by: $info" >&2
      return 2
    fi

    if [ "$waited" -eq 0 ]; then
      info=$(lock_owner_info)
      echo "[lock] waiting; currently held by: $info"
    fi
    sleep 3
    waited=$((waited + 3))
  done
}

release_lock() {
  # Only release if we own it (owner file records our PID)
  local info pid
  info=$(lock_owner_info)
  if [ -n "$info" ]; then
    pid=$(echo "$info" | cut -d'|' -f1)
    if [ "$pid" = "$$" ]; then
      rm -rf "$PLABS_LOCK_DIR"
      echo "[lock] released"
    fi
  fi
  trap - EXIT INT TERM
}

# -----------------------------------------------------------------------------
# plabs wrappers
# -----------------------------------------------------------------------------

run_plabs() {
  # Run plabs from the labs directory without changing our own cwd.
  (cd "$PLABS_DIR" && ./plabs "$@")
}

preflight_sso() {
  # Fail fast if any plabs profile is expired before we take the lock.
  # A 5-minute `plabs apply` dying halfway because SSO expired is much worse
  # than a 1-second STS probe at the start.
  if [ "$SKIP_SSO_CHECK" = "1" ]; then
    return 0
  fi
  if [ ! -x "$SCRIPT_DIR/check-sso.sh" ]; then
    echo "[preflight] check-sso.sh not found or not executable; skipping SSO check" >&2
    return 0
  fi
  if ! "$SCRIPT_DIR/check-sso.sh" plabs >/dev/null 2>&1; then
    echo "[preflight] SSO check failed — one or more plabs profiles are expired. Details:" >&2
    "$SCRIPT_DIR/check-sso.sh" plabs || true
    echo >&2
    echo "[preflight] refresh with 'aws sso login --profile <name>' and retry" >&2
    exit 4
  fi
}

import_creds_for() {
  # Best-effort import of a scenario's starting creds into pathrunner's
  # identity store. Non-fatal — the lab is already deployed even if this fails.
  if [ "$SKIP_CREDS_IMPORT" = "1" ]; then
    return 0
  fi
  if [ ! -x "$SCRIPT_DIR/import-lab-creds.sh" ]; then
    return 0
  fi
  local sid="$1"
  if ! "$SCRIPT_DIR/import-lab-creds.sh" "$sid"; then
    echo "[creds] warning: could not import creds for $sid; run './scripts/import-lab-creds.sh $sid' manually" >&2
  fi
}

cmd_status() {
  run_plabs status
}

cmd_lock_info() {
  if [ ! -d "$PLABS_LOCK_DIR" ]; then
    echo "unlocked"
    return 0
  fi
  local info
  info=$(lock_owner_info)
  if [ -z "$info" ]; then
    echo "locked (no owner info — mid-acquire or corrupted)"
    return 0
  fi
  local pid acquired host purpose now age
  pid=$(echo "$info" | cut -d'|' -f1)
  acquired=$(echo "$info" | cut -d'|' -f2)
  host=$(echo "$info" | cut -d'|' -f3)
  purpose=$(echo "$info" | cut -d'|' -f4-)
  now=$(date +%s)
  age=$((now - acquired))
  local alive="unknown"
  if kill -0 "$pid" 2>/dev/null; then
    alive="alive"
  else
    alive="dead"
  fi
  printf 'locked\n  pid: %s (%s)\n  host: %s\n  age: %ds\n  purpose: %s\n' \
    "$pid" "$alive" "$host" "$age" "$purpose"
  if [ "$age" -gt "$PLABS_LOCK_LEASE_MAX" ] && [ "$alive" = "dead" ]; then
    echo "  status: STALE — next acquire will reclaim"
  fi
}

cmd_force_unlock() {
  if [ ! -d "$PLABS_LOCK_DIR" ]; then
    echo "not locked"
    return 0
  fi
  local info
  info=$(lock_owner_info)
  echo "removing lock; previous owner: ${info:-unknown}" >&2
  rm -rf "$PLABS_LOCK_DIR"
  echo "unlocked"
}

cmd_enable() {
  if [ "$#" -lt 1 ]; then
    echo "usage: plabs-lifecycle.sh enable <scenario-id>..." >&2
    exit 1
  fi
  preflight_sso
  acquire_lock "enable: $*"
  run_plabs enable "$@" -y
  run_plabs apply -y
  # Terraform apply succeeded — import each scenario's starting creds so
  # downstream module work has an identity to switch to.
  for sid in "$@"; do
    import_creds_for "$sid"
  done
}

cmd_disable() {
  if [ "$#" -lt 1 ]; then
    echo "usage: plabs-lifecycle.sh disable <scenario-id>..." >&2
    exit 1
  fi
  preflight_sso
  acquire_lock "disable: $*"
  run_plabs disable "$@" -y
  run_plabs apply -y
  # Remove imported identities for the disabled scenarios; the underlying IAM
  # user is gone, so keeping the identity around just clutters the store.
  for sid in "$@"; do
    "$PATHRUNNER_BIN" identity clear "$sid" >/dev/null 2>&1 || true
  done
}

cmd_swap() {
  local -a to_add=()
  local -a to_remove=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --add)
        [ "$#" -ge 2 ] || { echo "--add requires an id" >&2; exit 1; }
        to_add+=("$2"); shift 2 ;;
      --remove)
        [ "$#" -ge 2 ] || { echo "--remove requires an id" >&2; exit 1; }
        to_remove+=("$2"); shift 2 ;;
      *)
        echo "usage: plabs-lifecycle.sh swap [--add <id>]... [--remove <id>]..." >&2
        exit 1 ;;
    esac
  done
  if [ "${#to_add[@]}" -eq 0 ] && [ "${#to_remove[@]}" -eq 0 ]; then
    echo "swap: nothing to add or remove" >&2
    exit 1
  fi

  local purpose="swap:"
  [ "${#to_remove[@]}" -gt 0 ] && purpose="$purpose -${to_remove[*]}"
  [ "${#to_add[@]}" -gt 0 ] && purpose="$purpose +${to_add[*]}"

  preflight_sso
  acquire_lock "$purpose"

  # Toggle state without applying, then one apply picks up the combined delta.
  if [ "${#to_remove[@]}" -gt 0 ]; then
    run_plabs disable "${to_remove[@]}" -y
  fi
  if [ "${#to_add[@]}" -gt 0 ]; then
    run_plabs enable "${to_add[@]}" -y
  fi
  run_plabs apply -y

  # Bring pathrunner's identity store in line with the new deployed set.
  for sid in "${to_remove[@]}"; do
    "$PATHRUNNER_BIN" identity clear "$sid" >/dev/null 2>&1 || true
  done
  for sid in "${to_add[@]}"; do
    import_creds_for "$sid"
  done
}

# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

if [ "$#" -lt 1 ]; then
  cat >&2 <<EOF
usage: $(basename "$0") <command> [args]

Commands:
  enable  <id>...              Enable one or more scenarios and apply
  disable <id>...              Disable one or more scenarios and apply
  swap    [--add <id>]...      Combined add+remove in a single apply
          [--remove <id>]...
  status                       Show plabs status (no lock)
  lock-info                    Show current lock holder / staleness (no lock)
  force-unlock                 Remove the lock unconditionally (emergency)

Env:
  PLABS_DIR=$PLABS_DIR
  PLABS_LOCK_DIR=$PLABS_LOCK_DIR
  PLABS_LOCK_TIMEOUT=$PLABS_LOCK_TIMEOUT
  PLABS_LOCK_LEASE_MAX=$PLABS_LOCK_LEASE_MAX
  PATHRUNNER_BIN=$PATHRUNNER_BIN
  SKIP_SSO_CHECK=$SKIP_SSO_CHECK        (set to 1 to bypass the SSO preflight)
  SKIP_CREDS_IMPORT=$SKIP_CREDS_IMPORT  (set to 1 to bypass auto-import of scenario creds)

Side effects of enable/swap (unless disabled via env):
  - preflight SSO check on all plabs profiles (fails fast if expired)
  - after successful apply, imports scenario starting creds into pathrunner as identity <scenario-id>
Side effects of disable/swap:
  - removes the corresponding pathrunner identity for each disabled scenario
EOF
  exit 1
fi

cmd="$1"
shift
case "$cmd" in
  enable)       cmd_enable "$@" ;;
  disable)      cmd_disable "$@" ;;
  swap)         cmd_swap "$@" ;;
  status)       cmd_status ;;
  lock-info)    cmd_lock_info ;;
  force-unlock) cmd_force_unlock ;;
  *)
    echo "unknown command: $cmd" >&2
    exit 1 ;;
esac
