#!/usr/bin/env bash
set -euo pipefail

# test-module.sh — Test a pathrunner module against a deployed pathfinding-labs scenario
#
# Usage:
#   ./scripts/test-module.sh setup   <plabs-scenario-id> <pathrunner-module-id> [payload1,payload2,...]
#   ./scripts/test-module.sh cleanup <plabs-scenario-id> <pathrunner-module-id>
#   ./scripts/test-module.sh full    [-i] <plabs-scenario-id> <pathrunner-module-id> [payload1,payload2,...]
#
# Subcommands:
#   setup    Build, import creds, load module, auto-map options — stops before exploit
#   cleanup  Run workspace cleanup and verify no leftover resources
#   full     Full run: setup + exploit + verification + cleanup (default if omitted)
#
# Flags:
#   -i    Interactive mode (full only): pause before cleanup with y/n prompt
#
# Examples:
#   ./scripts/test-module.sh setup lambda-001-to-admin lambda-001
#   ./scripts/test-module.sh cleanup lambda-001-to-admin lambda-001
#   ./scripts/test-module.sh full lambda-001-to-admin lambda-001
#   ./scripts/test-module.sh full -i lambda-001-to-admin lambda-001 backdoor/attach-policy
#   ./scripts/test-module.sh lambda-001-to-admin lambda-001 exfil/output   # defaults to "full"

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# === Paths ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PATHRUNNER="$PROJECT_DIR/pathrunner"
PLABS=""

# === Temp directory ===
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# === Parse subcommand, flags, and arguments ===
SUBCOMMAND=""
INTERACTIVE=false
POSITIONAL=()

# First arg might be a subcommand
case "${1:-}" in
    setup|cleanup|full)
        SUBCOMMAND="$1"
        shift
        ;;
    *)
        # No subcommand — default to "full"
        SUBCOMMAND="full"
        ;;
esac

for arg in "$@"; do
    case "$arg" in
        -i) INTERACTIVE=true ;;
        *)  POSITIONAL+=("$arg") ;;
    esac
done

SCENARIO_ID="${POSITIONAL[0]:-}"
MODULE_ID="${POSITIONAL[1]:-}"
PAYLOAD_FILTER="${POSITIONAL[2]:-}"

# === State ===
STARTING_IDENTITY=""
STARTING_USERNAME=""
PLABS_RAW=""
declare -a RESULT_PAYLOADS=()
declare -a RESULT_EXECUTION=()
declare -a RESULT_CREDS=()
declare -a RESULT_CLEANUP=()

# ──────────────────────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────────────────────

info()    { echo -e "${CYAN}>>>${NC} $*"; }
success() { echo -e "${GREEN} +${NC} $*"; }
warn()    { echo -e "${YELLOW} !${NC} $*"; }
fail()    { echo -e "${RED} x${NC} $*" >&2; }
header()  { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

strip_ansi() {
    sed $'s/\033\[[0-9;]*m//g'
}

show_usage() {
    echo "Usage:"
    echo "  $0 setup   <plabs-scenario-id> <pathrunner-module-id> [payload1,payload2,...]"
    echo "  $0 cleanup <plabs-scenario-id> <pathrunner-module-id>"
    echo "  $0 full    [-i] <plabs-scenario-id> <pathrunner-module-id> [payload1,payload2,...]"
    echo ""
    echo "Subcommands:"
    echo "  setup    Build, import creds, load module, auto-map options — stops before exploit"
    echo "  cleanup  Run workspace cleanup and verify no leftover resources"
    echo "  full     Full run: setup + exploit + verification + cleanup (default)"
    echo ""
    echo "Flags:"
    echo "  -i    Interactive mode (full only): pause before cleanup with y/n prompt"
    echo ""
    echo "Examples:"
    echo "  $0 setup lambda-001-to-admin lambda-001"
    echo "  $0 cleanup lambda-001-to-admin lambda-001"
    echo "  $0 full lambda-001-to-admin lambda-001"
    echo "  $0 full -i lambda-001-to-admin lambda-001 backdoor/attach-policy"
}

# ──────────────────────────────────────────────────────────────
# Find plabs binary
# ──────────────────────────────────────────────────────────────

find_plabs() {
    if command -v plabs &>/dev/null; then
        PLABS="plabs"
        return
    fi
    local search_paths=(
        "$HOME/Documents/projects/pathfinding-labs/plabs"
        "/Users/seth.art/Documents/projects/pathfinding-labs/plabs"
    )
    for p in "${search_paths[@]}"; do
        if [[ -x "$p" ]]; then
            PLABS="$p"
            return
        fi
    done
    fail "plabs binary not found. Install pathfinding-labs or add plabs to PATH."
    exit 1
}

# ──────────────────────────────────────────────────────────────
# Get plabs scenario output with full (untruncated) ARNs
# Uses macOS script command to create pseudo-TTY with wide columns
# so term.GetSize doesn't fall back to 80-column truncation.
# ──────────────────────────────────────────────────────────────

get_plabs_output() {
    local scenario_id="$1"
    script -q /dev/null bash -c "stty cols 500 2>/dev/null; $PLABS scenarios show $scenario_id" 2>/dev/null \
        | tr -d '\r' \
        | sed 's/[[:space:]]*$//'
}

# ──────────────────────────────────────────────────────────────
# Parse deployed resource ARNs from plabs output
# ──────────────────────────────────────────────────────────────

parse_deployed_resources() {
    local plabs_output="$1"
    echo "$plabs_output" \
        | sed -n '/Deployed Resources/,/^[[:space:]]*$/p' \
        | grep -oE 'arn:aws:[^ ]+' \
        | sed 's/[[:space:]]*$//' \
        || true
}

# ──────────────────────────────────────────────────────────────
# Map an ARN to a pathrunner option name based on resource type.
# Returns empty string for unrecognized or starting-user resources.
# ──────────────────────────────────────────────────────────────

map_arn_to_option() {
    local arn="$1"
    # Skip starting-user resources (credentials, not module targets)
    if [[ "$arn" == *"starting"* ]]; then
        echo ""
        return
    fi
    case "$arn" in
        *:role/*)               echo "ROLE_ARN" ;;
        *:function:*)           echo "FUNCTION_NAME" ;;
        *:instance-profile/*)   echo "INSTANCE_PROFILE" ;;
        *:table/*/stream/*)     echo "STREAM_ARN" ;;
        *)                      echo "" ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Extract the usable value from an ARN for a given option.
# Some options want the full ARN; others want just the name.
# ──────────────────────────────────────────────────────────────

extract_value_from_arn() {
    local arn="$1" option="$2"
    case "$option" in
        FUNCTION_NAME)
            # arn:aws:lambda:region:account:function:NAME
            echo "$arn" | rev | cut -d: -f1 | rev
            ;;
        *)
            echo "$arn"
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Parse module options from pathrunner show options output.
# get_required_options: returns only required option names
# get_all_option_names: returns all option names
# ──────────────────────────────────────────────────────────────

get_required_options() {
    "$PATHRUNNER" show options 2>&1 | strip_ansi | \
        awk -F'│' '{
            gsub(/^[ \t]+|[ \t]+$/, "", $2);
            gsub(/^[ \t]+|[ \t]+$/, "", $4);
            if ($4 == "Yes" && $2 != "" && $2 != "Option") print $2
        }'
}

get_all_option_names() {
    "$PATHRUNNER" show options 2>&1 | strip_ansi | \
        awk -F'│' '{
            gsub(/^[ \t]+|[ \t]+$/, "", $2);
            gsub(/^[ \t]+|[ \t]+$/, "", $4);
            if (($4 == "Yes" || $4 == "No") && $2 != "" && $2 != "Option") print $2
        }'
}

# ──────────────────────────────────────────────────────────────
# Parse available payloads from pathrunner show payloads output.
# ──────────────────────────────────────────────────────────────

get_available_payloads() {
    "$PATHRUNNER" show payloads 2>&1 | strip_ansi | \
        awk -F'│' '{
            gsub(/^[ \t]+|[ \t]+$/, "", $3);
            if ($3 != "" && $3 != "Payload" && $3 ~ /\//) print $3
        }'
}

# ──────────────────────────────────────────────────────────────
# Run a single payload test: set payload, exploit, check, cleanup
# ──────────────────────────────────────────────────────────────

run_payload_test() {
    local payload="$1"
    local output_file="$WORK_DIR/exploit_${payload//\//_}.txt"

    # Set payload (skip for non-payload modules)
    if [[ "$payload" != "none" ]]; then
        info "Setting payload: $payload"
        "$PATHRUNNER" set PAYLOAD "$payload" 2>&1

        # Auto-fill payload-specific required options
        local payload_required
        payload_required=$("$PATHRUNNER" show options 2>&1 | strip_ansi | \
            awk -F'│' '{
                gsub(/^[ \t]+|[ \t]+$/, "", $2);
                gsub(/^[ \t]+|[ \t]+$/, "", $3);
                gsub(/^[ \t]+|[ \t]+$/, "", $4);
                if ($4 == "Yes" && $3 == "<not set>" && $2 != "" && $2 != "Option" && $2 != "Payload Option") print $2
            }')

        for opt in $payload_required; do
            case "$opt" in
                TARGET_USER)
                    if [[ -n "$STARTING_USERNAME" ]]; then
                        info "Auto-setting $opt = $STARTING_USERNAME"
                        "$PATHRUNNER" set "$opt" "$STARTING_USERNAME" 2>&1
                    fi
                    ;;
                PAYLOAD|ROLE_ARN|INSTANCE_PROFILE)
                    ;; # already handled
                *)
                    warn "Payload option $opt is required but unset"
                    read -rp "  Enter value for $opt (or Enter to skip): " manual_val
                    if [[ -n "$manual_val" ]]; then
                        "$PATHRUNNER" set "$opt" "$manual_val" 2>&1
                    fi
                    ;;
            esac
        done
    fi

    echo ""
    info "Running exploit..."
    echo -e "${DIM}$(printf '%.0s-' {1..50})${NC}"

    # Run exploit, capture output while streaming to terminal
    set +e
    "$PATHRUNNER" exploit 2>&1 | tee "$output_file"
    local exit_code=${PIPESTATUS[0]}
    set -e

    echo -e "${DIM}$(printf '%.0s-' {1..50})${NC}"

    # Determine results
    local execution="FAIL"
    local creds="NO"

    if [[ $exit_code -eq 0 ]]; then
        execution="PASS"
    fi

    local clean_output
    clean_output=$(strip_ansi < "$output_file")
    if echo "$clean_output" | grep -qE "PATHFINDER_IDENTITY_DATA|AccessKeyId|access_key_id|AWS_ACCESS_KEY_ID"; then
        creds="YES"
        execution="PASS"
    fi

    RESULT_PAYLOADS+=("$payload")
    RESULT_EXECUTION+=("$execution")
    RESULT_CREDS+=("$creds")

    if [[ "$execution" == "PASS" ]]; then
        success "Exploit succeeded (creds: $creds)"
    else
        fail "Exploit failed"
    fi

    # Verify escalation by calling iam:ListUsers from the escalated principal.
    # For exfil payloads: the auto-imported identity has the escalated role creds.
    # For backdoor payloads: the starting user itself was elevated.
    echo ""
    local escalated_identity=""
    escalated_identity=$(strip_ansi < "$output_file" | sed -n "s/.*Added identity '\([^']*\)'.*/\1/p" | head -1)

    if [[ -n "$escalated_identity" ]]; then
        info "Switching to escalated identity ($escalated_identity) for verification..."
        "$PATHRUNNER" identity switch "$escalated_identity" 2>&1 || true
    fi

    info "Verifying escalated privileges (iam:ListUsers)..."
    local verify_output
    set +e
    verify_output=$("$PATHRUNNER" aws iam list-users --max-items 5 --output table 2>&1)
    local verify_exit=$?
    set -e

    if [[ $verify_exit -eq 0 ]] && echo "$verify_output" | grep -q "UserName\|UserId"; then
        success "Privilege escalation confirmed - iam:ListUsers succeeded"
        echo "$verify_output"
    else
        warn "iam:ListUsers failed (escalation may not have taken effect yet)"
        echo "$verify_output" | head -5
    fi

    # Switch back to starting identity before cleanup
    echo ""
    info "Switching back to starting identity..."
    "$PATHRUNNER" identity switch "$STARTING_IDENTITY" 2>&1 || true

    # Interactive mode: pause before cleanup
    if [[ "$INTERACTIVE" == true ]]; then
        echo ""
        read -rp "Run cleanup for this payload? [Y/n]: " cleanup_response
        if [[ "$cleanup_response" =~ ^[Nn] ]]; then
            warn "Skipping cleanup (resources left in place)"
            RESULT_CLEANUP+=("SKIP")
            return
        fi
    fi

    # Run cleanup for this module
    info "Running cleanup..."
    local cleanup_output
    cleanup_output=$("$PATHRUNNER" workspace cleanup --module "$MODULE_ID" --all 2>&1) || true
    echo "$cleanup_output"

    local cleanup_result="PASS"
    if echo "$cleanup_output" | strip_ansi | grep -qE "FAILED|[1-9][0-9]* failed|could not|permission"; then
        cleanup_result="WARN"
    fi
    RESULT_CLEANUP+=("$cleanup_result")
}

# ──────────────────────────────────────────────────────────────
# Verify no leftover resources after all tests
# ──────────────────────────────────────────────────────────────

verify_cleanup() {
    header "Cleanup Verification"
    local has_issues=false

    # Check for leftover pathrunner Lambda functions
    info "Checking for leftover Lambda functions..."
    local lambda_output
    lambda_output=$("$PATHRUNNER" aws lambda list-functions \
        --output text --region us-east-1 2>&1) || true

    if echo "$lambda_output" | grep -qi "pathrunner"; then
        warn "Found leftover Lambda functions containing 'pathrunner':"
        echo "$lambda_output" | grep -i "pathrunner"
        has_issues=true
    else
        success "No leftover Lambda functions"
    fi

    # Check for leftover policy attachments on starting user
    if [[ -n "$STARTING_USERNAME" ]]; then
        info "Checking policy attachments on $STARTING_USERNAME..."
        local policy_output
        policy_output=$("$PATHRUNNER" aws iam list-attached-user-policies \
            --user-name "$STARTING_USERNAME" --output json 2>&1) || true

        if echo "$policy_output" | grep -q "AdministratorAccess"; then
            warn "Found leftover AdministratorAccess policy on $STARTING_USERNAME"
            has_issues=true
        else
            success "No unexpected policy attachments"
        fi
    fi

    if [[ "$has_issues" == true ]]; then
        warn "Cleanup verification found issues - manual cleanup may be needed"
    else
        success "All resources cleaned up successfully"
    fi
}

# ──────────────────────────────────────────────────────────────
# Print results summary table
# ──────────────────────────────────────────────────────────────

print_summary() {
    header "Test Results"

    # Calculate payload column width
    local max_len=7 # "Payload"
    for p in "${RESULT_PAYLOADS[@]}"; do
        (( ${#p} > max_len )) && max_len=${#p}
    done
    local pw=$max_len
    local bp
    bp=$(printf '=%.0s' $(seq 1 $((pw + 2))))

    # Borders
    echo -e "${BOLD}+${bp}+===========+================+=========+${NC}"
    local ph
    ph=$(printf "%-${pw}s" "Payload")
    echo -e "${BOLD}| ${ph} | Execution | Creds Obtained | Cleanup |${NC}"
    echo -e "${BOLD}+${bp}+===========+================+=========+${NC}"

    for i in "${!RESULT_PAYLOADS[@]}"; do
        local exec_color="$RED" creds_color="$RED" clean_color="$GREEN"
        [[ "${RESULT_EXECUTION[$i]}" == "PASS" ]] && exec_color="$GREEN"
        [[ "${RESULT_CREDS[$i]}" == "YES" ]] && creds_color="$GREEN"
        [[ "${RESULT_CLEANUP[$i]}" == "WARN" ]] && clean_color="$YELLOW"
        [[ "${RESULT_CLEANUP[$i]}" == "FAIL" ]] && clean_color="$RED"
        [[ "${RESULT_CLEANUP[$i]}" == "SKIP" ]] && clean_color="$YELLOW"

        local ps es cs ls
        ps=$(printf "%-${pw}s" "${RESULT_PAYLOADS[$i]}")
        es=$(printf "%-9s" "${RESULT_EXECUTION[$i]}")
        cs=$(printf "%-14s" "${RESULT_CREDS[$i]}")
        ls=$(printf "%-7s" "${RESULT_CLEANUP[$i]}")

        echo -e "| ${ps} | ${exec_color}${es}${NC} | ${creds_color}${cs}${NC} | ${clean_color}${ls}${NC} |"
    done

    echo -e "${BOLD}+${bp}+===========+================+=========+${NC}"
}

# ──────────────────────────────────────────────────────────────
# Phase functions (composable)
# ──────────────────────────────────────────────────────────────

# Phase 1+2+3: Build, import creds, configure module options
do_setup() {
    # ── Phase 1: Setup ─────────────────────────────────────────
    header "Phase 1: Setup"

    find_plabs
    success "Found plabs: $PLABS"

    info "Building pathrunner..."
    (cd "$PROJECT_DIR" && go build -o pathrunner cmd/pathrunner/main.go)
    success "Built pathrunner"

    # Switch to (or create) the testing workspace
    info "Switching to 'testing' workspace..."
    if "$PATHRUNNER" workspace switch testing 2>&1 | grep -q "Switched"; then
        success "Using existing 'testing' workspace"
    else
        "$PATHRUNNER" workspace create testing 2>&1
        success "Created 'testing' workspace"
    fi

    info "Getting scenario info (pseudo-TTY for full ARNs)..."
    PLABS_RAW=$(get_plabs_output "$SCENARIO_ID")

    # Check deployment status
    if ! echo "$PLABS_RAW" | grep -qE "Status.*Deployed"; then
        fail "Scenario '$SCENARIO_ID' is not deployed."
        echo "  Run: plabs scenarios deploy $SCENARIO_ID"
        exit 1
    fi
    success "Scenario is deployed"

    # Parse deployed resources
    local resources
    resources=$(parse_deployed_resources "$PLABS_RAW")
    if [[ -z "$resources" ]]; then
        warn "No deployed resources found in scenario output"
    else
        info "Deployed resources:"
        while IFS= read -r arn; do
            echo -e "  ${DIM}${arn}${NC}"
        done <<< "$resources"
    fi

    # Extract starting username for cleanup verification
    STARTING_USERNAME=$(echo "$PLABS_RAW" \
        | sed -n '/Deployed Resources/,/^[[:space:]]*$/p' \
        | grep -oE 'arn:aws:iam::[0-9]+:user/[^ ]+' \
        | grep "starting" \
        | rev | cut -d/ -f1 | rev \
        || true)

    if [[ -n "$STARTING_USERNAME" ]]; then
        info "Starting username: $STARTING_USERNAME"
    fi

    # ── Phase 2: Credential Import ─────────────────────────────
    header "Phase 2: Credential Import"

    info "Getting scenario credentials..."
    local creds_json
    creds_json=$("$PLABS" credentials "$SCENARIO_ID" --format=json 2>&1)

    local access_key secret_key
    access_key=$(echo "$creds_json" | jq -r '.access_key_id')
    secret_key=$(echo "$creds_json" | jq -r '.secret_access_key')

    if [[ -z "$access_key" || "$access_key" == "null" ]]; then
        fail "Failed to get credentials for scenario"
        echo "$creds_json"
        exit 1
    fi
    success "Got credentials (${access_key:0:12}...)"

    # Use scenario ID as the identity name for consistency across runs.
    # Try switching to existing identity first (may exist from previous run).
    STARTING_IDENTITY="$SCENARIO_ID"

    if "$PATHRUNNER" identity switch "$STARTING_IDENTITY" 2>&1 | grep -q "Switched"; then
        success "Switched to existing identity: $STARTING_IDENTITY"
    else
        info "Adding new identity: $STARTING_IDENTITY"
        local add_output
        add_output=$("$PATHRUNNER" identity add \
            --access "$access_key" --secret "$secret_key" \
            --name "$STARTING_IDENTITY" --switch 2>&1) || true
        echo "$add_output"
        success "Active identity: $STARTING_IDENTITY"
    fi

    # ── Phase 3: Module Configuration ──────────────────────────
    header "Phase 3: Module Configuration"

    info "Loading module: $MODULE_ID"
    "$PATHRUNNER" use "$MODULE_ID" 2>&1

    # Get module option names
    local required_options all_options
    required_options=$(get_required_options)
    all_options=$(get_all_option_names)
    info "Required options: $(echo $required_options | tr '\n' ' ')"

    # Map deployed resources to module options
    declare -A option_candidates

    while IFS= read -r arn; do
        [[ -z "$arn" ]] && continue

        local opt
        opt=$(map_arn_to_option "$arn")
        [[ -z "$opt" ]] && continue

        # Only map if this option exists for the current module
        if ! echo "$all_options" | grep -q "^${opt}$"; then
            continue
        fi

        local val
        val=$(extract_value_from_arn "$arn" "$opt")

        if [[ -n "${option_candidates[$opt]:-}" ]]; then
            option_candidates[$opt]="${option_candidates[$opt]}|$val"
        else
            option_candidates[$opt]="$val"
        fi
    done <<< "$resources"

    # Set mapped options
    for opt in "${!option_candidates[@]}"; do
        local candidates="${option_candidates[$opt]}"
        IFS='|' read -ra vals <<< "$candidates"

        if (( ${#vals[@]} == 1 )); then
            info "Auto-setting $opt = ${vals[0]}"
            "$PATHRUNNER" set "$opt" "${vals[0]}" 2>&1
        else
            echo ""
            warn "Multiple candidates for $opt:"
            select val in "${vals[@]}"; do
                if [[ -n "$val" ]]; then
                    info "Setting $opt = $val"
                    "$PATHRUNNER" set "$opt" "$val" 2>&1
                    break
                fi
            done
        fi
    done

    # Set region (default for all current scenarios)
    "$PATHRUNNER" set REGION us-east-1 2>&1 || true

    # Check for unset required options (except PAYLOAD, set per-test)
    for opt in $required_options; do
        [[ "$opt" == "PAYLOAD" ]] && continue
        if [[ -z "${option_candidates[$opt]:-}" ]]; then
            echo ""
            warn "Required option $opt was not auto-mapped from resources"
            read -rp "  Enter value for $opt (or Enter to skip): " manual_val
            if [[ -n "$manual_val" ]]; then
                "$PATHRUNNER" set "$opt" "$manual_val" 2>&1
            fi
        fi
    done

    # Show final configuration
    echo ""
    info "Current configuration:"
    "$PATHRUNNER" show options 2>&1
}

# Phase 4: Run exploit with each payload
do_exploit() {
    header "Phase 4: Payload Testing"

    local -a payloads=()
    if [[ -n "$PAYLOAD_FILTER" ]]; then
        IFS=',' read -ra payloads <<< "$PAYLOAD_FILTER"
    else
        while IFS= read -r p; do
            [[ -n "$p" ]] && payloads+=("$p")
        done < <(get_available_payloads)
    fi

    if (( ${#payloads[@]} == 0 )); then
        warn "No payloads found - running single exploit without payload"
        run_payload_test "none"
    else
        info "Testing ${#payloads[@]} payload(s): ${payloads[*]}"
        echo ""

        for i in "${!payloads[@]}"; do
            local payload="${payloads[$i]}"
            local n=$((i + 1))
            echo -e "${BOLD}-- Payload ${n}/${#payloads[@]}: ${payload} --${NC}"
            echo ""

            run_payload_test "$payload"

            # Pause between payloads (not after the last one)
            if (( n < ${#payloads[@]} )); then
                echo ""
                read -rp "Press Enter for next payload (or 'q' to quit): " response
                if [[ "$response" == "q" ]]; then
                    warn "Stopped by user"
                    break
                fi
                echo ""
            fi
        done
    fi
}

# Phase 5: Cleanup and verify
do_cleanup() {
    # Ensure we're in the testing workspace
    "$PATHRUNNER" workspace switch testing 2>&1 || true

    # Ensure identity is active for cleanup commands
    STARTING_IDENTITY="$SCENARIO_ID"
    if ! "$PATHRUNNER" identity switch "$STARTING_IDENTITY" 2>&1 | grep -q "Switched"; then
        warn "Could not switch to identity '$STARTING_IDENTITY' — cleanup may fail"
    fi

    # Ensure module is loaded for --module filter
    "$PATHRUNNER" use "$MODULE_ID" 2>&1 || true

    header "Cleanup"

    info "Running workspace cleanup for module $MODULE_ID..."
    local cleanup_output
    cleanup_output=$("$PATHRUNNER" workspace cleanup --module "$MODULE_ID" --all 2>&1) || true
    echo "$cleanup_output"

    if echo "$cleanup_output" | strip_ansi | grep -qE "FAILED|[1-9][0-9]* failed|could not|permission"; then
        warn "Some cleanup operations had issues"
    else
        success "Cleanup completed"
    fi

    # Extract starting username if not already set (standalone cleanup mode)
    if [[ -z "$STARTING_USERNAME" ]]; then
        find_plabs
        PLABS_RAW=$(get_plabs_output "$SCENARIO_ID")
        STARTING_USERNAME=$(echo "$PLABS_RAW" \
            | sed -n '/Deployed Resources/,/^[[:space:]]*$/p' \
            | grep -oE 'arn:aws:iam::[0-9]+:user/[^ ]+' \
            | grep "starting" \
            | rev | cut -d/ -f1 | rev \
            || true)
    fi

    verify_cleanup
}

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

main() {
    # Validate arguments
    if [[ -z "$SCENARIO_ID" || -z "$MODULE_ID" ]]; then
        show_usage
        exit 1
    fi

    # Check bash version (need 4+ for associative arrays)
    if (( BASH_VERSINFO[0] < 4 )); then
        fail "Bash 4+ required (current: $BASH_VERSION). Install via: brew install bash"
        exit 1
    fi

    # Check dependencies
    command -v jq &>/dev/null || { fail "jq not found. Install via: brew install jq"; exit 1; }
    command -v go &>/dev/null || { fail "go not found"; exit 1; }

    case "$SUBCOMMAND" in
        setup)
            do_setup
            echo ""
            success "Setup complete. Module is configured in the 'testing' workspace."
            echo -e "  Open pathrunner and switch to the testing workspace:"
            echo -e "  ${BOLD}./pathrunner${NC}  then  ${BOLD}workspace switch testing${NC}"
            echo -e "  Or run directly: ${BOLD}./pathrunner exploit${NC}"
            ;;
        cleanup)
            do_cleanup
            ;;
        full)
            do_setup
            do_exploit

            # Cleanup verification
            verify_cleanup

            # Summary
            if (( ${#RESULT_PAYLOADS[@]} > 0 )); then
                print_summary
            fi
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
