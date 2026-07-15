#!/usr/bin/env bash
set -euo pipefail

# test-module.sh — Test a pathrunner module against a deployed pathfinding-labs scenario
#
# Usage:
#   ./scripts/test-module.sh setup   <module-id> [scenario-suffix] [payload1,payload2,...]
#   ./scripts/test-module.sh cleanup <module-id> [scenario-suffix]
#   ./scripts/test-module.sh full    [-i] <module-id> [scenario-suffix] [payload1,payload2,...]
#
# The module-id is the pathrunner module (e.g., lambda-001, iam-001).
# The plabs scenario ID is derived as <module-id>-<suffix>, defaulting to "to-admin".
# If the second positional arg contains '/', it's treated as a payload filter, not a suffix.
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
#   ./scripts/test-module.sh setup lambda-001
#   ./scripts/test-module.sh cleanup lambda-001
#   ./scripts/test-module.sh full lambda-001                          # scenario: lambda-001-to-admin
#   ./scripts/test-module.sh full lambda-001 to-bucket                # scenario: lambda-001-to-bucket
#   ./scripts/test-module.sh full -i lambda-001 backdoor/attach-policy  # scenario: lambda-001-to-admin
#   ./scripts/test-module.sh lambda-001 exfil/output                  # defaults to "full"

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

# === Transcript logging ===
# Re-exec with tee so every run saves a log to test-results/<module-id>[-<suffix>].log.
# TEST_MODULE_LOGGING is set before re-exec to prevent an infinite loop.
if [[ -z "${TEST_MODULE_LOGGING:-}" ]]; then
    # Derive module ID and scenario suffix from args (mirrors the arg parser below)
    _log_subcommand="${1:-}"
    _log_args=("$@")
    case "$_log_subcommand" in
        setup|cleanup|full) _log_args=("${@:2}") ;;
    esac
    # Strip flags (-i) to find positional args
    _log_positional=()
    for _a in "${_log_args[@]}"; do
        [[ "$_a" == -* ]] || _log_positional+=("$_a")
    done
    _log_module="${_log_positional[0]:-unknown}"
    _log_suffix=""
    if [[ -n "${_log_positional[1]:-}" ]] && [[ "${_log_positional[1]}" != */* ]]; then
        _log_suffix="-${_log_positional[1]}"
    fi
    _log_dir="$PROJECT_DIR/test-results"
    mkdir -p "$_log_dir"
    _log_file="$_log_dir/${_log_module}${_log_suffix}.log"
    export TEST_MODULE_LOGGING=1
    exec > >(tee "$_log_file") 2>&1
fi

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

MODULE_ID="${POSITIONAL[0]:-}"
SCENARIO_SUFFIX=""
PAYLOAD_FILTER=""

# Second positional arg: if it contains '/' it's a payload filter, otherwise a scenario suffix
if [[ -n "${POSITIONAL[1]:-}" ]]; then
    if [[ "${POSITIONAL[1]}" == */* ]]; then
        PAYLOAD_FILTER="${POSITIONAL[1]}"
    else
        SCENARIO_SUFFIX="${POSITIONAL[1]}"
        PAYLOAD_FILTER="${POSITIONAL[2]:-}"
    fi
fi

# Default scenario suffix to "to-admin"
[[ -z "$SCENARIO_SUFFIX" ]] && SCENARIO_SUFFIX="to-admin"
SCENARIO_ID="${MODULE_ID}-${SCENARIO_SUFFIX}"

# Use a module-specific workspace name to prevent concurrent test collisions.
# Multiple batch-module agents run in parallel and all used "testing" previously,
# causing workspace state to be overwritten between setup and exploit phases.
TEST_WORKSPACE="test-${MODULE_ID}"

# Export PATHRUNNER_WORKSPACE so every pathrunner invocation in this script uses
# the module-specific workspace without touching the shared ~/.pathrunner/config.json.
# This prevents concurrent agents from overwriting each other's current-workspace pointer.
export PATHRUNNER_WORKSPACE="$TEST_WORKSPACE"

# === State ===
STARTING_IDENTITY=""
STARTING_USERNAME=""
PLABS_RAW=""
ALL_OPTIONS=""
ECR_CONTAINER_URI=""  # Set when CONTAINER_URI is auto-mapped from an ECR repo ARN
ASSUMED_ROLE_ARN=""   # Set when a starting-role is assumed for self-escalation modules
declare -a RESULT_PAYLOADS=()
declare -a RESULT_EXECUTION=()
declare -a RESULT_CREDS=()
declare -a RESULT_VERIFIED=()
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
    echo "  $0 setup   <module-id> [scenario-suffix] [payload1,payload2,...]"
    echo "  $0 cleanup <module-id> [scenario-suffix]"
    echo "  $0 full    [-i] <module-id> [scenario-suffix] [payload1,payload2,...]"
    echo ""
    echo "The plabs scenario ID is derived as <module-id>-<suffix> (default: to-admin)."
    echo "If the second arg contains '/', it's treated as a payload filter."
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
    echo "  $0 setup lambda-001"
    echo "  $0 cleanup lambda-001"
    echo "  $0 full lambda-001                           # scenario: lambda-001-to-admin"
    echo "  $0 full lambda-001 to-bucket                 # scenario: lambda-001-to-bucket"
    echo "  $0 full -i lambda-001 backdoor/attach-policy # scenario: lambda-001-to-admin"
    echo "  $0 lambda-001 exfil/output                   # defaults to full"
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
# Uses ALL_OPTIONS (set by caller) to pick the right option name
# when multiple candidates exist (e.g., ROLE_ARN vs TARGET_ROLE).
# ──────────────────────────────────────────────────────────────

map_arn_to_option() {
    local arn="$1"
    # Skip starting-user resources (credentials, not module targets).
    # Starting-role resources are kept — self-escalation modules need them as ROLE_ARN.
    if [[ "$arn" == *"starting-user"* ]]; then
        echo ""
        return
    fi
    # Skip infrastructure ARNs that are never module options
    case "$arn" in
        *:role/aws-service-role/*)   echo ""; return ;;
        *:ssm:*:parameter/*)         echo ""; return ;;
        *:ec2:*:security-group/*)    echo ""; return ;;
        *:ec2:*:image/*)             echo ""; return ;;
        *:batch:*:compute-environment/*) echo ""; return ;;
    esac
    case "$arn" in
        *:ec2:*:instance/*)
            if echo "$ALL_OPTIONS" | grep -q "^INSTANCE_ID$"; then
                echo "INSTANCE_ID"
            else
                echo ""
            fi
            ;;
        *:role/*)
            local role_name
            role_name=$(echo "$arn" | rev | cut -d/ -f1 | rev)
            # Disambiguate by role naming conventions from plabs scenarios
            if [[ "$role_name" == *"admin"* ]]; then
                if echo "$ALL_OPTIONS" | grep -q "^ADMIN_ROLE_ARN$"; then
                    echo "ADMIN_ROLE_ARN"; return
                fi
            fi
            if [[ "$role_name" == *"execution"* ]]; then
                if echo "$ALL_OPTIONS" | grep -q "^EXECUTION_ROLE_NAME$"; then
                    echo "EXECUTION_ROLE_NAME"; return
                fi
                if echo "$ALL_OPTIONS" | grep -q "^EXECUTION_ROLE_ARN$"; then
                    echo "EXECUTION_ROLE_ARN"; return
                fi
            fi
            if [[ "$role_name" == *"service"* ]]; then
                if echo "$ALL_OPTIONS" | grep -q "^SERVICE_ROLE$"; then
                    echo "SERVICE_ROLE"; return
                fi
            fi
            # Default role mapping (target/generic roles)
            if echo "$ALL_OPTIONS" | grep -q "^TARGET_ROLE$"; then
                echo "TARGET_ROLE"
            elif echo "$ALL_OPTIONS" | grep -q "^ROLE_ARN$"; then
                echo "ROLE_ARN"
            elif echo "$ALL_OPTIONS" | grep -q "^EXECUTION_ROLE_ARN$"; then
                echo "EXECUTION_ROLE_ARN"
            else
                echo ""
            fi
            ;;
        *:user/*)
            if echo "$ALL_OPTIONS" | grep -q "^TARGET_USER$"; then
                echo "TARGET_USER"
            else
                echo ""
            fi
            ;;
        *:group/*)
            if echo "$ALL_OPTIONS" | grep -q "^GROUP_NAME$"; then
                echo "GROUP_NAME"
            else
                echo ""
            fi
            ;;
        *:policy/*)
            if echo "$ALL_OPTIONS" | grep -q "^POLICY_ARN$"; then
                echo "POLICY_ARN"
            else
                echo ""
            fi
            ;;
        *:function:*)           echo "FUNCTION_NAME" ;;
        *codebuild*:project/*)  echo "PROJECT_NAME" ;;
        *:instance-profile/*)   echo "INSTANCE_PROFILE" ;;
        *ecr*:repository/*)
            if echo "$ALL_OPTIONS" | grep -q "^CONTAINER_URI$"; then
                echo "CONTAINER_URI"
            else
                echo ""
            fi
            ;;
        *:table/*/stream/*)     echo "STREAM_ARN" ;;
        *:task-definition/*)
            if echo "$ALL_OPTIONS" | grep -q "^TASK_DEFINITION$"; then
                echo "TASK_DEFINITION"
            else
                echo ""
            fi
            ;;
        *:cluster/*)
            if echo "$ALL_OPTIONS" | grep -q "^CLUSTER_ARN$"; then
                echo "CLUSTER_ARN"
            elif echo "$ALL_OPTIONS" | grep -q "^CLUSTER_NAME$"; then
                echo "CLUSTER_NAME"
            elif echo "$ALL_OPTIONS" | grep -q "^CLUSTER$"; then
                echo "CLUSTER"
            else
                echo ""
            fi
            ;;
        *:stackset/*)
            if echo "$ALL_OPTIONS" | grep -q "^STACKSET_NAME$"; then
                echo "STACKSET_NAME"
            else
                echo ""
            fi
            ;;
        *:apprunner:*:service/*)
            if echo "$ALL_OPTIONS" | grep -q "^SERVICE_ARN$"; then
                echo "SERVICE_ARN"
            else
                echo ""
            fi
            ;;
        *:batch:*:job-definition/*)
            if echo "$ALL_OPTIONS" | grep -q "^JOB_DEFINITION$"; then
                echo "JOB_DEFINITION"
            else
                echo ""
            fi
            ;;
        *:batch:*:job-queue/*)
            if echo "$ALL_OPTIONS" | grep -q "^JOB_QUEUE$"; then
                echo "JOB_QUEUE"
            else
                echo ""
            fi
            ;;
        *:bedrock-agentcore:*:code-interpreter/*)
            if echo "$ALL_OPTIONS" | grep -q "^INTERPRETER_ID$"; then
                echo "INTERPRETER_ID"
            else
                echo ""
            fi
            ;;
        *:bedrock-agentcore:*:browser/*)
            if echo "$ALL_OPTIONS" | grep -q "^BROWSER_ID$"; then
                echo "BROWSER_ID"
            else
                echo ""
            fi
            ;;
        *:bedrock-agentcore:*:agent-runtime/*|*:bedrock-agentcore:*:harness/*)
            if echo "$ALL_OPTIONS" | grep -q "^TARGET_RUNTIME_ARN$"; then
                echo "TARGET_RUNTIME_ARN"
            else
                echo ""
            fi
            ;;
        *:cloudformation:*:stack/*)
            if echo "$ALL_OPTIONS" | grep -q "^STACK_NAME$"; then
                echo "STACK_NAME"
            else
                echo ""
            fi
            ;;
        *:glue:*:job/*)
            if echo "$ALL_OPTIONS" | grep -q "^JOB_NAME$"; then
                echo "JOB_NAME"
            else
                echo ""
            fi
            ;;
        *:codedeploy:*:application:*)
            if echo "$ALL_OPTIONS" | grep -q "^APP_NAME$"; then
                echo "APP_NAME"
            else
                echo ""
            fi
            ;;
        *:codedeploy:*:deploymentgroup:*)
            if echo "$ALL_OPTIONS" | grep -q "^DEPLOYMENT_GROUP$"; then
                echo "DEPLOYMENT_GROUP"
            else
                echo ""
            fi
            ;;
        arn:aws:s3:::*)
            # S3 ARN: bucket (no slash) or object (has slash).
            if [[ "$arn" != *"/"* ]]; then
                # Bucket ARN: map to BUCKET, CODE_BUCKET, or EXFIL_BUCKET
                if echo "$ALL_OPTIONS" | grep -q "^BUCKET$"; then
                    echo "BUCKET"
                elif echo "$ALL_OPTIONS" | grep -q "^CODE_BUCKET$"; then
                    echo "CODE_BUCKET"
                elif echo "$ALL_OPTIONS" | grep -q "^EXFIL_BUCKET$"; then
                    # Used for modules (e.g. omics-001) where the lab provides a
                    # dedicated in-region S3 bucket for both run output and exfil.
                    echo "EXFIL_BUCKET"
                else
                    echo ""
                fi
            else
                # Object ARN: map to CODE_KEY if the module has that option
                if echo "$ALL_OPTIONS" | grep -q "^CODE_KEY$"; then
                    echo "CODE_KEY"
                else
                    echo ""
                fi
            fi
            ;;
        *)                      echo "" ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Get the description for a module option from show options output.
# ──────────────────────────────────────────────────────────────

get_option_description() {
    local option="$1"
    # Extract everything after "Yes/No  " on the matching option line
    "$PATHRUNNER" show options 2>&1 | strip_ansi | \
        awk -v opt="$option" '$1 == opt { match($0, /  (Yes|No) +/); print substr($0, RSTART+RLENGTH) }' | head -1
}

# ──────────────────────────────────────────────────────────────
# Extract the usable value from an ARN for a given option.
# Some options want the full ARN; others want just the name.
# ──────────────────────────────────────────────────────────────

extract_value_from_arn() {
    local arn="$1" option="$2"
    case "$option" in
        INSTANCE_ID)
            # arn:aws:ec2:REGION:ACCOUNT:instance/i-XXXXX — extract just the instance ID
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        FUNCTION_NAME)
            # arn:aws:lambda:region:account:function:NAME
            echo "$arn" | rev | cut -d: -f1 | rev
            ;;
        TARGET_USER|GROUP_NAME|CLUSTER_NAME|TASK_DEFINITION|PROJECT_NAME)
            # These always want just the name (or family:revision for task definitions)
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        EXECUTION_ROLE_NAME)
            # Just the role name, not the full ARN
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        JOB_DEFINITION)
            # arn:aws:batch:REGION:ACCOUNT:job-definition/NAME:REV — extract NAME:REV
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        JOB_QUEUE)
            # arn:aws:batch:REGION:ACCOUNT:job-queue/NAME — extract NAME
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        INTERPRETER_ID)
            # arn:aws:bedrock-agentcore:REGION:ACCOUNT:code-interpreter/ID — extract ID
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        BROWSER_ID)
            # arn:aws:bedrock-agentcore:REGION:ACCOUNT:browser/ID — extract ID
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        STACK_NAME)
            # arn:aws:cloudformation:REGION:ACCOUNT:stack/NAME/UUID — extract just NAME
            echo "$arn" | sed 's|.*:stack/||' | cut -d/ -f1
            ;;
        JOB_NAME)
            # arn:aws:glue:REGION:ACCOUNT:job/NAME — extract just the job name
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        STACKSET_NAME)
            # arn:aws:cloudformation:region:account:stackset/NAME:UUID — extract just the NAME
            echo "$arn" | sed 's/:[a-f0-9-]*$//' | rev | cut -d/ -f1 | rev
            ;;
        TARGET_ROLE)
            # Some modules want ARN, others want name — check description
            local desc
            desc=$(get_option_description "$option")
            if echo "$desc" | grep -qi "^ARN\|ARN of"; then
                echo "$arn"
            else
                echo "$arn" | rev | cut -d/ -f1 | rev
            fi
            ;;
        CONTAINER_URI)
            # Convert ECR repository ARN to docker pull URI with :latest tag.
            # Input:  arn:aws:ecr:REGION:ACCOUNT:repository/NAME
            # Output: ACCOUNT.dkr.ecr.REGION.amazonaws.com/NAME:latest
            local ecr_account ecr_region ecr_repo_name
            ecr_account=$(echo "$arn" | cut -d: -f5)
            ecr_region=$(echo "$arn" | cut -d: -f4)
            ecr_repo_name=$(echo "$arn" | sed 's|.*:repository/||')
            echo "${ecr_account}.dkr.ecr.${ecr_region}.amazonaws.com/${ecr_repo_name}:latest"
            ;;
        APP_NAME)
            # arn:aws:codedeploy:REGION:ACCOUNT:application:NAME — extract just the app name
            echo "$arn" | rev | cut -d: -f1 | rev
            ;;
        DEPLOYMENT_GROUP)
            # arn:aws:codedeploy:REGION:ACCOUNT:deploymentgroup:APP/GROUP — extract just the group name
            echo "$arn" | rev | cut -d/ -f1 | rev
            ;;
        BUCKET|CODE_BUCKET|EXFIL_BUCKET)
            # arn:aws:s3:::BUCKET-NAME — extract just the bucket name
            echo "$arn" | rev | cut -d: -f1 | rev
            ;;
        CODE_KEY)
            # arn:aws:s3:::BUCKET-NAME/object/key — extract just the object key
            echo "$arn" | sed 's|arn:aws:s3:::[^/]*/||'
            ;;
        *)
            # ROLE_ARN, POLICY_ARN, STREAM_ARN, INSTANCE_PROFILE, EXECUTION_ROLE_ARN,
            # SERVICE_ARN, TARGET_RUNTIME_ARN, ADMIN_ROLE_ARN — full ARN
            echo "$arn"
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────
# Build and push a container image to an ECR repository.
# Called when the test script auto-maps an ECR repo ARN to
# CONTAINER_URI — the repo exists (Terraform created it) but
# has no image pushed yet (demo_attack.sh normally does this).
#
# For repos whose name contains "aws-cli", pulls the public
# public.ecr.aws/aws-cli/aws-cli:latest image and re-tags+pushes
# it rather than building from the local bedrock-runtime source.
# ──────────────────────────────────────────────────────────────

build_and_push_container_image() {
    local container_uri="$1"

    # Extract registry and region from the URI.
    # Format: ACCOUNT.dkr.ecr.REGION.amazonaws.com/NAME:TAG
    local ecr_registry ecr_region
    ecr_registry=$(echo "$container_uri" | cut -d'/' -f1)
    ecr_region=$(echo "$ecr_registry" | sed -E 's/[^.]+\.dkr\.ecr\.([^.]+)\.amazonaws\.com/\1/')

    if [[ -z "$ecr_region" || "$ecr_region" == "$ecr_registry" ]]; then
        fail "Could not extract region from container URI: $container_uri"
        return 1
    fi

    # Check docker is available
    if ! command -v docker &>/dev/null; then
        fail "docker not found — cannot build/push container image"
        return 1
    fi

    # Authenticate to ECR using the plabs production profile
    local plabs_prod_profile
    plabs_prod_profile=$("$PLABS" info 2>&1 | grep "Production:" | sed 's/.*profile: //' | tr -d '[:space:]') || true

    # Extract the repo name (strip registry prefix and tag suffix) to decide
    # whether to build from local source or pull-and-push a public image.
    local repo_name
    repo_name=$(echo "$container_uri" | sed 's|[^/]*/||; s|:.*||')

    if [[ "$repo_name" == *"aws-cli"* ]]; then
        # The omics-001 scenario uses a plain aws-cli image sourced from the
        # public ECR gallery. Pull it and re-tag+push it to the private repo.
        # The private ECR repo is in the attacker account, so use the attacker
        # profile rather than the production (victim) profile.
        local plabs_attacker_profile
        plabs_attacker_profile=$("$PLABS" info 2>&1 | grep "Attacker:" | sed 's/.*profile: //' | tr -d '[:space:]') || true

        local public_image="public.ecr.aws/aws-cli/aws-cli:latest"
        info "Pulling public aws-cli image and pushing to private ECR: $container_uri ..."
        set +e
        (
            unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
            if [[ -n "$plabs_attacker_profile" ]]; then
                export AWS_PROFILE="$plabs_attacker_profile"
            fi

            # Log in to the public ECR gallery (us-east-1 is the only valid region)
            aws ecr-public get-login-password --region us-east-1 \
            | docker login --username AWS --password-stdin public.ecr.aws

            # Pull the linux/amd64 variant explicitly: HealthOmics runs on x86_64 and
            # will return "exec format error" if given an arm64 image.
            docker pull --platform linux/amd64 "$public_image"
            docker tag "$public_image" "$container_uri"

            aws ecr get-login-password --region "$ecr_region" \
            | docker login --username AWS --password-stdin "$ecr_registry"

            docker push "$container_uri"
        )
        local push_exit=$?
        set -e

        if [[ $push_exit -ne 0 ]]; then
            fail "Failed to pull and push aws-cli container image"
            return 1
        fi
    else
        # Default: build from the local bedrock-runtime source directory.
        local container_dir
        container_dir="$PROJECT_DIR/pkg/attacker/containers/bedrock-runtime"
        if [[ ! -d "$container_dir" ]]; then
            fail "Container directory not found: $container_dir"
            return 1
        fi

        # Run login + build in a single subshell with the attacker account's
        # AWS profile. We unset key/secret/token env vars AND set AWS_PROFILE
        # explicitly so that all credential resolution (docker login, buildx
        # push, ECR credential helpers) uses the attacker account -- not the
        # victim identity or the operator's default profile.
        info "Authenticating to ECR and building container image: $container_uri ..."
        set +e
        (
            unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
            if [[ -n "$plabs_prod_profile" ]]; then
                export AWS_PROFILE="$plabs_prod_profile"
            fi

            aws ecr get-login-password --region "$ecr_region" \
            | docker login --username AWS --password-stdin "$ecr_registry"

            docker buildx build \
                --platform linux/arm64 \
                --provenance=false \
                --push \
                --tag "$container_uri" \
                "$container_dir"
        )
        local build_exit=$?
        set -e

        if [[ $build_exit -ne 0 ]]; then
            fail "Failed to build and push container image"
            return 1
        fi
    fi

    success "Container image pushed: $container_uri"
}

# ──────────────────────────────────────────────────────────────
# Parse module options from pathrunner show options output.
# get_required_options: returns only required option names
# get_all_option_names: returns all option names
# ──────────────────────────────────────────────────────────────

get_required_options() {
    "$PATHRUNNER" show options 2>&1 | strip_ansi | \
        awk '/^[A-Z][A-Z_]+/ && /  Yes  / { print $1 }'
}

get_all_option_names() {
    "$PATHRUNNER" show options 2>&1 | strip_ansi | \
        awk '/^[A-Z][A-Z_]+/ && /  (Yes|No)  / { print $1 }'
}

# ──────────────────────────────────────────────────────────────
# Parse available payloads from pathrunner show payloads output.
# ──────────────────────────────────────────────────────────────

get_available_payloads() {
    "$PATHRUNNER" show payloads 2>&1 | strip_ansi | \
        awk '/\// && !/^Module|^---/ { for(i=1;i<=NF;i++) if($i ~ /\//) { print $i; break } }'
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
            awk '/^[A-Z][A-Z_]+/ && /  Yes  / && /<not set>/ { print $1 }')

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
                    if [[ -t 0 ]]; then
                        read -rp "  Enter value for $opt (or Enter to skip): " manual_val
                        if [[ -n "$manual_val" ]]; then
                            "$PATHRUNNER" set "$opt" "$manual_val" 2>&1
                        fi
                    else
                        warn "Non-interactive mode: skipping $opt"
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
    local exploit_error=""

    local clean_output
    clean_output=$(strip_ansi < "$output_file")

    # Strip noise lines before error detection:
    # - "[harness stderr]" and "[runtime stderr]" are container log pass-through, not errors.
    # - "Warning:" prefixed lines are non-fatal module advisories (e.g., cleanup restore
    #   failures when the starting user lacks PassRole on the original role). These should
    #   not trigger a FAIL when the exploit itself succeeded (exit code 0).
    local error_check_output
    error_check_output=$(echo "$clean_output" \
        | grep -vE "^\[(harness|runtime) stderr\]" \
        | grep -vE "^Warning:")

    # Check for explicit error indicators in the exploit output, even if exit code was 0.
    # Pathrunner sometimes exits 0 when it hits a soft failure (missing options, resolution errors).
    if echo "$error_check_output" | grep -qiE "no value provided for|Error:.*missing required|could not resolve|failed to|error occurred|AccessDenied|UnauthorizedAccess|is not authorized|InvalidParameter|ValidationException"; then
        exploit_error=$(echo "$error_check_output" | grep -iE "no value provided for|Error:.*missing required|could not resolve|failed to|error occurred|AccessDenied|UnauthorizedAccess|is not authorized|InvalidParameter|ValidationException" | head -5)
        execution="FAIL"
    elif [[ $exit_code -eq 0 ]]; then
        execution="PASS"
    fi

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
        fail "Exploit failed (exit code: $exit_code)"
        if [[ -n "$exploit_error" ]]; then
            echo ""
            fail "Error details from exploit output:"
            echo "$exploit_error" | while IFS= read -r line; do
                echo -e "  ${RED}${line}${NC}"
            done
        fi
    fi

    # Verify escalation by calling iam:ListUsers from the escalated principal.
    # For exfil payloads: the auto-imported identity has the escalated role creds.
    # For backdoor payloads: the starting user itself was elevated.
    echo ""

    # Skip verification entirely if the exploit itself failed — no point waiting 20s
    if [[ "$execution" == "FAIL" ]]; then
        warn "Skipping privilege verification — exploit did not succeed"
        RESULT_VERIFIED+=("SKIP")
    else
        local escalated_identity=""
        escalated_identity=$(strip_ansi < "$output_file" | sed -n "s/.*Added identity '\([^']*\)'.*/\1/p" | head -1)

        if [[ -n "$escalated_identity" ]]; then
            info "Switching to escalated identity ($escalated_identity) for verification..."
            "$PATHRUNNER" identity switch "$escalated_identity" 2>&1 || true
        fi

        info "Verifying escalated privileges (iam:ListUsers)..."
        local verify_output verify_exit verified="NO"

        for attempt in 1 2 3; do
            set +e
            verify_output=$(AWS_PAGER="" "$PATHRUNNER" aws iam list-users --max-items 5 --output json 2>&1)
            verify_exit=$?
            set -e

            if [[ $verify_exit -eq 0 ]] && echo "$verify_output" | grep -q '"UserName"'; then
                verified="YES"
                break
            fi

            if (( attempt < 3 )); then
                info "Verification attempt $attempt failed, retrying in 10s (IAM propagation)..."
                echo "$verify_output" | strip_ansi | grep -iE "error|denied|unauthorized" || true
                sleep 10
            fi
        done

        RESULT_VERIFIED+=("$verified")

        if [[ "$verified" == "YES" ]]; then
            success "Privilege escalation confirmed - iam:ListUsers succeeded"
            echo "$verify_output" | head -n 10
        else
            fail "Privilege escalation verification FAILED - iam:ListUsers did not succeed"
            echo "$verify_output"
            RESULT_EXECUTION[$((${#RESULT_EXECUTION[@]} - 1))]="FAIL"
        fi
    fi

    # Switch back to the exploit identity before next payload.
    # If we assumed a starting-role, switch to that (not the user).
    echo ""
    if [[ -n "$ASSUMED_ROLE_ARN" ]]; then
        info "Switching back to assumed role identity..."
        "$PATHRUNNER" identity switch "${SCENARIO_ID}-role" 2>&1 || true
    else
        info "Switching back to starting identity..."
        "$PATHRUNNER" identity switch "$STARTING_IDENTITY" 2>&1 || true
    fi
}

# ──────────────────────────────────────────────────────────────
# Verify no leftover resources after all tests
# ──────────────────────────────────────────────────────────────

verify_cleanup() {
    header "Cleanup Verification"
    local has_issues=false

    # Check workspace report for any remaining tracked resources for this module
    info "Checking tracked resources for module $MODULE_ID..."
    local report_output
    report_output=$("$PATHRUNNER" workspace report --module "$MODULE_ID" 2>&1) || true
    local clean_report
    clean_report=$(echo "$report_output" | strip_ansi)

    if echo "$clean_report" | grep -qE "No resources|no tracked resources|0 resources"; then
        success "No tracked resources remaining for $MODULE_ID"
    elif echo "$clean_report" | grep -qE "arn:aws:|Resource"; then
        warn "Found remaining tracked resources for $MODULE_ID:"
        echo "$report_output"
        has_issues=true
    else
        success "No tracked resources remaining for $MODULE_ID"
    fi

    # Module-specific AWS verification based on module type
    case "$MODULE_ID" in
        lambda-*)
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
            ;;
    esac

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
    echo -e "${BOLD}+${bp}+===========+================+==========+${NC}"
    local ph
    ph=$(printf "%-${pw}s" "Payload")
    echo -e "${BOLD}| ${ph} | Execution | Creds Obtained | Verified |${NC}"
    echo -e "${BOLD}+${bp}+===========+================+==========+${NC}"

    for i in "${!RESULT_PAYLOADS[@]}"; do
        local exec_color="$RED" creds_color="$RED" ver_color="$RED"
        [[ "${RESULT_EXECUTION[$i]}" == "PASS" ]] && exec_color="$GREEN"
        [[ "${RESULT_CREDS[$i]}" == "YES" ]] && creds_color="$GREEN"
        [[ "${RESULT_VERIFIED[$i]}" == "YES" ]] && ver_color="$GREEN"
        [[ "${RESULT_VERIFIED[$i]}" == "SKIP" ]] && ver_color="$YELLOW"

        local ps es cs vs
        ps=$(printf "%-${pw}s" "${RESULT_PAYLOADS[$i]}")
        es=$(printf "%-9s" "${RESULT_EXECUTION[$i]}")
        cs=$(printf "%-14s" "${RESULT_CREDS[$i]}")
        vs=$(printf "%-8s" "${RESULT_VERIFIED[$i]}")

        echo -e "| ${ps} | ${exec_color}${es}${NC} | ${creds_color}${cs}${NC} | ${ver_color}${vs}${NC} |"
    done

    echo -e "${BOLD}+${bp}+===========+================+==========+${NC}"
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

    # Switch to (or create) the module-specific test workspace.
    # Each module gets its own workspace to prevent concurrent agent collisions.
    info "Switching to '${TEST_WORKSPACE}' workspace..."
    if "$PATHRUNNER" workspace switch "$TEST_WORKSPACE" 2>&1 | grep -q "Switched"; then
        success "Using existing '${TEST_WORKSPACE}' workspace"
    else
        "$PATHRUNNER" workspace create "$TEST_WORKSPACE" 2>&1
        success "Created '${TEST_WORKSPACE}' workspace"
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

    # Always add fresh credentials under the scenario ID name (overwrites stale creds
    # from previous runs — storeIdentity does im.identities[name] = identity, no error
    # on duplicate). Never skip this in favour of a pre-existing identity switch, because
    # the scenario may have been re-deployed with new keys since the last run.
    STARTING_IDENTITY="$SCENARIO_ID"
    info "Adding/refreshing identity: $STARTING_IDENTITY"
    local add_output
    add_output=$("$PATHRUNNER" identity add \
        --access "$access_key" --secret "$secret_key" \
        --name "$STARTING_IDENTITY" --switch 2>&1)
    echo "$add_output"
    if ! echo "$add_output" | grep -qiE "added|switched|active|success"; then
        fail "identity add may have failed — check output above before continuing"
    fi
    success "Active identity: $STARTING_IDENTITY"

    # ── Phase 3: Module Configuration ──────────────────────────
    header "Phase 3: Module Configuration"

    info "Loading module: $MODULE_ID"
    "$PATHRUNNER" use "$MODULE_ID" 2>&1

    # Get module option names (ALL_OPTIONS is used by map_arn_to_option)
    local required_options
    required_options=$(get_required_options)
    ALL_OPTIONS=$(get_all_option_names)
    info "Required options: $(echo $required_options | tr '\n' ' ')"

    # Map deployed resources to module options
    declare -A option_candidates

    while IFS= read -r arn; do
        [[ -z "$arn" ]] && continue

        local opt
        opt=$(map_arn_to_option "$arn")
        [[ -z "$opt" ]] && continue

        local val
        val=$(extract_value_from_arn "$arn" "$opt")

        # Track when CONTAINER_URI is mapped from an ECR repo — we'll need to
        # build and push the container image after options are set.
        if [[ "$opt" == "CONTAINER_URI" ]]; then
            ECR_CONTAINER_URI="$val"
        fi

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
            # Try to auto-select: prefer "target" ARN for role options
            local auto_selected=""
            for val in "${vals[@]}"; do
                if [[ "$val" == *"target"* ]]; then
                    auto_selected="$val"
                    break
                fi
            done

            if [[ -n "$auto_selected" ]]; then
                info "Auto-setting $opt = $auto_selected (preferred 'target' candidate)"
                "$PATHRUNNER" set "$opt" "$auto_selected" 2>&1
            elif [[ -t 0 ]]; then
                echo ""
                warn "Multiple candidates for $opt:"
                select val in "${vals[@]}"; do
                    if [[ -n "$val" ]]; then
                        info "Setting $opt = $val"
                        "$PATHRUNNER" set "$opt" "$val" 2>&1
                        break
                    fi
                done
            else
                # Non-interactive: pick the first candidate
                info "Auto-setting $opt = ${vals[0]} (first candidate, non-interactive)"
                "$PATHRUNNER" set "$opt" "${vals[0]}" 2>&1
            fi
        fi
    done

    # Set region (default for all current scenarios)
    "$PATHRUNNER" set REGION us-east-1 2>&1 || true

    # Check for unset required options (except PAYLOAD, set per-test)
    for opt in $required_options; do
        [[ "$opt" == "PAYLOAD" ]] && continue
        if [[ -z "${option_candidates[$opt]:-}" ]]; then
            # Try discovery-based auto-fill for known option types
            local discovered=""
            case "$opt" in
                CONTAINER_INSTANCE_ARN)
                    # Discover container instance from the cluster
                    local ci_cluster="${option_candidates[CLUSTER_NAME]:-}"
                    if [[ -z "$ci_cluster" ]]; then
                        ci_cluster=$("$PATHRUNNER" show options 2>&1 | strip_ansi | awk '$1 == "CLUSTER_NAME" { print $2 }')
                    fi
                    if [[ -n "$ci_cluster" ]]; then
                        info "Discovering container instances in cluster $ci_cluster..."
                        discovered=$("$PATHRUNNER" aws ecs list-container-instances \
                            --cluster "$ci_cluster" --region us-east-1 \
                            --query 'containerInstanceArns[0]' --output text 2>/dev/null) || true
                        if [[ -n "$discovered" && "$discovered" != "None" && "$discovered" != "null" ]]; then
                            info "Auto-setting $opt = $discovered (discovered from cluster)"
                            "$PATHRUNNER" set "$opt" "$discovered" 2>&1
                        else
                            discovered=""
                        fi
                    fi
                    ;;
                CONTAINER_NAME)
                    # Discover container name from the task definition.
                    # The starting user typically lacks ecs:DescribeTaskDefinition,
                    # so we try multiple credential sources.
                    local td_val=""
                    td_val=$("$PATHRUNNER" show options 2>&1 | strip_ansi | awk '$1 == "TASK_DEFINITION" { print $2 }')
                    if [[ -n "$td_val" ]]; then
                        info "Discovering container name from task definition $td_val..."
                        # Try via pathrunner first (uses starting user identity)
                        discovered=$("$PATHRUNNER" aws ecs describe-task-definition \
                            --task-definition "$td_val" --region us-east-1 \
                            --query 'taskDefinition.containerDefinitions[0].name' --output text 2>/dev/null) || true
                        if [[ -z "$discovered" || "$discovered" == "None" || "$discovered" == "null" ]]; then
                            # Fall back to plabs production profile
                            local plabs_prod_profile=""
                            plabs_prod_profile=$("$PLABS" info 2>&1 | grep "Production:" | sed 's/.*profile: //' | tr -d '[:space:]') || true
                            if [[ -n "$plabs_prod_profile" ]]; then
                                discovered=$(AWS_PROFILE="$plabs_prod_profile" aws ecs describe-task-definition \
                                    --task-definition "$td_val" --region us-east-1 \
                                    --query 'taskDefinition.containerDefinitions[0].name' --output text 2>/dev/null) || true
                            fi
                        fi
                        if [[ -z "$discovered" || "$discovered" == "None" || "$discovered" == "null" ]]; then
                            # Fall back to default AWS CLI credentials
                            discovered=$(aws ecs describe-task-definition \
                                --task-definition "$td_val" --region us-east-1 \
                                --query 'taskDefinition.containerDefinitions[0].name' --output text 2>/dev/null) || true
                        fi
                        if [[ -n "$discovered" && "$discovered" != "None" && "$discovered" != "null" ]]; then
                            info "Auto-setting $opt = $discovered (discovered from task definition)"
                            "$PATHRUNNER" set "$opt" "$discovered" 2>&1
                        else
                            discovered=""
                        fi
                    fi
                    ;;
            esac

            if [[ -z "$discovered" ]]; then
                echo ""
                warn "Required option $opt was not auto-mapped from resources"
                if [[ -t 0 ]]; then
                    read -rp "  Enter value for $opt (or Enter to skip): " manual_val
                else
                    warn "Non-interactive mode: skipping $opt"
                    local manual_val=""
                fi
                if [[ -n "$manual_val" ]]; then
                    "$PATHRUNNER" set "$opt" "$manual_val" 2>&1
                fi
            fi
        fi
    done

    # Attempt discovery for CONTAINER_NAME if the module has it and it's not already set.
    # This runs after the required-options loop because CONTAINER_NAME is optional — the
    # module auto-discovers it at execute time, but pre-setting it here avoids a
    # DescribeTaskDefinition call under the starting-user identity (which may lack that permission).
    if echo "$ALL_OPTIONS" | grep -q "^CONTAINER_NAME$"; then
        local current_cn
        current_cn=$("$PATHRUNNER" show options 2>&1 | strip_ansi | awk '$1 == "CONTAINER_NAME" { print $2 }')
        if [[ -z "$current_cn" || "$current_cn" == "<not" ]]; then
            local td_for_cn
            td_for_cn=$("$PATHRUNNER" show options 2>&1 | strip_ansi | awk '$1 == "TASK_DEFINITION" { print $2 }')
            if [[ -n "$td_for_cn" ]]; then
                local cn_discovered=""
                # Try starting user first
                cn_discovered=$("$PATHRUNNER" aws ecs describe-task-definition \
                    --task-definition "$td_for_cn" --region us-east-1 \
                    --query 'taskDefinition.containerDefinitions[0].name' --output text 2>/dev/null) || true
                # Fall back to plabs production profile
                if [[ -z "$cn_discovered" || "$cn_discovered" == "None" || "$cn_discovered" == "null" ]]; then
                    local plabs_prod_profile_cn
                    plabs_prod_profile_cn=$("$PLABS" info 2>&1 | grep "Production:" | sed 's/.*profile: //' | tr -d '[:space:]') || true
                    if [[ -n "$plabs_prod_profile_cn" ]]; then
                        cn_discovered=$(AWS_PROFILE="$plabs_prod_profile_cn" aws ecs describe-task-definition \
                            --task-definition "$td_for_cn" --region us-east-1 \
                            --query 'taskDefinition.containerDefinitions[0].name' --output text 2>/dev/null) || true
                    fi
                fi
                # Fall back to default AWS CLI credentials
                if [[ -z "$cn_discovered" || "$cn_discovered" == "None" || "$cn_discovered" == "null" ]]; then
                    cn_discovered=$(aws ecs describe-task-definition \
                        --task-definition "$td_for_cn" --region us-east-1 \
                        --query 'taskDefinition.containerDefinitions[0].name' --output text 2>/dev/null) || true
                fi
                if [[ -n "$cn_discovered" && "$cn_discovered" != "None" && "$cn_discovered" != "null" ]]; then
                    info "Auto-setting CONTAINER_NAME = $cn_discovered (discovered from task definition)"
                    "$PATHRUNNER" set CONTAINER_NAME "$cn_discovered" 2>&1
                else
                    warn "Could not auto-discover CONTAINER_NAME from task definition $td_for_cn — module will attempt auto-discovery at execute time"
                fi
            fi
        fi
    fi

    # If CONTAINER_URI was auto-mapped from an ECR repo ARN, build and push the
    # container image. The lab's Terraform creates the repo but demo_attack.sh
    # (not Terraform) builds the image — so we need to do it here too.
    if [[ -n "$ECR_CONTAINER_URI" ]]; then
        echo ""
        header "Container Image Build"
        build_and_push_container_image "$ECR_CONTAINER_URI"
    fi

    # Self-escalation role assumption: if the starting identity is a user and ROLE_ARN
    # was auto-mapped from a "starting-role" resource, assume that role so the module
    # executes as the role principal. This handles self-escalation paths (e.g., iam-005)
    # where PutRolePolicy/AttachRolePolicy only work when the caller IS the role.
    if [[ -n "$STARTING_USERNAME" ]]; then
        local role_arn_value
        role_arn_value=$("$PATHRUNNER" show options 2>&1 | strip_ansi | awk '$1 == "ROLE_ARN" && $2 != "<not" { print $2 }')
        if [[ -n "$role_arn_value" && "$role_arn_value" == *"starting"*"role"* ]]; then
            echo ""
            info "Self-escalation detected: starting identity is a user but ROLE_ARN points to a starting-role"
            info "Assuming role $role_arn_value before exploit..."

            local assume_output
            assume_output=$("$PATHRUNNER" aws sts assume-role \
                --role-arn "$role_arn_value" \
                --role-session-name "pathrunner-test-setup" \
                --output json 2>&1) || true

            if echo "$assume_output" | grep -q "AccessKeyId"; then
                local role_access_key role_secret_key role_session_token
                role_access_key=$(echo "$assume_output" | jq -r '.Credentials.AccessKeyId')
                role_secret_key=$(echo "$assume_output" | jq -r '.Credentials.SecretAccessKey')
                role_session_token=$(echo "$assume_output" | jq -r '.Credentials.SessionToken')

                local role_identity_name="${SCENARIO_ID}-role"
                "$PATHRUNNER" identity add \
                    --access "$role_access_key" --secret "$role_secret_key" --token "$role_session_token" \
                    --name "$role_identity_name" --switch 2>&1

                ASSUMED_ROLE_ARN="$role_arn_value"
                success "Assumed starting-role and switched to identity: $role_identity_name"
            else
                warn "Could not assume starting-role — module will run as the starting user"
                echo "$assume_output" | head -3
            fi
        fi
    fi

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
        # Explicit payload(s) on command line — always respected, no menu.
        IFS=',' read -ra payloads <<< "$PAYLOAD_FILTER"
    else
        while IFS= read -r p; do
            [[ -n "$p" ]] && payloads+=("$p")
        done < <(get_available_payloads)

        # Interactive payload picker: only when -i is set, stdin is a TTY,
        # and there are multiple payloads to choose from.
        if [[ "$INTERACTIVE" == true && -t 0 && ${#payloads[@]} -gt 1 ]]; then
            echo ""
            echo -e "${BOLD}Available payloads:${NC}"
            local i
            for i in "${!payloads[@]}"; do
                echo -e "  $((i+1))) ${payloads[$i]}"
            done
            echo -e "  a) Run all (sequential, cleanup between each)"
            echo ""
            local choice
            read -rp "Select payload [1-${#payloads[@]}/a, default=a]: " choice || true

            if [[ -z "$choice" || "$choice" == "a" ]]; then
                : # keep full payloads array — run all
            elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#payloads[@]} )); then
                payloads=("${payloads[$((choice-1))]}")
            else
                warn "Invalid selection '$choice' — running all payloads"
            fi
            echo ""
        fi
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

            # Pause between payloads (not after the last one, interactive mode only)
            if (( n < ${#payloads[@]} )) && [[ -t 0 ]]; then
                echo ""
                read -rp "Press Enter for next payload (or 'q' to quit): " response || true
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
    # Ensure we're in the module-specific test workspace
    "$PATHRUNNER" workspace switch "$TEST_WORKSPACE" 2>&1 || true

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
    if [[ -z "$MODULE_ID" ]]; then
        show_usage
        exit 1
    fi

    info "Module: $MODULE_ID | Scenario: $SCENARIO_ID"

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
            success "Setup complete. Module is configured in the '${TEST_WORKSPACE}' workspace."
            echo -e "  Open pathrunner and switch to the test workspace:"
            echo -e "  ${BOLD}./pathrunner${NC}  then  ${BOLD}workspace switch ${TEST_WORKSPACE}${NC}"
            echo -e "  Or run directly: ${BOLD}./pathrunner exploit${NC}"
            ;;
        cleanup)
            do_cleanup
            ;;
        full)
            do_setup
            do_exploit

            # Summary first — show results before asking about cleanup
            if (( ${#RESULT_PAYLOADS[@]} > 0 )); then
                print_summary
            fi

            # Interactive mode: prompt before cleanup
            local skip_cleanup=false
            if [[ "$INTERACTIVE" == true ]]; then
                echo ""
                read -rp "Run cleanup? [Y/n]: " cleanup_response
                if [[ "$cleanup_response" =~ ^[Nn] ]]; then
                    warn "Skipping cleanup (resources left in place)"
                    skip_cleanup=true
                fi
            fi

            if [[ "$skip_cleanup" == false ]]; then
                # Switch back to the starting user for cleanup
                "$PATHRUNNER" identity switch "$STARTING_IDENTITY" 2>&1 || true

                # Run cleanup for all payloads
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

                verify_cleanup
            fi

            # Record per-payload test results
            if (( ${#RESULT_PAYLOADS[@]} > 0 )); then
                local results_file="$WORK_DIR/test-results.json"
                local results_json="["
                for i in "${!RESULT_PAYLOADS[@]}"; do
                    local fail_reason=""
                    if [[ "${RESULT_EXECUTION[$i]}" == "FAIL" ]]; then
                        local output_file="$WORK_DIR/exploit_${RESULT_PAYLOADS[$i]//\//_}.txt"
                        if [[ -f "$output_file" ]]; then
                            fail_reason=$(strip_ansi < "$output_file" \
                                | grep -vE "^\[(harness|runtime) stderr\]" \
                                | grep -iE "AccessDenied|error occurred|failed to|is not authorized|ValidationException|no value provided|missing required|could not resolve" \
                                | head -1 \
                                | sed 's/"/\\"/g' \
                                | cut -c1-200)
                        fi
                    elif [[ "${RESULT_VERIFIED[$i]}" == "NO" ]]; then
                        fail_reason="privilege verification failed: iam:ListUsers did not succeed"
                    fi

                    (( i > 0 )) && results_json+=","
                    results_json+="{\"payload\":\"${RESULT_PAYLOADS[$i]}\""
                    results_json+=",\"execution\":\"${RESULT_EXECUTION[$i]}\""
                    results_json+=",\"creds_obtained\":\"${RESULT_CREDS[$i]}\""
                    results_json+=",\"verified\":\"${RESULT_VERIFIED[$i]}\""
                    if [[ -n "$fail_reason" ]]; then
                        results_json+=",\"fail_reason\":\"${fail_reason}\""
                    fi
                    results_json+="}"
                done
                results_json+="]"

                echo "$results_json" > "$results_file"
                info "Recording test results for $MODULE_ID..."
                "$PATHRUNNER" modules mark-results "$MODULE_ID" "$SCENARIO_ID" "$results_file" 2>&1 || true
            fi
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
