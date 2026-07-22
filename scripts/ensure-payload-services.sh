#!/usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
# This product includes software developed at Datadog (https://www.datadoghq.com/)
# Copyright 2026 Datadog, Inc.

set -euo pipefail

# ensure-payload-services.sh — Create payload service directories and blank imports
# for services that don't have them yet.
#
# Usage:
#   ./scripts/ensure-payload-services.sh <service1> [service2] ...
#   ./scripts/ensure-payload-services.sh ecs bedrock batch
#
# For each service:
#   1. Creates pkg/payloads/{service}/doc.go if the directory doesn't exist
#   2. Adds blank import to cmd/pathrunner/main.go if not already present
#
# Idempotent — safe to run multiple times with the same arguments.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MAIN_GO="$PROJECT_DIR/cmd/pathrunner/main.go"

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <service1> [service2] ..." >&2
    exit 1
fi

changed=false

for service in "$@"; do
    service_dir="$PROJECT_DIR/pkg/payloads/$service"
    import_path="pathrunner/pkg/payloads/$service"

    # Create the package directory if it doesn't exist
    if [[ ! -d "$service_dir" ]]; then
        mkdir -p "$service_dir"
        cat > "$service_dir/doc.go" <<EOF
// Package $service provides payload implementations for ${service^^}-based exploit modules.
package $service
EOF
        echo "  created pkg/payloads/$service/doc.go"
        changed=true
    fi

    # Add blank import to main.go if not already present
    if ! grep -q "\"$import_path\"" "$MAIN_GO" 2>/dev/null; then
        # Insert after the last existing payload import line
        # Find the line number of the last _ "pathrunner/pkg/payloads/ import
        last_payload_line=$(grep -n 'pathrunner/pkg/payloads/' "$MAIN_GO" | tail -1 | cut -d: -f1)
        if [[ -n "$last_payload_line" ]]; then
            sed -i '' "${last_payload_line}a\\
	_ \"${import_path}\"
" "$MAIN_GO"
            echo "  added blank import for $import_path to main.go"
            changed=true
        else
            echo "  warning: could not find payload imports section in main.go" >&2
        fi
    fi
done

if [[ "$changed" == true ]]; then
    echo "  running make build..."
    (cd "$PROJECT_DIR" && make build 2>&1 | tail -2)
fi
