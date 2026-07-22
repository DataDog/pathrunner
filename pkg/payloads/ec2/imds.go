// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ec2

// IMDSHelperSnippet returns a bash snippet that sets up IMDS access compatible
// with both IMDSv1 and IMDSv2. It defines an `imds_get` function that the rest
// of the user-data script can call instead of raw curl.
//
// Usage in generated scripts:
//
//	script := IMDSHelperSnippet() + "\n" + "ROLE=$(imds_get /latest/meta-data/iam/security-credentials/)"
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
# --- End IMDS Setup ---`
}
