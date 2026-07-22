// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/attacker"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"    // Import to register EC2 payloads
	_ "github.com/DataDog/pathrunner/pkg/payloads/glue"   // Import to register Glue payloads
	_ "github.com/DataDog/pathrunner/pkg/payloads/lambda" // Import to register Lambda payloads
	"strings"
	"testing"
)

func TestPayloadRegistry(t *testing.T) {
	t.Run("GetPayload_Unambiguous", func(t *testing.T) {
		// exfil/response only exists in Lambda, so GetPayload should work
		payload, err := payloads.GetPayload("exfil/response")
		if err != nil {
			t.Errorf("Expected no error getting exfil/response payload, got: %v", err)
		}
		if payload == nil {
			t.Error("Expected payload to be non-nil")
		}
		if payload.GetName() != "exfil/response" {
			t.Errorf("Expected payload name 'exfil/response', got: %s", payload.GetName())
		}
	})

	t.Run("GetPayload_Ambiguous", func(t *testing.T) {
		// backdoor/attach-policy exists in both Lambda and EC2
		_, err := payloads.GetPayload("backdoor/attach-policy")
		if err == nil {
			t.Error("Expected ambiguity error for backdoor/attach-policy (exists in Lambda and EC2)")
		}
		if err != nil && !strings.Contains(err.Error(), "ambiguous") {
			t.Errorf("Expected ambiguity error, got: %v", err)
		}
	})

	t.Run("GetPayloadForService", func(t *testing.T) {
		// Lambda version of backdoor/attach-policy
		lambdaPayload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if !hasTag(lambdaPayload.GetTags(), payloads.TagServiceLambda) {
			t.Error("Expected Lambda service tag on Lambda payload")
		}

		// EC2 version of backdoor/attach-policy
		ec2Payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if !hasTag(ec2Payload.GetTags(), payloads.TagServiceEC2) {
			t.Error("Expected EC2 service tag on EC2 payload")
		}
	})

	t.Run("GetPayloadForService_NotFound", func(t *testing.T) {
		_, err := payloads.GetPayloadForService("nonexistent/payload", payloads.TagServiceLambda)
		if err == nil {
			t.Error("Expected error for non-existent payload")
		}
	})

	t.Run("GetPayload_NotFound", func(t *testing.T) {
		_, err := payloads.GetPayload("nonexistent/payload")
		if err == nil {
			t.Error("Expected error for non-existent payload, got nil")
		}
	})

	t.Run("GetPayloadsByTags_Lambda", func(t *testing.T) {
		lambdaPayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceLambda})
		if len(lambdaPayloads) == 0 {
			t.Error("Expected at least one Lambda payload")
		}

		for _, payload := range lambdaPayloads {
			if !hasTag(payload.GetTags(), payloads.TagServiceLambda) {
				t.Errorf("Payload %s missing Lambda tag", payload.GetName())
			}
		}
	})

	t.Run("GetPayloadsByTags_Multiple", func(t *testing.T) {
		filteredPayloads := payloads.GetPayloadsByTags([]string{
			payloads.TagServiceLambda,
			payloads.TagLanguagePython,
		})

		if len(filteredPayloads) == 0 {
			t.Error("Expected at least one Lambda Python payload")
		}

		for _, payload := range filteredPayloads {
			tags := payload.GetTags()
			if !hasTag(tags, payloads.TagServiceLambda) {
				t.Errorf("Payload %s missing Lambda tag", payload.GetName())
			}
			if !hasTag(tags, payloads.TagLanguagePython) {
				t.Errorf("Payload %s missing Python tag", payload.GetName())
			}
		}
	})

	t.Run("GetPayloadsByTags_Exfil", func(t *testing.T) {
		exfilPayloads := payloads.GetPayloadsByTags([]string{payloads.TagTechniqueExfil})
		if len(exfilPayloads) < 2 {
			t.Errorf("Expected at least 2 exfil payloads, got: %d", len(exfilPayloads))
		}
	})

	t.Run("GetPayloadsByTags_Backdoor", func(t *testing.T) {
		backdoorPayloads := payloads.GetPayloadsByTags([]string{payloads.TagTechniqueBackdoor})
		if len(backdoorPayloads) < 2 {
			t.Errorf("Expected at least 2 backdoor payloads, got: %d", len(backdoorPayloads))
		}
	})

	t.Run("ListAllPayloads", func(t *testing.T) {
		allPayloads := payloads.ListAllPayloads()
		if len(allPayloads) < 4 {
			t.Errorf("Expected at least 4 payloads, got: %d", len(allPayloads))
		}
	})

	t.Run("CompositeKey_SameNameDifferentServices", func(t *testing.T) {
		// Both exfil/https and backdoor/attach-policy exist in Lambda and EC2
		allPayloads := payloads.ListAllPayloads()

		exfilHTTPSCount := 0
		backdoorAPCount := 0
		for _, p := range allPayloads {
			if p.GetName() == "exfil/https" {
				exfilHTTPSCount++
			}
			if p.GetName() == "backdoor/attach-policy" {
				backdoorAPCount++
			}
		}

		if exfilHTTPSCount != 3 {
			t.Errorf("Expected 3 exfil/https payloads (Lambda + EC2 + Glue), got %d", exfilHTTPSCount)
		}
		if backdoorAPCount != 12 {
			t.Errorf("Expected 12 backdoor/attach-policy payloads (all service payload packages imported by unit tests), got %d", backdoorAPCount)
		}
	})

	t.Run("PayloadInterface", func(t *testing.T) {
		allPayloads := payloads.ListAllPayloads()
		for _, payload := range allPayloads {
			if payload.GetName() == "" {
				t.Error("Payload has empty name")
			}
			if payload.GetDescription() == "" {
				t.Error("Payload has empty description")
			}
			if len(payload.GetTags()) == 0 {
				t.Errorf("Payload %s has no tags", payload.GetName())
			}

			// Test GenerateCode with empty options (may fail, just testing interface)
			_, _ = payload.GenerateCode(map[string]string{})

			// Test ProcessResult with empty result (may fail, just testing interface)
			_, _ = payload.ProcessResult("")

			// Test Validate with empty options (may fail, just testing interface)
			_ = payload.Validate(map[string]string{})
		}
	})

	t.Run("TagFilter_Matches", func(t *testing.T) {
		filter := &payloads.TagFilter{
			RequireAll: []string{payloads.TagServiceLambda, payloads.TagLanguagePython},
			RequireAny: []string{},
			Exclude:    []string{},
		}

		tags := []string{payloads.TagServiceLambda, payloads.TagLanguagePython, payloads.TagTechniqueExfil}
		if !filter.Matches(tags) {
			t.Error("Expected filter to match tags")
		}
	})

	t.Run("TagFilter_RequireAny", func(t *testing.T) {
		filter := &payloads.TagFilter{
			RequireAll: []string{},
			RequireAny: []string{payloads.TagTechniqueExfil, payloads.TagTechniqueBackdoor},
			Exclude:    []string{},
		}

		exfilTags := []string{payloads.TagServiceLambda, payloads.TagTechniqueExfil}
		if !filter.Matches(exfilTags) {
			t.Error("Expected filter to match exfil tags")
		}

		backdoorTags := []string{payloads.TagServiceLambda, payloads.TagTechniqueBackdoor}
		if !filter.Matches(backdoorTags) {
			t.Error("Expected filter to match backdoor tags")
		}

		neitherTags := []string{payloads.TagServiceLambda}
		if filter.Matches(neitherTags) {
			t.Error("Expected filter to not match tags without required any")
		}
	})

	t.Run("TagFilter_Exclude", func(t *testing.T) {
		filter := &payloads.TagFilter{
			RequireAll: []string{payloads.TagServiceLambda},
			RequireAny: []string{},
			Exclude:    []string{payloads.TagTechniqueBackdoor},
		}

		exfilTags := []string{payloads.TagServiceLambda, payloads.TagTechniqueExfil}
		if !filter.Matches(exfilTags) {
			t.Error("Expected filter to match exfil tags")
		}

		backdoorTags := []string{payloads.TagServiceLambda, payloads.TagTechniqueBackdoor}
		if filter.Matches(backdoorTags) {
			t.Error("Expected filter to exclude backdoor tags")
		}
	})

	t.Run("GetPayloadsByFilter", func(t *testing.T) {
		filter := &payloads.TagFilter{
			RequireAll: []string{payloads.TagServiceLambda},
			RequireAny: []string{},
			Exclude:    []string{payloads.TagTechniqueBackdoor},
		}

		filteredPayloads := payloads.GetPayloadsByFilter(filter)
		if len(filteredPayloads) < 2 {
			t.Errorf("Expected at least 2 payloads, got: %d", len(filteredPayloads))
		}

		for _, payload := range filteredPayloads {
			if hasTag(payload.GetTags(), payloads.TagTechniqueBackdoor) {
				t.Errorf("Payload %s should have been excluded", payload.GetName())
			}
		}
	})

	t.Run("GetPayloadInfo", func(t *testing.T) {
		info, err := payloads.GetPayloadInfo("exfil/response")
		if err != nil {
			t.Errorf("Expected no error getting payload info, got: %v", err)
		}
		if info.Name != "exfil/response" {
			t.Errorf("Expected name 'exfil/response', got: %s", info.Name)
		}
		if info.Description == "" {
			t.Error("Expected non-empty description")
		}
		if len(info.Tags) == 0 {
			t.Error("Expected non-empty tags")
		}
	})

	t.Run("QualifiedName", func(t *testing.T) {
		qn := payloads.QualifiedName("lambda", "backdoor/attach-policy")
		if qn != "lambda:backdoor/attach-policy" {
			t.Errorf("Expected 'lambda:backdoor/attach-policy', got '%s'", qn)
		}
	})
}

func TestPayloadValidation(t *testing.T) {
	t.Run("ExfilHTTPS_RequiresURL", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("exfil/https", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		err = payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing HTTPS_URL")
		}

		err = payload.Validate(map[string]string{"HTTPS_URL": "https://example.com"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorCreateRole_RequiresTrustedPrincipal", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		err = payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TRUST_PRINCIPAL")
		}

		err = payload.Validate(map[string]string{"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:user/attacker"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})
}

func TestSideEffectReporter(t *testing.T) {
	t.Run("BackdoorAttachPolicy_Lambda_ImplementsSideEffectReporter", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/attach-policy (lambda) should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "test-user",
			"POLICY_ARN": "arn:aws:iam::aws:policy/AdministratorAccess",
		})

		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}

		effect := effects[0]
		if effect.Type != "iam:attached-policy" {
			t.Errorf("Expected type 'iam:attached-policy', got '%s'", effect.Type)
		}
		if effect.Metadata["principal_type"] != "user" {
			t.Errorf("Expected principal_type 'user', got '%s'", effect.Metadata["principal_type"])
		}
		if effect.Metadata["principal_name"] != "test-user" {
			t.Errorf("Expected principal_name 'test-user', got '%s'", effect.Metadata["principal_name"])
		}
		if effect.Metadata["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" {
			t.Errorf("Expected correct policy_arn, got '%s'", effect.Metadata["policy_arn"])
		}
		if effect.CleanupMethod != "iam:DetachUserPolicy" {
			t.Errorf("Expected cleanup method 'iam:DetachUserPolicy', got '%s'", effect.CleanupMethod)
		}
	})

	t.Run("BackdoorAttachPolicy_DefaultPolicyARN", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "my-user",
		})

		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}

		if effects[0].Metadata["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" {
			t.Errorf("Expected default AdministratorAccess policy, got '%s'", effects[0].Metadata["policy_arn"])
		}
	})

	t.Run("BackdoorAttachPolicy_EC2_ImplementsSideEffectReporter", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/attach-policy (ec2) should implement SideEffectReporter")
		}

		// Test user principal via ARN (ARN triggers user detection)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "arn:aws:iam::123456789012:user/test-user",
		})

		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].CleanupMethod != "iam:DetachUserPolicy" {
			t.Errorf("Expected 'iam:DetachUserPolicy' for user, got '%s'", effects[0].CleanupMethod)
		}
		if effects[0].Metadata["principal_type"] != "user" {
			t.Errorf("Expected principal_type 'user', got '%s'", effects[0].Metadata["principal_type"])
		}
	})

	t.Run("BackdoorAttachPolicy_EC2_RolePrincipal", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "arn:aws:iam::123456789012:role/test-role",
		})

		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].CleanupMethod != "iam:DetachRolePolicy" {
			t.Errorf("Expected 'iam:DetachRolePolicy' for role, got '%s'", effects[0].CleanupMethod)
		}
		if effects[0].Metadata["principal_type"] != "role" {
			t.Errorf("Expected principal_type 'role', got '%s'", effects[0].Metadata["principal_type"])
		}
	})

	t.Run("ExfilPayloads_DoNotImplementSideEffectReporter", func(t *testing.T) {
		// exfil/response only exists in Lambda
		payload, err := payloads.GetPayload("exfil/response")
		if err != nil {
			t.Fatalf("Failed to get payload exfil/response: %v", err)
		}
		_, ok := payload.(payloads.SideEffectReporter)
		if ok {
			t.Errorf("Payload exfil/response should NOT implement SideEffectReporter (read-only)")
		}

		// exfil/https exists in both — check Lambda version
		lambdaExfil, err := payloads.GetPayloadForService("exfil/https", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload exfil/https (lambda): %v", err)
		}
		_, ok = lambdaExfil.(payloads.SideEffectReporter)
		if ok {
			t.Errorf("Payload exfil/https (lambda) should NOT implement SideEffectReporter (read-only)")
		}
	})

	t.Run("SideEffectResources_CompatibleWithCleanupHandler", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "cleanup-test-user",
		})

		effect := effects[0]

		if effect.Metadata["principal_type"] == "" {
			t.Error("Side effect must include principal_type in metadata")
		}
		if effect.Metadata["principal_name"] == "" {
			t.Error("Side effect must include principal_name in metadata")
		}
		if effect.Metadata["policy_arn"] == "" {
			t.Error("Side effect must include policy_arn in metadata")
		}
	})

	t.Run("SideEffect_ModuleIDNotSetByPayload", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "test",
		})

		if effects[0].ModuleID != "" {
			t.Errorf("Payload should not set ModuleID (module does that), got '%s'", effects[0].ModuleID)
		}
	})

	t.Run("SideEffect_NameIsReadable", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "alice",
		})

		if !strings.Contains(effects[0].Name, "alice") {
			t.Errorf("Side effect Name should contain target user for readability, got '%s'", effects[0].Name)
		}
	})
}

func TestVerifiableInterface(t *testing.T) {
	t.Run("BackdoorAttachPolicy_ImplementsVerifiable", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		_, ok := payload.(payloads.Verifiable)
		if !ok {
			t.Fatal("backdoor/attach-policy (lambda) should implement Verifiable")
		}
	})

	t.Run("ExfilPayloads_DoNotImplementVerifiable", func(t *testing.T) {
		payload, err := payloads.GetPayload("exfil/response")
		if err != nil {
			t.Fatalf("Failed to get payload exfil/response: %v", err)
		}
		_, ok := payload.(payloads.Verifiable)
		if ok {
			t.Errorf("Payload exfil/response should NOT implement Verifiable")
		}

		lambdaExfil, err := payloads.GetPayloadForService("exfil/https", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get payload exfil/https (lambda): %v", err)
		}
		_, ok = lambdaExfil.(payloads.Verifiable)
		if ok {
			t.Errorf("Payload exfil/https (lambda) should NOT implement Verifiable")
		}
	})
}

func TestSideEffectReporter_ResourceTracking(t *testing.T) {
	t.Run("ModuleIntegration_SetModuleID", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		reporter := payload.(payloads.SideEffectReporter)

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "starting-user",
			"POLICY_ARN": "arn:aws:iam::aws:policy/AdministratorAccess",
		})

		for i := range effects {
			effects[i].ModuleID = "lambda-002"
			effects[i].Region = "us-east-1"
		}

		effect := effects[0]
		if effect.ModuleID != "lambda-002" {
			t.Errorf("Expected ModuleID 'lambda-002', got '%s'", effect.ModuleID)
		}
		if effect.Region != "us-east-1" {
			t.Errorf("Expected Region 'us-east-1', got '%s'", effect.Region)
		}
	})

	t.Run("FullResourceStruct", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceLambda)
		reporter := payload.(payloads.SideEffectReporter)

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "my-user",
		})

		var _ modules.CreatedResource = effects[0] // compile-time check
	})
}

func TestGluePayloads(t *testing.T) {
	t.Run("ExfilHTTPS_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("exfil/https", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue exfil/https payload: %v", err)
		}
		if payload.GetName() != "exfil/https" {
			t.Errorf("Expected name 'exfil/https', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagTransportHTTPS) {
			t.Error("Expected exfil/https to have https transport tag")
		}
	})

	t.Run("ExfilHTTPS_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/https", payloads.TagServiceGlue)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing HTTPS_URL")
		}

		err = payload.Validate(map[string]string{"HTTPS_URL": "not-a-url"})
		if err == nil {
			t.Error("Expected validation error for invalid URL")
		}

		err = payload.Validate(map[string]string{"HTTPS_URL": "https://attacker.example.com/collect"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("ExfilHTTPS_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/https", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"HTTPS_URL": "https://attacker.example.com/collect",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "https://attacker.example.com/collect") {
			t.Error("Generated code should contain the target URL")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
		if !strings.Contains(code, "urllib.request") {
			t.Error("Generated code should use urllib.request for HTTPS POST")
		}
		// Should be a standalone script, not a lambda handler
		if strings.Contains(code, "lambda_handler") {
			t.Error("Glue payload should not contain lambda_handler")
		}
	})

	t.Run("ExfilS3_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue exfil/s3 payload: %v", err)
		}
		if payload.GetName() != "exfil/s3" {
			t.Errorf("Expected name 'exfil/s3', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagTransportFilesystem) {
			t.Error("Expected exfil/s3 to have filesystem transport tag")
		}
	})

	t.Run("ExfilS3_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceGlue)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing EXFIL_BUCKET")
		}

		err = payload.Validate(map[string]string{"EXFIL_BUCKET": "s3://my-bucket"})
		if err == nil {
			t.Error("Expected validation error for S3 URI (should be bucket name only)")
		}

		err = payload.Validate(map[string]string{"EXFIL_BUCKET": "my-exfil-bucket"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("ExfilS3_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"EXFIL_BUCKET": "attacker-exfil-bucket",
			"EXFIL_PREFIX": "loot/",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "attacker-exfil-bucket") {
			t.Error("Generated code should contain the exfil bucket name")
		}
		if !strings.Contains(code, "loot/") {
			t.Error("Generated code should contain the exfil prefix")
		}
		if !strings.Contains(code, "s3.put_object") {
			t.Error("Generated code should use s3.put_object for exfiltration")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
	})

	t.Run("RevshellTLS_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue revshell/tls payload: %v", err)
		}
		if payload.GetName() != "revshell/tls" {
			t.Errorf("Expected name 'revshell/tls', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagTechniqueAccess) {
			t.Error("Expected revshell/tls to have access technique tag")
		}
		if !hasTag(payload.GetTags(), payloads.TagTransportHTTPS) {
			t.Error("Expected revshell/tls to have https transport tag")
		}
	})

	t.Run("RevshellTLS_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceGlue)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing LISTENER_IP")
		}

		// LISTENER_PORT is optional (defaults to 4444), so only LISTENER_IP is required
		err = payload.Validate(map[string]string{"LISTENER_IP": "10.0.0.1"})
		if err != nil {
			t.Errorf("Expected no validation error with just LISTENER_IP, got: %v", err)
		}

		err = payload.Validate(map[string]string{"LISTENER_IP": "10.0.0.1", "LISTENER_PORT": "4443"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("RevshellTLS_InputSanitization", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceGlue)

		err := payload.Validate(map[string]string{"LISTENER_IP": "'; rm -rf /; '", "LISTENER_PORT": "4443"})
		if err == nil {
			t.Error("Expected validation error for LISTENER_IP containing single quotes")
		}
	})

	t.Run("RevshellTLS_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"LISTENER_IP":   "10.0.0.1",
			"LISTENER_PORT": "4443",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "10.0.0.1") {
			t.Error("Generated code should contain LISTENER_IP")
		}
		if !strings.Contains(code, "4443") {
			t.Error("Generated code should contain LISTENER_PORT")
		}
		if !strings.Contains(code, "ssl.SSLContext") {
			t.Error("Generated code should use ssl.SSLContext for TLS")
		}
		if !strings.Contains(code, "subprocess.call") {
			t.Error("Generated code should use subprocess.call for shell execution")
		}
	})

	t.Run("ExfilCloudWatch_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("exfil/cloudwatch", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue exfil/cloudwatch payload: %v", err)
		}
		if payload.GetName() != "exfil/cloudwatch" {
			t.Errorf("Expected name 'exfil/cloudwatch', got '%s'", payload.GetName())
		}
	})

	t.Run("BackdoorAttachPolicy_Glue_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue backdoor/attach-policy payload: %v", err)
		}
		if !hasTag(payload.GetTags(), payloads.TagServiceGlue) {
			t.Error("Expected glue tag on backdoor/attach-policy")
		}
	})

	t.Run("BackdoorAttachPolicy_Glue_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceGlue)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("Glue backdoor/attach-policy should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "victim-user",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:attached-policy" {
			t.Errorf("Expected type 'iam:attached-policy', got '%s'", effects[0].Type)
		}
	})

	t.Run("BackdoorAttachPolicy_Glue_Verifiable", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy", payloads.TagServiceGlue)
		_, ok := payload.(payloads.Verifiable)
		if !ok {
			t.Fatal("Glue backdoor/attach-policy should implement Verifiable")
		}
	})

	t.Run("AllGluePayloads_StandaloneScripts", func(t *testing.T) {
		gluePayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceGlue})
		if len(gluePayloads) == 0 {
			t.Fatal("Expected at least one Glue payload registered")
		}

		for _, p := range gluePayloads {
			// Build minimal valid options for code generation
			opts := map[string]string{}
			for _, opt := range p.GetOptions() {
				if opt.Required {
					switch opt.Name {
					case "TARGET_ARN":
						opts["TARGET_ARN"] = "test-user"
					case "HTTPS_URL":
						opts["HTTPS_URL"] = "https://test.example.com"
					case "EXFIL_BUCKET":
						opts["EXFIL_BUCKET"] = "test-bucket"
					case "LISTENER_IP":
						opts["LISTENER_IP"] = "10.0.0.1"
					case "LISTENER_PORT":
						opts["LISTENER_PORT"] = "4444"
					}
				}
			}

			code, err := p.GenerateCode(opts)
			if err != nil {
				t.Errorf("Glue payload '%s' failed to generate code: %v", p.GetName(), err)
				continue
			}

			// Glue payloads should be standalone Python scripts, not Lambda handlers
			if strings.Contains(code, "lambda_handler") {
				t.Errorf("Glue payload '%s' should not contain lambda_handler", p.GetName())
			}

			// All should have python tag
			if !hasTag(p.GetTags(), payloads.TagLanguagePython) {
				t.Errorf("Glue payload '%s' should have python language tag", p.GetName())
			}
		}
	})
}

func TestNewLambdaPayloads(t *testing.T) {
	t.Run("BackdoorCreateAccessKey_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get lambda backdoor/create-access-key: %v", err)
		}
		if payload.GetName() != "backdoor/create-access-key" {
			t.Errorf("Expected name 'backdoor/create-access-key', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagServiceLambda) {
			t.Error("Expected lambda service tag")
		}
		if !hasTag(payload.GetTags(), payloads.TagLanguagePython) {
			t.Error("Expected python language tag")
		}
	})

	t.Run("BackdoorCreateAccessKey_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceLambda)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TARGET_ARN")
		}

		// Should reject role ARNs since CreateAccessKey only works on users
		err = payload.Validate(map[string]string{"TARGET_ARN": "arn:aws:iam::123456789012:role/my-role"})
		if err == nil {
			t.Error("Expected validation error for role ARN")
		}

		err = payload.Validate(map[string]string{"TARGET_ARN": "arn:aws:iam::123456789012:user/my-user"})
		if err != nil {
			t.Errorf("Expected no validation error for user ARN, got: %v", err)
		}

		err = payload.Validate(map[string]string{"TARGET_ARN": "my-user"})
		if err != nil {
			t.Errorf("Expected no validation error for plain username, got: %v", err)
		}
	})

	t.Run("BackdoorCreateAccessKey_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceLambda)
		code, err := payload.GenerateCode(map[string]string{
			"TARGET_ARN": "victim-user",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "lambda_handler") {
			t.Error("Lambda payload should contain lambda_handler")
		}
		if !strings.Contains(code, "create_access_key") {
			t.Error("Generated code should call create_access_key")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
	})

	t.Run("BackdoorCreateAccessKey_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceLambda)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/create-access-key should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "victim-user",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:access-key" {
			t.Errorf("Expected type 'iam:access-key', got '%s'", effects[0].Type)
		}
		if effects[0].CleanupMethod != "iam:DeleteAccessKey" {
			t.Errorf("Expected cleanup 'iam:DeleteAccessKey', got '%s'", effects[0].CleanupMethod)
		}
	})

	t.Run("BackdoorUpdateRoleTrust_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get lambda backdoor/update-role-trust: %v", err)
		}
		if payload.GetName() != "backdoor/update-role-trust" {
			t.Errorf("Expected name 'backdoor/update-role-trust', got '%s'", payload.GetName())
		}
	})

	t.Run("BackdoorUpdateRoleTrust_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceLambda)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TARGET_ROLE")
		}

		err = payload.Validate(map[string]string{"TARGET_ROLE": "my-role"})
		if err == nil {
			t.Error("Expected validation error for missing TRUST_PRINCIPAL")
		}

		err = payload.Validate(map[string]string{
			"TARGET_ROLE":     "my-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorUpdateRoleTrust_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceLambda)
		code, err := payload.GenerateCode(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "lambda_handler") {
			t.Error("Lambda payload should contain lambda_handler")
		}
		if !strings.Contains(code, "update_assume_role_policy") {
			t.Error("Generated code should call update_assume_role_policy")
		}
		if !strings.Contains(code, "get_role") {
			t.Error("Generated code should get existing trust policy before modifying")
		}
	})

	t.Run("BackdoorUpdateRoleTrust_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceLambda)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/update-role-trust should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:trust-policy" {
			t.Errorf("Expected type 'iam:trust-policy', got '%s'", effects[0].Type)
		}
		if effects[0].CleanupMethod != "iam:UpdateAssumeRolePolicy" {
			t.Errorf("Expected cleanup 'iam:UpdateAssumeRolePolicy', got '%s'", effects[0].CleanupMethod)
		}
		if effects[0].Metadata["role_name"] != "target-role" {
			t.Errorf("Expected role_name 'target-role', got '%s'", effects[0].Metadata["role_name"])
		}
	})

	t.Run("BackdoorUpdateRoleTrust_ARNParsing", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceLambda)
		reporter := payload.(payloads.SideEffectReporter)

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ROLE":     "arn:aws:iam::123456789012:role/my-target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if effects[0].Metadata["role_name"] != "my-target-role" {
			t.Errorf("Expected role_name parsed from ARN, got '%s'", effects[0].Metadata["role_name"])
		}
	})

	t.Run("ExfilS3_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get lambda exfil/s3: %v", err)
		}
		if payload.GetName() != "exfil/s3" {
			t.Errorf("Expected name 'exfil/s3', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagTechniqueExfil) {
			t.Error("Expected exfil technique tag")
		}
	})

	t.Run("ExfilS3_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceLambda)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing EXFIL_BUCKET")
		}

		err = payload.Validate(map[string]string{"EXFIL_BUCKET": "s3://my-bucket"})
		if err == nil {
			t.Error("Expected validation error for S3 URI")
		}

		err = payload.Validate(map[string]string{"EXFIL_BUCKET": "my-exfil-bucket"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("ExfilS3_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceLambda)
		code, err := payload.GenerateCode(map[string]string{
			"EXFIL_BUCKET": "attacker-bucket",
			"EXFIL_PREFIX": "creds/",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "lambda_handler") {
			t.Error("Lambda payload should contain lambda_handler")
		}
		if !strings.Contains(code, "put_object") {
			t.Error("Generated code should use put_object for S3 upload")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
	})

	t.Run("ExfilS3_NotSideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceLambda)
		_, ok := payload.(payloads.SideEffectReporter)
		if ok {
			t.Error("exfil/s3 should NOT implement SideEffectReporter (read-only credential exfil)")
		}
	})

	t.Run("RevshellTLS_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceLambda)
		if err != nil {
			t.Fatalf("Failed to get lambda revshell/tls: %v", err)
		}
		if payload.GetName() != "revshell/tls" {
			t.Errorf("Expected name 'revshell/tls', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagTechniqueAccess) {
			t.Error("Expected access technique tag")
		}
	})

	t.Run("RevshellTLS_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceLambda)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing LISTENER_IP")
		}

		err = payload.Validate(map[string]string{"LISTENER_IP": "10.0.0.1"})
		if err != nil {
			t.Errorf("Expected no validation error with just LISTENER_IP, got: %v", err)
		}

		err = payload.Validate(map[string]string{"LISTENER_IP": "'; rm -rf /; '"})
		if err == nil {
			t.Error("Expected validation error for LISTENER_IP with single quotes")
		}
	})

	t.Run("RevshellTLS_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceLambda)
		code, err := payload.GenerateCode(map[string]string{
			"LISTENER_IP":   "10.0.0.1",
			"LISTENER_PORT": "4443",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "lambda_handler") {
			t.Error("Lambda payload should contain lambda_handler")
		}
		if !strings.Contains(code, "ssl.SSLContext") {
			t.Error("Generated code should use ssl.SSLContext for TLS")
		}
		if !strings.Contains(code, "subprocess.call") {
			t.Error("Generated code should use subprocess.call for shell execution")
		}
		if !strings.Contains(code, "os.dup2") {
			t.Error("Generated code should redirect stdin/stdout/stderr with os.dup2")
		}
	})

	t.Run("RevshellTLS_NotSideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls", payloads.TagServiceLambda)
		_, ok := payload.(payloads.SideEffectReporter)
		if ok {
			t.Error("revshell/tls should NOT implement SideEffectReporter")
		}
	})

	t.Run("AllLambdaPayloads_HaveLambdaHandler", func(t *testing.T) {
		lambdaPayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceLambda})
		for _, p := range lambdaPayloads {
			opts := buildMinimalValidOptions(p)
			code, err := p.GenerateCode(opts)
			if err != nil {
				t.Errorf("Lambda payload '%s' failed to generate code: %v", p.GetName(), err)
				continue
			}
			if !strings.Contains(code, "lambda_handler") {
				t.Errorf("Lambda payload '%s' should contain lambda_handler", p.GetName())
			}
		}
	})
}

func TestNewEC2Payloads(t *testing.T) {
	t.Run("BackdoorCreateRole_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get ec2 backdoor/create-role: %v", err)
		}
		if payload.GetName() != "backdoor/create-role" {
			t.Errorf("Expected name 'backdoor/create-role', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagServiceEC2) {
			t.Error("Expected ec2 service tag")
		}
		if !hasTag(payload.GetTags(), payloads.TagLanguageBash) {
			t.Error("Expected bash language tag")
		}
	})

	t.Run("BackdoorCreateRole_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceEC2)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TRUST_PRINCIPAL")
		}

		err = payload.Validate(map[string]string{"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorCreateRole_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "#!/bin/bash") {
			t.Error("EC2 payload should be a bash script")
		}
		if !strings.Contains(code, "aws iam create-role") {
			t.Error("Generated code should call aws iam create-role")
		}
		if !strings.Contains(code, "aws iam attach-role-policy") {
			t.Error("Generated code should attach AdministratorAccess policy")
		}
		if !strings.Contains(code, "AdministratorAccess") {
			t.Error("Generated code should reference AdministratorAccess")
		}
	})

	t.Run("BackdoorCreateRole_ServicePrincipal", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"TRUST_PRINCIPAL": "lambda.amazonaws.com",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, `"Service"`) {
			t.Error("Service principal should use 'Service' as principal key")
		}
	})

	t.Run("BackdoorCreateRole_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceEC2)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/create-role should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
			"ROLE_NAME":       "my-backdoor",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:role" {
			t.Errorf("Expected type 'iam:role', got '%s'", effects[0].Type)
		}
		if effects[0].Name != "my-backdoor" {
			t.Errorf("Expected name 'my-backdoor', got '%s'", effects[0].Name)
		}
		if effects[0].CleanupMethod != "iam:DeleteRole" {
			t.Errorf("Expected cleanup 'iam:DeleteRole', got '%s'", effects[0].CleanupMethod)
		}
	})

	t.Run("BackdoorCreateUser_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/create-user", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get ec2 backdoor/create-user: %v", err)
		}
		if payload.GetName() != "backdoor/create-user" {
			t.Errorf("Expected name 'backdoor/create-user', got '%s'", payload.GetName())
		}
	})

	t.Run("BackdoorCreateUser_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-user", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"USER_NAME":      "backdoor-admin",
			"CONSOLE_ACCESS": "true",
			"ACCESS_KEY":     "true",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "#!/bin/bash") {
			t.Error("EC2 payload should be a bash script")
		}
		if !strings.Contains(code, "aws iam create-user") {
			t.Error("Generated code should call aws iam create-user")
		}
		if !strings.Contains(code, "create-login-profile") {
			t.Error("Generated code should create console login profile")
		}
		if !strings.Contains(code, "create-access-key") {
			t.Error("Generated code should create access keys")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
	})

	t.Run("BackdoorCreateUser_NoConsoleAccess", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-user", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"CONSOLE_ACCESS": "false",
			"ACCESS_KEY":     "true",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if strings.Contains(code, "create-login-profile") {
			t.Error("Should not create login profile when CONSOLE_ACCESS is false")
		}
	})

	t.Run("BackdoorCreateUser_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-user", payloads.TagServiceEC2)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/create-user should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"USER_NAME": "backdoor-admin",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:user" {
			t.Errorf("Expected type 'iam:user', got '%s'", effects[0].Type)
		}
		if effects[0].CleanupMethod != "iam:DeleteUser" {
			t.Errorf("Expected cleanup 'iam:DeleteUser', got '%s'", effects[0].CleanupMethod)
		}
	})

	t.Run("BackdoorCreateAccessKey_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get ec2 backdoor/create-access-key: %v", err)
		}
		if !hasTag(payload.GetTags(), payloads.TagServiceEC2) {
			t.Error("Expected ec2 service tag")
		}
	})

	t.Run("BackdoorCreateAccessKey_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceEC2)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TARGET_ARN")
		}

		err = payload.Validate(map[string]string{"TARGET_ARN": "victim-user"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorCreateAccessKey_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"TARGET_ARN": "victim-user",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "#!/bin/bash") {
			t.Error("EC2 payload should be a bash script")
		}
		if !strings.Contains(code, "aws iam create-access-key") {
			t.Error("Generated code should call aws iam create-access-key")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
	})

	t.Run("BackdoorCreateAccessKey_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key", payloads.TagServiceEC2)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/create-access-key should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ARN": "victim-user",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:access-key" {
			t.Errorf("Expected type 'iam:access-key', got '%s'", effects[0].Type)
		}
	})

	t.Run("BackdoorUpdateRoleTrust_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get ec2 backdoor/update-role-trust: %v", err)
		}
		if payload.GetName() != "backdoor/update-role-trust" {
			t.Errorf("Expected name 'backdoor/update-role-trust', got '%s'", payload.GetName())
		}
	})

	t.Run("BackdoorUpdateRoleTrust_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceEC2)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TARGET_ROLE")
		}

		err = payload.Validate(map[string]string{"TARGET_ROLE": "my-role"})
		if err == nil {
			t.Error("Expected validation error for missing TRUST_PRINCIPAL")
		}

		err = payload.Validate(map[string]string{
			"TARGET_ROLE":     "my-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorUpdateRoleTrust_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "#!/bin/bash") {
			t.Error("EC2 payload should be a bash script")
		}
		if !strings.Contains(code, "aws iam get-role") {
			t.Error("Generated code should get existing role trust policy")
		}
		if !strings.Contains(code, "aws iam update-assume-role-policy") {
			t.Error("Generated code should update trust policy")
		}
		if !strings.Contains(code, "jq") {
			t.Error("Generated code should use jq for JSON manipulation")
		}
	})

	t.Run("BackdoorUpdateRoleTrust_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceEC2)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/update-role-trust should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:trust-policy" {
			t.Errorf("Expected type 'iam:trust-policy', got '%s'", effects[0].Type)
		}
		if effects[0].Metadata["target_role"] != "target-role" {
			t.Errorf("Expected target_role 'target-role', got '%s'", effects[0].Metadata["target_role"])
		}
	})

	t.Run("ExfilS3_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceEC2)
		if err != nil {
			t.Fatalf("Failed to get ec2 exfil/s3: %v", err)
		}
		if payload.GetName() != "exfil/s3" {
			t.Errorf("Expected name 'exfil/s3', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagTechniqueExfil) {
			t.Error("Expected exfil technique tag")
		}
	})

	t.Run("ExfilS3_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceEC2)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing EXFIL_BUCKET")
		}

		err = payload.Validate(map[string]string{"EXFIL_BUCKET": "s3://my-bucket"})
		if err == nil {
			t.Error("Expected validation error for S3 URI")
		}

		err = payload.Validate(map[string]string{"EXFIL_BUCKET": "my-bucket"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("ExfilS3_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/s3", payloads.TagServiceEC2)
		code, err := payload.GenerateCode(map[string]string{
			"EXFIL_BUCKET": "attacker-bucket",
			"EXFIL_PREFIX": "loot/",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "#!/bin/bash") {
			t.Error("EC2 payload should be a bash script")
		}
		if !strings.Contains(code, "aws s3 cp") {
			t.Error("Generated code should use aws s3 cp for upload")
		}
		if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
			t.Error("Generated code should include PATHFINDER_IDENTITY_DATA markers")
		}
		if !strings.Contains(code, "attacker-bucket") {
			t.Error("Generated code should contain the bucket name")
		}
	})

	t.Run("AllEC2Payloads_AreBashScripts", func(t *testing.T) {
		ec2Payloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceEC2})
		for _, p := range ec2Payloads {
			opts := buildMinimalValidOptions(p)
			code, err := p.GenerateCode(opts)
			if err != nil {
				t.Errorf("EC2 payload '%s' failed to generate code: %v", p.GetName(), err)
				continue
			}
			if !strings.Contains(code, "#!/bin/bash") {
				t.Errorf("EC2 payload '%s' should be a bash script", p.GetName())
			}
			if !hasTag(p.GetTags(), payloads.TagLanguageBash) {
				t.Errorf("EC2 payload '%s' should have bash language tag", p.GetName())
			}
		}
	})
}

func TestNewGluePayloads(t *testing.T) {
	t.Run("BackdoorCreateRole_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue backdoor/create-role: %v", err)
		}
		if payload.GetName() != "backdoor/create-role" {
			t.Errorf("Expected name 'backdoor/create-role', got '%s'", payload.GetName())
		}
		if !hasTag(payload.GetTags(), payloads.TagServiceGlue) {
			t.Error("Expected glue service tag")
		}
	})

	t.Run("BackdoorCreateRole_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceGlue)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TRUST_PRINCIPAL")
		}

		err = payload.Validate(map[string]string{"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorCreateRole_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if strings.Contains(code, "lambda_handler") {
			t.Error("Glue payload should NOT contain lambda_handler")
		}
		if !strings.Contains(code, "sys.argv") {
			t.Error("Glue payload should use sys.argv for parameter parsing")
		}
		if !strings.Contains(code, "create_role") {
			t.Error("Generated code should call create_role")
		}
		if !strings.Contains(code, "attach_role_policy") {
			t.Error("Generated code should attach AdministratorAccess")
		}
	})

	t.Run("BackdoorCreateRole_ServicePrincipalDetection", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"TRUST_PRINCIPAL": "lambda.amazonaws.com",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if !strings.Contains(code, "Service") {
			t.Error("Service principal should trigger 'Service' principal key detection in code")
		}
	})

	t.Run("BackdoorCreateRole_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-role", payloads.TagServiceGlue)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/create-role should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
			"ROLE_NAME":       "glue-backdoor",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:role" {
			t.Errorf("Expected type 'iam:role', got '%s'", effects[0].Type)
		}
		if effects[0].Name != "glue-backdoor" {
			t.Errorf("Expected name 'glue-backdoor', got '%s'", effects[0].Name)
		}
	})

	t.Run("BackdoorUpdateRoleTrust_Registration", func(t *testing.T) {
		payload, err := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceGlue)
		if err != nil {
			t.Fatalf("Failed to get glue backdoor/update-role-trust: %v", err)
		}
		if payload.GetName() != "backdoor/update-role-trust" {
			t.Errorf("Expected name 'backdoor/update-role-trust', got '%s'", payload.GetName())
		}
	})

	t.Run("BackdoorUpdateRoleTrust_Validation", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceGlue)

		err := payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TARGET_ROLE")
		}

		err = payload.Validate(map[string]string{"TARGET_ROLE": "my-role"})
		if err == nil {
			t.Error("Expected validation error for missing TRUST_PRINCIPAL")
		}

		err = payload.Validate(map[string]string{
			"TARGET_ROLE":     "my-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorUpdateRoleTrust_GenerateCode", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		if strings.Contains(code, "lambda_handler") {
			t.Error("Glue payload should NOT contain lambda_handler")
		}
		if !strings.Contains(code, "sys.argv") {
			t.Error("Glue payload should use sys.argv for parameter parsing")
		}
		if !strings.Contains(code, "update_assume_role_policy") {
			t.Error("Generated code should call update_assume_role_policy")
		}
		if !strings.Contains(code, "get_role") {
			t.Error("Generated code should get existing trust policy")
		}
	})

	t.Run("BackdoorUpdateRoleTrust_AccountIDAutoDetect", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceGlue)
		code, err := payload.GenerateCode(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "123456789012",
		})
		if err != nil {
			t.Fatalf("Failed to generate code: %v", err)
		}
		// The Glue version does 12-digit account ID -> arn:aws:iam::ACCOUNT:root conversion
		if !strings.Contains(code, "isdigit") {
			t.Error("Generated code should handle 12-digit account ID detection")
		}
	})

	t.Run("BackdoorUpdateRoleTrust_SideEffectReporter", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust", payloads.TagServiceGlue)
		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/update-role-trust should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_ROLE":     "target-role",
			"TRUST_PRINCIPAL": "arn:aws:iam::123456789012:root",
		})
		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}
		if effects[0].Type != "iam:trust-policy" {
			t.Errorf("Expected type 'iam:trust-policy', got '%s'", effects[0].Type)
		}
		if effects[0].CleanupMethod != "iam:UpdateAssumeRolePolicy" {
			t.Errorf("Expected cleanup 'iam:UpdateAssumeRolePolicy', got '%s'", effects[0].CleanupMethod)
		}
	})
}

func TestPayloadMatrixCompleteness(t *testing.T) {
	// Verify the unified payload matrix across all three services
	services := map[string]string{
		"lambda": payloads.TagServiceLambda,
		"ec2":    payloads.TagServiceEC2,
		"glue":   payloads.TagServiceGlue,
	}

	// Payloads that should exist in all three services
	universalPayloads := []string{
		"backdoor/attach-policy",
		"backdoor/create-role",
		"backdoor/update-role-trust",
		"exfil/https",
		"exfil/s3",
	}

	for _, payloadName := range universalPayloads {
		for serviceName, serviceTag := range services {
			t.Run(serviceName+"_"+strings.ReplaceAll(payloadName, "/", "_"), func(t *testing.T) {
				_, err := payloads.GetPayloadForService(payloadName, serviceTag)
				if err != nil {
					t.Errorf("Expected %s to exist for %s service, got: %v", payloadName, serviceName, err)
				}
			})
		}
	}

	// Payloads that should exist in specific services
	t.Run("RevshellTLS_AllThreeServices", func(t *testing.T) {
		for serviceName, serviceTag := range services {
			_, err := payloads.GetPayloadForService("revshell/tls", serviceTag)
			if err != nil {
				t.Errorf("Expected revshell/tls for %s, got: %v", serviceName, err)
			}
		}
	})

	t.Run("BackdoorCreateAccessKey_LambdaAndEC2", func(t *testing.T) {
		for _, serviceTag := range []string{payloads.TagServiceLambda, payloads.TagServiceEC2} {
			_, err := payloads.GetPayloadForService("backdoor/create-access-key", serviceTag)
			if err != nil {
				t.Errorf("Expected backdoor/create-access-key for service tag %s, got: %v", serviceTag, err)
			}
		}
	})

	t.Run("BackdoorCreateUser_LambdaEC2Glue", func(t *testing.T) {
		for serviceName, serviceTag := range services {
			_, err := payloads.GetPayloadForService("backdoor/create-user", serviceTag)
			if err != nil {
				t.Errorf("Expected backdoor/create-user for %s, got: %v", serviceName, err)
			}
		}
	})
}

// buildMinimalValidOptions creates the minimum required options for a payload to generate code
func buildMinimalValidOptions(p payloads.Payload) map[string]string {
	opts := map[string]string{}
	for _, opt := range p.GetOptions() {
		if opt.Required {
			switch opt.Name {
			case "TARGET_ARN":
				opts["TARGET_ARN"] = "test-user"
			case "HTTPS_URL":
				opts["HTTPS_URL"] = "https://test.example.com"
			case "EXFIL_BUCKET":
				opts["EXFIL_BUCKET"] = "test-bucket"
			case "LISTENER_IP":
				opts["LISTENER_IP"] = "10.0.0.1"
			case "LISTENER_PORT":
				opts["LISTENER_PORT"] = "4444"
			case "TRUST_PRINCIPAL":
				opts["TRUST_PRINCIPAL"] = "arn:aws:iam::123456789012:root"
			case "TARGET_ROLE":
				opts["TARGET_ROLE"] = "test-role"
			default:
				opts[opt.Name] = "test-value"
			}
		}
	}
	return opts
}

func TestAttackerExfilBucketTracking(t *testing.T) {
	// Verify TrackAttackerBucket works for exfil buckets the same as code buckets
	resource := attacker.TrackAttackerBucket("pathrunner-exfil-abc123", "us-west-2", "glue-003")

	if resource.Type != "s3_bucket" {
		t.Errorf("Expected type 's3_bucket', got '%s'", resource.Type)
	}
	if resource.AccountContext != "attacker" {
		t.Errorf("Expected AccountContext 'attacker', got '%s'", resource.AccountContext)
	}
	if resource.Name != "pathrunner-exfil-abc123" {
		t.Errorf("Expected name 'pathrunner-exfil-abc123', got '%s'", resource.Name)
	}
	if resource.Region != "us-west-2" {
		t.Errorf("Expected region 'us-west-2', got '%s'", resource.Region)
	}
	if resource.ModuleID != "glue-003" {
		t.Errorf("Expected moduleID 'glue-003', got '%s'", resource.ModuleID)
	}
}

// Helper function
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
