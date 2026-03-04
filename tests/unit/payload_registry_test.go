package unit

import (
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	_ "pathrunner/pkg/payloads/ec2"    // Import to register EC2 payloads
	_ "pathrunner/pkg/payloads/lambda" // Import to register payloads
	"strings"
	"testing"
)

func TestPayloadRegistry(t *testing.T) {
	t.Run("GetPayload", func(t *testing.T) {
		// Test retrieving an existing payload
		payload, err := payloads.GetPayload("exfil/output")
		if err != nil {
			t.Errorf("Expected no error getting exfil/output payload, got: %v", err)
		}
		if payload == nil {
			t.Error("Expected payload to be non-nil")
		}
		if payload.GetName() != "exfil/output" {
			t.Errorf("Expected payload name 'exfil/output', got: %s", payload.GetName())
		}
	})

	t.Run("GetPayload_NotFound", func(t *testing.T) {
		// Test retrieving a non-existent payload
		_, err := payloads.GetPayload("nonexistent/payload")
		if err == nil {
			t.Error("Expected error for non-existent payload, got nil")
		}
	})

	t.Run("GetPayloadsByTags_Lambda", func(t *testing.T) {
		// Test filtering by Lambda tag
		lambdaPayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceLambda})
		if len(lambdaPayloads) == 0 {
			t.Error("Expected at least one Lambda payload")
		}

		// Verify all returned payloads have the Lambda tag
		for _, payload := range lambdaPayloads {
			if !hasTag(payload.GetTags(), payloads.TagServiceLambda) {
				t.Errorf("Payload %s missing Lambda tag", payload.GetName())
			}
		}
	})

	t.Run("GetPayloadsByTags_Multiple", func(t *testing.T) {
		// Test filtering by multiple tags (Lambda AND Python)
		filteredPayloads := payloads.GetPayloadsByTags([]string{
			payloads.TagServiceLambda,
			payloads.TagLanguagePython,
		})

		if len(filteredPayloads) == 0 {
			t.Error("Expected at least one Lambda Python payload")
		}

		// Verify all returned payloads have both tags
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
		// Test filtering by technique tag
		exfilPayloads := payloads.GetPayloadsByTags([]string{payloads.TagTechniqueExfil})
		if len(exfilPayloads) < 2 {
			t.Errorf("Expected at least 2 exfil payloads, got: %d", len(exfilPayloads))
		}
	})

	t.Run("GetPayloadsByTags_Backdoor", func(t *testing.T) {
		// Test filtering by backdoor technique
		backdoorPayloads := payloads.GetPayloadsByTags([]string{payloads.TagTechniqueBackdoor})
		if len(backdoorPayloads) < 2 {
			t.Errorf("Expected at least 2 backdoor payloads, got: %d", len(backdoorPayloads))
		}
	})

	t.Run("ListAllPayloads", func(t *testing.T) {
		// Test getting all registered payloads
		allPayloads := payloads.ListAllPayloads()
		if len(allPayloads) < 4 {
			t.Errorf("Expected at least 4 payloads, got: %d", len(allPayloads))
		}

		// Verify names are unique
		nameMap := make(map[string]bool)
		for _, payload := range allPayloads {
			name := payload.GetName()
			if nameMap[name] {
				t.Errorf("Duplicate payload name: %s", name)
			}
			nameMap[name] = true
		}
	})

	t.Run("PayloadInterface", func(t *testing.T) {
		// Test that all payloads implement the interface correctly
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

		// Verify none of the returned payloads have the backdoor tag
		for _, payload := range filteredPayloads {
			if hasTag(payload.GetTags(), payloads.TagTechniqueBackdoor) {
				t.Errorf("Payload %s should have been excluded", payload.GetName())
			}
		}
	})

	t.Run("GetPayloadInfo", func(t *testing.T) {
		info, err := payloads.GetPayloadInfo("exfil/output")
		if err != nil {
			t.Errorf("Expected no error getting payload info, got: %v", err)
		}
		if info.Name != "exfil/output" {
			t.Errorf("Expected name 'exfil/output', got: %s", info.Name)
		}
		if info.Description == "" {
			t.Error("Expected non-empty description")
		}
		if len(info.Tags) == 0 {
			t.Error("Expected non-empty tags")
		}
	})
}

func TestPayloadValidation(t *testing.T) {
	t.Run("ExfilHTTPS_RequiresURL", func(t *testing.T) {
		payload, err := payloads.GetPayload("exfil/https")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		// Should fail without HTTPS_URL
		err = payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing HTTPS_URL")
		}

		// Should pass with HTTPS_URL
		err = payload.Validate(map[string]string{"HTTPS_URL": "https://example.com"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("BackdoorRole_RequiresTrustedPrincipal", func(t *testing.T) {
		payload, err := payloads.GetPayload("backdoor/role")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		// Should fail without TRUSTED_PRINCIPAL
		err = payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing TRUSTED_PRINCIPAL")
		}

		// Should pass with TRUSTED_PRINCIPAL
		err = payload.Validate(map[string]string{"TRUSTED_PRINCIPAL": "arn:aws:iam::123456789012:user/attacker"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})
}

func TestSideEffectReporter(t *testing.T) {
	t.Run("BackdoorAttachPolicy_ImplementsSideEffectReporter", func(t *testing.T) {
		payload, err := payloads.GetPayload("backdoor/attach-policy")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("backdoor/attach-policy should implement SideEffectReporter")
		}

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "test-user",
			"POLICY_ARN":  "arn:aws:iam::aws:policy/AdministratorAccess",
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
		payload, err := payloads.GetPayload("backdoor/attach-policy")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "my-user",
		})

		if len(effects) != 1 {
			t.Fatalf("Expected 1 side effect, got %d", len(effects))
		}

		if effects[0].Metadata["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" {
			t.Errorf("Expected default AdministratorAccess policy, got '%s'", effects[0].Metadata["policy_arn"])
		}
	})

	t.Run("ElevationDirect_ImplementsSideEffectReporter", func(t *testing.T) {
		payload, err := payloads.GetPayload("elevation/direct")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter, ok := payload.(payloads.SideEffectReporter)
		if !ok {
			t.Fatal("elevation/direct should implement SideEffectReporter")
		}

		// Test user principal
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_PRINCIPAL_TYPE": "user",
			"TARGET_PRINCIPAL_NAME": "test-user",
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

	t.Run("ElevationDirect_RolePrincipal", func(t *testing.T) {
		payload, err := payloads.GetPayload("elevation/direct")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_PRINCIPAL_TYPE": "role",
			"TARGET_PRINCIPAL_NAME": "test-role",
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
		for _, name := range []string{"exfil/output", "exfil/https"} {
			payload, err := payloads.GetPayload(name)
			if err != nil {
				t.Fatalf("Failed to get payload %s: %v", name, err)
			}

			_, ok := payload.(payloads.SideEffectReporter)
			if ok {
				t.Errorf("Payload %s should NOT implement SideEffectReporter (read-only)", name)
			}
		}
	})

	t.Run("SideEffectResources_CompatibleWithCleanupHandler", func(t *testing.T) {
		// Verify that reported side effects match the metadata schema
		// expected by the iam:attached-policy cleanup handler
		payload, _ := payloads.GetPayload("backdoor/attach-policy")
		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "cleanup-test-user",
		})

		effect := effects[0]

		// The cleanup handler reads these three fields
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
		// ModuleID should be empty — the module sets it after calling ReportSideEffects
		payload, _ := payloads.GetPayload("backdoor/attach-policy")
		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "test",
		})

		if effects[0].ModuleID != "" {
			t.Errorf("Payload should not set ModuleID (module does that), got '%s'", effects[0].ModuleID)
		}
	})

	t.Run("SideEffect_NameIsReadable", func(t *testing.T) {
		payload, _ := payloads.GetPayload("backdoor/attach-policy")
		reporter := payload.(payloads.SideEffectReporter)
		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "alice",
		})

		// Name should contain the target user for display in workspace cleanup
		if !strings.Contains(effects[0].Name, "alice") {
			t.Errorf("Side effect Name should contain target user for readability, got '%s'", effects[0].Name)
		}
	})
}

func TestVerifiableInterface(t *testing.T) {
	t.Run("BackdoorAttachPolicy_ImplementsVerifiable", func(t *testing.T) {
		payload, err := payloads.GetPayload("backdoor/attach-policy")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		_, ok := payload.(payloads.Verifiable)
		if !ok {
			t.Fatal("backdoor/attach-policy should implement Verifiable")
		}
	})

	t.Run("ExfilPayloads_DoNotImplementVerifiable", func(t *testing.T) {
		for _, name := range []string{"exfil/output", "exfil/https"} {
			payload, err := payloads.GetPayload(name)
			if err != nil {
				t.Fatalf("Failed to get payload %s: %v", name, err)
			}

			_, ok := payload.(payloads.Verifiable)
			if ok {
				t.Errorf("Payload %s should NOT implement Verifiable", name)
			}
		}
	})
}

func TestSideEffectReporter_ResourceTracking(t *testing.T) {
	// Simulate what a module does: get side effects, set ModuleID, and verify
	// the resource is properly formed for the resource tracker
	t.Run("ModuleIntegration_SetModuleID", func(t *testing.T) {
		payload, _ := payloads.GetPayload("backdoor/attach-policy")
		reporter := payload.(payloads.SideEffectReporter)

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "starting-user",
			"POLICY_ARN":  "arn:aws:iam::aws:policy/AdministratorAccess",
		})

		// Simulate what the module does
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
		// Verify the resource can be represented as a CreatedResource
		payload, _ := payloads.GetPayload("backdoor/attach-policy")
		reporter := payload.(payloads.SideEffectReporter)

		effects := reporter.ReportSideEffects(map[string]string{
			"TARGET_USER": "my-user",
		})

		var _ modules.CreatedResource = effects[0] // compile-time check
	})
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
