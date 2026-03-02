package unit

import (
	"pathrunner/pkg/payloads"
	_ "pathrunner/pkg/payloads/lambda" // Import to register payloads
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

	t.Run("BackdoorRole_RequiresAccount", func(t *testing.T) {
		payload, err := payloads.GetPayload("backdoor/role")
		if err != nil {
			t.Fatalf("Failed to get payload: %v", err)
		}

		// Should fail without BACKDOOR_ACCOUNT
		err = payload.Validate(map[string]string{})
		if err == nil {
			t.Error("Expected validation error for missing BACKDOOR_ACCOUNT")
		}

		// Should pass with BACKDOOR_ACCOUNT
		err = payload.Validate(map[string]string{"BACKDOOR_ACCOUNT": "123456789012"})
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
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
