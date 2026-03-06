package unit

import (
	"fmt"
	"pathrunner/pkg/discovery"
	"pathrunner/pkg/modules"
	"strings"
	"testing"

	// Import modules to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole_esm"
	_ "pathrunner/pkg/exploits/sts_assume_role"
)

func TestDiscoveryChoiceStruct(t *testing.T) {
	t.Run("BasicFields", func(t *testing.T) {
		choice := modules.DiscoveryChoice{
			Value: "arn:aws:iam::123456789012:role/MyRole",
			Label: "MyRole [ADMIN] (AdministratorAccess)",
			Metadata: map[string]string{
				"role_name":    "MyRole",
				"admin_access": "true",
			},
		}

		if choice.Value != "arn:aws:iam::123456789012:role/MyRole" {
			t.Errorf("Expected Value to be set, got %q", choice.Value)
		}

		if choice.Label != "MyRole [ADMIN] (AdministratorAccess)" {
			t.Errorf("Expected Label to be set, got %q", choice.Label)
		}

		if choice.Metadata["role_name"] != "MyRole" {
			t.Errorf("Expected Metadata role_name = MyRole, got %q", choice.Metadata["role_name"])
		}
	})

	t.Run("EmptyMetadata", func(t *testing.T) {
		choice := modules.DiscoveryChoice{
			Value: "some-value",
			Label: "some-label",
		}

		if choice.Metadata != nil {
			t.Error("Expected nil Metadata for empty DiscoveryChoice")
		}
	})
}

func TestDiscoverableInterfaceCompliance(t *testing.T) {
	testCases := []struct {
		name               string
		moduleID           string
		expectDiscoverable bool
		expectedOptions    []string
	}{
		{
			name:               "lambda-001 implements Discoverable",
			moduleID:           "lambda-001",
			expectDiscoverable: true,
			expectedOptions:    []string{"ROLE_ARN"},
		},
		{
			name:               "lambda-002 implements Discoverable",
			moduleID:           "lambda-002",
			expectDiscoverable: true,
			expectedOptions:    []string{"ROLE_ARN", "EVENT_SOURCE_ARN", "TABLE_NAME"},
		},
		{
			name:               "ec2-001 implements Discoverable",
			moduleID:           "ec2-001",
			expectDiscoverable: true,
			expectedOptions:    []string{"INSTANCE_PROFILE", "SUBNET_ID", "SECURITY_GROUP_ID"},
		},
		{
			name:               "sts-001 implements Discoverable",
			moduleID:           "sts-001",
			expectDiscoverable: true,
			expectedOptions:    []string{"ROLE_ARN"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			module, err := modules.LoadModule(tc.moduleID)
			if err != nil {
				t.Fatalf("Failed to load module %s: %v", tc.moduleID, err)
			}

			discoverable, ok := module.(modules.Discoverable)
			if ok != tc.expectDiscoverable {
				t.Errorf("Expected Discoverable=%v for %s, got %v", tc.expectDiscoverable, tc.moduleID, ok)
				return
			}

			if !tc.expectDiscoverable {
				return
			}

			opts := discoverable.DiscoverableOptions()
			if len(opts) != len(tc.expectedOptions) {
				t.Errorf("Expected %d discoverable options, got %d: %v", len(tc.expectedOptions), len(opts), opts)
				return
			}

			for i, expected := range tc.expectedOptions {
				if opts[i] != expected {
					t.Errorf("Expected option[%d] = %q, got %q", i, expected, opts[i])
				}
			}
		})
	}
}

func TestDiscoverUnsupportedOption(t *testing.T) {
	module, err := modules.LoadModule("lambda-001")
	if err != nil {
		t.Fatalf("Failed to load module: %v", err)
	}

	discoverable, ok := module.(modules.Discoverable)
	if !ok {
		t.Fatal("lambda-001 should implement Discoverable")
	}

	// Try to discover a non-discoverable option
	_, err = discoverable.Discover("FUNCTION_NAME", nil, nil)
	if err == nil {
		t.Error("Expected error for non-discoverable option FUNCTION_NAME")
	}
	if !strings.Contains(err.Error(), "does not support auto-discovery") {
		t.Errorf("Expected 'does not support auto-discovery' error, got: %v", err)
	}
}

func TestDiscoverUnsupportedOptionSTS(t *testing.T) {
	module, err := modules.LoadModule("sts-001")
	if err != nil {
		t.Fatalf("Failed to load module: %v", err)
	}

	discoverable, ok := module.(modules.Discoverable)
	if !ok {
		t.Fatal("sts-001 should implement Discoverable")
	}

	// Try to discover a non-discoverable option
	_, err = discoverable.Discover("SESSION_NAME", nil, nil)
	if err == nil {
		t.Error("Expected error for non-discoverable option SESSION_NAME")
	}
	if !strings.Contains(err.Error(), "does not support auto-discovery") {
		t.Errorf("Expected 'does not support auto-discovery' error, got: %v", err)
	}
}

func TestDiscoverUnsupportedOptionEC2Extended(t *testing.T) {
	module, err := modules.LoadModule("ec2-001")
	if err != nil {
		t.Fatalf("Failed to load module: %v", err)
	}

	discoverable, ok := module.(modules.Discoverable)
	if !ok {
		t.Fatal("ec2-001 should implement Discoverable")
	}

	// AMI_ID is not discoverable
	_, err = discoverable.Discover("AMI_ID", nil, nil)
	if err == nil {
		t.Error("Expected error for non-discoverable option AMI_ID")
	}
	if !strings.Contains(err.Error(), "does not support auto-discovery") {
		t.Errorf("Expected 'does not support auto-discovery' error, got: %v", err)
	}
}

func TestIsAccessDenied(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "AccessDenied",
			err:      fmt.Errorf("AccessDenied: User is not authorized"),
			expected: true,
		},
		{
			name:     "AccessDeniedException",
			err:      fmt.Errorf("AccessDeniedException: operation error"),
			expected: true,
		},
		{
			name:     "UnauthorizedAccess",
			err:      fmt.Errorf("UnauthorizedAccess: forbidden"),
			expected: true,
		},
		{
			name:     "is not authorized to perform",
			err:      fmt.Errorf("User: arn:aws:iam::123:user/test is not authorized to perform: iam:ListRoles"),
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      fmt.Errorf("connection timeout"),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := discovery.IsAccessDenied(tc.err)
			if result != tc.expected {
				t.Errorf("IsAccessDenied(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestFormatPermissionError(t *testing.T) {
	err := fmt.Errorf("AccessDeniedException: not authorized")
	result := discovery.FormatPermissionError("ROLE_ARN", "iam:ListRoles", err)

	if !strings.Contains(result, "ROLE_ARN") {
		t.Error("Expected output to contain option name ROLE_ARN")
	}
	if !strings.Contains(result, "iam:ListRoles") {
		t.Error("Expected output to contain permission iam:ListRoles")
	}
	if !strings.Contains(result, "set ROLE_ARN") {
		t.Error("Expected output to contain manual set instructions")
	}
	if !strings.Contains(result, "AccessDeniedException") {
		t.Error("Expected output to contain original error")
	}
}

func TestLambda002DeriveTableName(t *testing.T) {
	// Test that lambda-002 can derive TABLE_NAME from EVENT_SOURCE_ARN
	module, err := modules.LoadModule("lambda-002")
	if err != nil {
		t.Fatalf("Failed to load module: %v", err)
	}

	discoverable, ok := module.(modules.Discoverable)
	if !ok {
		t.Fatal("lambda-002 should implement Discoverable")
	}

	// When EVENT_SOURCE_ARN is set, TABLE_NAME should be derived from it
	options := map[string]string{
		"EVENT_SOURCE_ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable/stream/2024-01-01T00:00:00.000",
	}

	choices, err := discoverable.Discover("TABLE_NAME", &modules.Identity{
		Type:   "keys",
		Region: "us-east-1",
	}, options)
	if err != nil {
		t.Fatalf("Expected no error for TABLE_NAME derivation, got: %v", err)
	}

	if len(choices) != 1 {
		t.Fatalf("Expected 1 choice for derived TABLE_NAME, got %d", len(choices))
	}

	if choices[0].Value != "MyTable" {
		t.Errorf("Expected derived table name 'MyTable', got %q", choices[0].Value)
	}
}
