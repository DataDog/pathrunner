package unit

import (
	"pathrunner/pkg/core/repl"
	"pathrunner/pkg/modules"
	"regexp"
	"strings"
	"testing"
)

// Helper function to strip ANSI color codes from strings for testing
func stripAnsi(s string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

// Mock module for testing
type MockModule struct {
	name        string
	description string
}

func (m *MockModule) PathInfo() modules.PathInfo {
	return modules.PathInfo{
		ID:          m.name,
		Description: m.description,
	}
}

func (m *MockModule) Name() string {
	return m.name
}

func (m *MockModule) Description() string {
	return m.description
}

func (m *MockModule) Options() []modules.Option {
	return []modules.Option{
		{Name: "REQUIRED_OPTION", Required: true, Description: "A required option"},
		{Name: "OPTIONAL_OPTION", Required: false, Description: "An optional option", Default: "default_value"},
	}
}

func (m *MockModule) PayloadOptions(payload string) []modules.Option {
	if payload == "test/payload" {
		return []modules.Option{
			{Name: "PAYLOAD_OPTION", Required: true, Description: "Payload specific option"},
		}
	}
	return []modules.Option{}
}

func (m *MockModule) ListPayloads() []modules.PayloadInfo {
	return []modules.PayloadInfo{
		{Name: "test/payload", Description: "Test payload"},
	}
}

func (m *MockModule) Execute(ctx modules.ExecutionContext) (string, error) {
	return "test result", nil
}

func TestContextualPrompt(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	// Test basic prompt (session and identity) - single-line format with spaced brackets (strip ANSI)
	prompt := stripAnsi(replInstance.BuildContextualPrompt())
	if !strings.Contains(prompt, "test-session") || !strings.Contains(prompt, "test-identity") {
		t.Errorf("Expected prompt to contain session and identity, got '%s'", prompt)
	}
	if !strings.HasPrefix(prompt, "[") {
		t.Errorf("Expected prompt to start with '[', got '%s'", prompt)
	}
	if !strings.Contains(prompt, "] [") {
		t.Errorf("Expected prompt to contain '] [' separators, got '%s'", prompt)
	}
	if strings.Contains(prompt, "\n") {
		t.Errorf("Expected single-line prompt, got multi-line: %s", prompt)
	}

	// Test with module selected
	mockModule := &MockModule{name: "exploit/test_module", description: "Test module"}
	replInstance.SetCurrentModule(mockModule)

	prompt = stripAnsi(replInstance.BuildContextualPrompt())
	if !strings.Contains(prompt, "test_module") {
		t.Errorf("Expected prompt to contain module, got '%s'", prompt)
	}

	// Test with payload selected - payload is no longer shown in prompt
	replInstance.SetOption("PAYLOAD", "test/payload")
	prompt = stripAnsi(replInstance.BuildContextualPrompt())
	if !strings.Contains(prompt, "test_module") {
		t.Errorf("Expected prompt to still contain module, got '%s'", prompt)
	}
	// Payload should NOT be in prompt anymore (removed to keep prompt shorter)
	if strings.Contains(prompt, "💣") {
		t.Errorf("Expected prompt to not contain payload emoji, got '%s'", prompt)
	}

	// Test unset payload
	replInstance.UnsetOption("PAYLOAD")
	prompt = stripAnsi(replInstance.BuildContextualPrompt())
	if !strings.Contains(prompt, "test_module") {
		t.Errorf("Expected prompt to still contain module after unset payload, got '%s'", prompt)
	}
}

func TestContextCommand(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	// Test context command exists
	commands := replInstance.GetCommands()
	contextCmd, exists := commands["context"]
	if !exists {
		t.Fatal("Expected 'context' command to exist")
	}

	if contextCmd.Name != "context" {
		t.Errorf("Expected command name 'context', got '%s'", contextCmd.Name)
	}

	if !strings.Contains(contextCmd.Description, "context") {
		t.Errorf("Expected context command description to mention context, got '%s'", contextCmd.Description)
	}

	// Test that context command can be executed (basic smoke test)
	// This would require capturing output in a real test
	err := contextCmd.Handler(replInstance, []string{})
	if err != nil {
		t.Errorf("Expected context command to execute without error, got: %v", err)
	}
}

func TestPromptUpdatesOnChanges(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	// Test that setting options updates prompt for PAYLOAD
	initialPrompt := replInstance.BuildContextualPrompt()

	// Set a regular option (should not change prompt)
	replInstance.SetOption("REGULAR_OPTION", "value")
	afterRegularOption := replInstance.BuildContextualPrompt()
	if afterRegularOption != initialPrompt {
		t.Errorf("Regular option should not change prompt. Before: '%s', After: '%s'", initialPrompt, afterRegularOption)
	}

	// Set PAYLOAD option (should change prompt if module is selected)
	mockModule := &MockModule{name: "exploit/test_module", description: "Test module"}
	replInstance.SetCurrentModule(mockModule)

	replInstance.SetOption("PAYLOAD", "test/payload")
	afterPayload := stripAnsi(replInstance.BuildContextualPrompt())
	// Payload is no longer shown in prompt
	if strings.Contains(afterPayload, "payload") {
		t.Errorf("Expected prompt to not contain 'payload' (removed from prompt), got '%s'", afterPayload)
	}
	// Should still show module
	if !strings.Contains(afterPayload, "test_module") {
		t.Errorf("Expected prompt to still contain module, got '%s'", afterPayload)
	}
}

func TestIdentityInPrompt(t *testing.T) {
	// Test with expired identity
	expiredIdentityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(expiredIdentityManager, sessionManager)

	// Mock expired identity by modifying the mock (this would need a more sophisticated mock in real implementation)
	prompt := replInstance.BuildContextualPrompt()
	if !strings.Contains(prompt, "test-identity") {
		t.Errorf("Expected identity in prompt, got '%s'", prompt)
	}
}

func TestSessionNamesInPrompt(t *testing.T) {
	identityManager := &MockIdentityManager{}

	// Test with non-default session name
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	// Basic test - this would need more sophisticated session manager mock
	// to test different session names (strip ANSI)
	prompt := stripAnsi(replInstance.BuildContextualPrompt())
	if !strings.HasPrefix(prompt, "[") {
		t.Errorf("Expected prompt to start with '[', got '%s'", prompt)
	}

	if !strings.HasSuffix(prompt, "> ") {
		t.Errorf("Expected prompt to end with '> ', got '%s'", prompt)
	}

	if strings.Contains(prompt, "\n") {
		t.Errorf("Expected single-line prompt, got multi-line: %s", prompt)
	}
}