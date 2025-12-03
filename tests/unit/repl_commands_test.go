package unit

import (
	"pathrunner/pkg/core/repl"
	"regexp"
	"strings"
	"testing"
)

// Helper function to strip ANSI color codes from strings for testing
func stripAnsiCodes(s string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

// Test identity command routing
func TestIdentityCommandRouting(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	identityCmd, exists := commands["identity"]

	if !exists {
		t.Fatal("Expected identity command to exist")
	}

	// Test that handler can be called without panic
	err := identityCmd.Handler(r, []string{})
	if err != nil {
		t.Errorf("Expected no error calling identity with no args (should list), got: %v", err)
	}
}

// Test workspace command routing
func TestWorkspaceCommandRouting(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	workspaceCmd, exists := commands["workspace"]

	if !exists {
		t.Fatal("Expected workspace command to exist")
	}

	// Test that handler can be called without panic
	err := workspaceCmd.Handler(r, []string{})
	if err != nil {
		t.Errorf("Expected no error calling workspace with no args (should list), got: %v", err)
	}
}

// Test use command
func TestUseCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	useCmd, exists := commands["use"]

	if !exists {
		t.Fatal("Expected use command to exist")
	}

	// Test use with no arguments (should error)
	err := useCmd.Handler(r, []string{})
	if err == nil {
		t.Error("Expected error when calling 'use' with no arguments")
	}

	// Test use with invalid module (should error)
	err = useCmd.Handler(r, []string{"nonexistent/module"})
	if err == nil {
		t.Error("Expected error when using non-existent module")
	}
}

// Test show command
func TestShowCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	showCmd, exists := commands["show"]

	if !exists {
		t.Fatal("Expected show command to exist")
	}

	// Test show with no arguments (should error)
	err := showCmd.Handler(r, []string{})
	if err == nil {
		t.Error("Expected error when calling 'show' with no arguments")
	}
}

// Test show modules
func TestShowModules(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	showCmd := commands["show"]

	// This should not error
	err := showCmd.Handler(r, []string{"modules"})
	if err != nil {
		t.Errorf("Expected no error showing modules, got: %v", err)
	}
}

// Test set command
func TestSetCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	setCmd, exists := commands["set"]

	if !exists {
		t.Fatal("Expected set command to exist")
	}

	// Test set with no arguments (should error)
	err := setCmd.Handler(r, []string{})
	if err == nil {
		t.Error("Expected error when calling 'set' with no arguments")
	}

	// Test set with one argument (should error)
	err = setCmd.Handler(r, []string{"OPTION"})
	if err == nil {
		t.Error("Expected error when calling 'set' with only one argument")
	}

	// Test set with two arguments (should work even without module)
	err = setCmd.Handler(r, []string{"OPTION", "value"})
	if err != nil {
		t.Errorf("Expected no error when setting option, got: %v", err)
	}

	// Verify option was set
	if r.GetOptions()["OPTION"] != "value" {
		t.Error("Expected OPTION to be set to 'value'")
	}
}

// Test unset command
func TestUnsetCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	unsetCmd, exists := commands["unset"]

	if !exists {
		t.Fatal("Expected unset command to exist")
	}

	// Test unset with no arguments (should error)
	err := unsetCmd.Handler(r, []string{})
	if err == nil {
		t.Error("Expected error when calling 'unset' with no arguments")
	}
}

// Test help command
func TestHelpCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	helpCmd, exists := commands["help"]

	if !exists {
		t.Fatal("Expected help command to exist")
	}

	// Help with no args should show general help
	err := helpCmd.Handler(r, []string{})
	if err != nil {
		t.Errorf("Expected no error showing general help, got: %v", err)
	}

	// Help with specific command
	err = helpCmd.Handler(r, []string{"identity"})
	if err != nil {
		t.Errorf("Expected no error showing identity help, got: %v", err)
	}
}

// Test whoami command
func TestWhoamiCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	whoamiCmd, exists := commands["whoami"]

	if !exists {
		t.Fatal("Expected whoami command to exist")
	}

	// Should not error when identity exists (mock returns one)
	err := whoamiCmd.Handler(r, []string{})
	if err != nil {
		t.Errorf("Expected no error with whoami, got: %v", err)
	}
}

// Test exploit command
func TestExploitCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	commands := r.GetCommands()
	exploitCmd, exists := commands["exploit"]

	if !exists {
		t.Fatal("Expected exploit command to exist")
	}

	// Should error when no module selected
	err := exploitCmd.Handler(r, []string{})
	if err == nil {
		t.Error("Expected error when running exploit without module selected")
	}
}

// Test command aliases
func TestCommandAliases(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	testCases := []struct {
		alias    string
		expected string
	}{
		{"identities", "identity"},
		{"workspaces", "workspace"},
		{"quit", "exit"},
	}

	for _, tc := range testCases {
		// Try to execute the alias - it should resolve to the actual command
		err := r.ExecuteCommand(tc.alias)
		// We expect no "command not found" error
		if err != nil && strings.Contains(err.Error(), "not found") {
			t.Errorf("Alias '%s' not properly resolved", tc.alias)
		}
	}
}

// Test module state management
func TestModuleStateManagement(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	// Initially no module should be selected
	if r.GetCurrentModule() != nil {
		t.Error("Expected no module selected initially")
	}

	// Set a module
	mockModule := &MockModule{
		name:        "test/module",
		description: "Test module",
	}
	r.SetCurrentModule(mockModule)

	// Verify module is set
	if r.GetCurrentModule() == nil {
		t.Error("Expected module to be set")
	}

	if r.GetCurrentModule().Name() != "test/module" {
		t.Errorf("Expected module name 'test/module', got '%s'", r.GetCurrentModule().Name())
	}
}

// Test option management with module context
func TestOptionManagementWithModule(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	// Set a module
	mockModule := &MockModule{
		name:        "test/module",
		description: "Test module",
	}
	r.SetCurrentModule(mockModule)

	// Set an option
	r.SetOption("TEST_OPTION", "test_value")

	options := r.GetOptions()
	if options["TEST_OPTION"] != "test_value" {
		t.Errorf("Expected option value 'test_value', got '%s'", options["TEST_OPTION"])
	}

	// Unset the option
	r.UnsetOption("TEST_OPTION")

	options = r.GetOptions()
	if _, exists := options["TEST_OPTION"]; exists {
		t.Error("Expected option to be unset")
	}
}

// Test error types
func TestREPLErrorTypes(t *testing.T) {
	// Test CommandNotFoundError
	err := repl.NewCommandNotFoundError("badcommand")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "badcommand") {
		t.Error("Expected error message to contain command name")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Error("Expected error message to indicate command not found")
	}

	// Test InvalidArgumentsError
	err = repl.NewInvalidArgumentsError("missing required argument")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "missing required argument") {
		t.Error("Expected error message to contain the provided message")
	}

	// Test IdentityRequiredError
	err = repl.NewIdentityRequiredError()
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "identity") {
		t.Error("Expected error message to mention identity requirement")
	}

	// Test ExecutionError
	innerErr := repl.NewCommandNotFoundError("test")
	err = repl.NewExecutionError("operation failed", innerErr)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "operation failed") {
		t.Error("Expected error message to contain context")
	}
}

// Test prompt building
func TestPromptBuilding(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	// Basic prompt - single-line format with spaced brackets (strip ANSI codes for testing)
	prompt := stripAnsiCodes(r.BuildContextualPrompt())
	if !strings.HasPrefix(prompt, "[") {
		t.Errorf("Expected prompt to start with '[', got: %s", prompt)
	}

	if !strings.HasSuffix(prompt, "] > ") {
		t.Errorf("Expected prompt to end with '] > ', got: %s", prompt)
	}

	if !strings.Contains(prompt, "] [") {
		t.Errorf("Expected prompt to contain '] [' separator, got: %s", prompt)
	}

	if strings.Contains(prompt, "\n") {
		t.Errorf("Expected single-line prompt, got multi-line: %s", prompt)
	}

	// With module
	mockModule := &MockModule{
		name:        "exploit/test_module",
		description: "Test",
	}
	r.SetCurrentModule(mockModule)

	prompt = stripAnsiCodes(r.BuildContextualPrompt())
	if !strings.Contains(prompt, "test_module") {
		t.Errorf("Expected prompt to contain module name, got: %s", prompt)
	}

	// With payload - payload is no longer shown in prompt
	r.SetOption("PAYLOAD", "test/payload")
	prompt = stripAnsiCodes(r.BuildContextualPrompt())
	// Should still show module but not payload
	if !strings.Contains(prompt, "test_module") {
		t.Errorf("Expected prompt to still contain module, got: %s", prompt)
	}
	if strings.Contains(prompt, "payload") {
		t.Errorf("Expected prompt to not contain payload (removed from prompt), got: %s", prompt)
	}
}

// Test command execution through ExecuteCommand
func TestExecuteCommand(t *testing.T) {
	im := &MockIdentityManager{}
	sm := &MockSessionManager{}
	r := repl.NewREPL(im, sm)

	// Valid command
	err := r.ExecuteCommand("help")
	if err != nil {
		t.Errorf("Expected no error executing 'help', got: %v", err)
	}

	// Invalid command
	err = r.ExecuteCommand("nonexistent")
	if err == nil {
		t.Error("Expected error executing non-existent command")
	}

	// Empty command
	err = r.ExecuteCommand("")
	if err != nil {
		t.Errorf("Expected no error for empty command, got: %v", err)
	}

	// Whitespace only
	err = r.ExecuteCommand("   ")
	if err != nil {
		t.Errorf("Expected no error for whitespace command, got: %v", err)
	}
}
