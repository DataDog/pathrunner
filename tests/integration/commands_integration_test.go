package integration

import (
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

// TestShowModules tests showing available modules
func TestShowModules(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("show modules")
	if err != nil {
		t.Errorf("Expected no error showing modules, got: %v", err)
	}
}

// TestShowPayloadsWithoutModule tests showing all payloads without module selected
func TestShowPayloadsWithoutModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should now show all payloads from all modules instead of erroring
	err := r.ExecuteCommand("show payloads")
	if err != nil {
		t.Errorf("Expected no error showing all payloads, got: %v", err)
	}
}

// TestSetUnsetOptions tests set and unset commands
func TestSetUnsetOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Set option
	err := r.ExecuteCommand("set TEST_OPTION test_value")
	if err != nil {
		t.Errorf("Expected no error setting option, got: %v", err)
	}

	// Verify option was set
	options := r.GetOptions()
	if options["TEST_OPTION"] != "test_value" {
		t.Errorf("Expected option to be 'test_value', got '%s'", options["TEST_OPTION"])
	}

	// Unset option
	err = r.ExecuteCommand("unset TEST_OPTION")
	if err != nil {
		t.Errorf("Expected no error unsetting option, got: %v", err)
	}

	// Verify option was unset
	options = r.GetOptions()
	if _, exists := options["TEST_OPTION"]; exists {
		t.Error("Expected option to be unset")
	}
}

// TestSetWithoutArguments tests set command validation
func TestSetWithoutArguments(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Set without arguments
	err := r.ExecuteCommand("set")
	if err == nil {
		t.Error("Expected error with 'set' without arguments")
	}

	// Set with only one argument
	err = r.ExecuteCommand("set OPTION")
	if err == nil {
		t.Error("Expected error with 'set' without value")
	}
}

// TestUnsetWithoutArguments tests unset command validation
func TestUnsetWithoutArguments(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("unset")
	if err == nil {
		t.Error("Expected error with 'unset' without arguments")
	}
}

// TestUseModule tests module selection
func TestUseModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Use without module name
	err := r.ExecuteCommand("use")
	if err == nil {
		t.Error("Expected error using 'use' without module name")
	}

	// Use non-existent module
	err = r.ExecuteCommand("use exploit/nonexistent")
	if err == nil {
		t.Error("Expected error using non-existent module")
	}
}

// TestExploit tests exploit command
func TestExploit(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Try to run without module selected
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected error running exploit without module selected")
	}

	if !strings.Contains(err.Error(), "module") {
		t.Errorf("Expected module-related error, got: %v", err)
	}
}

// TestWhoami tests whoami command
func TestWhoami(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Whoami without identity should return an error
	err := r.ExecuteCommand("whoami")
	if err == nil {
		t.Error("Expected error with whoami when no identity configured")
	}

	// Error should mention identity
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("Expected identity-related error, got: %v", err)
	}
}

// TestContext tests context command
func TestContext(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("context")
	if err != nil {
		t.Errorf("Expected no error with context command, got: %v", err)
	}
}

// TestHelp tests help command
func TestHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// General help
	err := r.ExecuteCommand("help")
	if err != nil {
		t.Errorf("Expected no error with help, got: %v", err)
	}

	// Help for specific commands
	commands := []string{"identity", "workspace", "use", "show", "set", "unset", "exploit", "whoami", "context"}

	for _, cmd := range commands {
		err := r.ExecuteCommand("help " + cmd)
		if err != nil {
			t.Errorf("Expected no error with 'help %s', got: %v", cmd, err)
		}
	}
}

// TestExit tests exit command
func TestExit(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("exit")
	// Exit should return io.EOF or handle gracefully
	// We just verify it doesn't panic
	_ = err
}

// TestQuitAlias tests quit alias for exit
func TestQuitAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("quit")
	// Quit should return io.EOF or handle gracefully
	_ = err
}

// TestInvalidCommands tests handling of invalid commands
func TestInvalidCommands(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	invalidCommands := []string{
		"invalid",
		"badcommand",
		"notarealcommand",
	}

	for _, cmd := range invalidCommands {
		err := r.ExecuteCommand(cmd)
		if err == nil {
			t.Errorf("Expected error for invalid command '%s'", cmd)
		}

		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected 'not found' error for '%s', got: %v", cmd, err)
		}
	}
}

// TestEmptyCommands tests handling of empty/whitespace commands
func TestEmptyCommands(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	emptyCommands := []string{
		"",
		" ",
		"  ",
		"\t",
	}

	for _, cmd := range emptyCommands {
		err := r.ExecuteCommand(cmd)
		if err != nil {
			t.Errorf("Expected no error for empty command, got: %v", err)
		}
	}
}

// TestCommandChaining tests executing multiple commands in sequence
func TestCommandChaining(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	commands := []struct {
		cmd         string
		expectError bool
	}{
		{"workspace list", false},
		{"identity list", false},
		{"show modules", false},
		{"help", false},
		{"context", false},
		{"set OPT1 val1", false},
		{"set OPT2 val2", false},
		{"unset OPT1", false},
		{"workspace create chain-test", false},
		{"workspace switch chain-test", false},
		{"workspace switch default", false},
		{"workspace delete chain-test", false},
	}

	for _, tc := range commands {
		err := r.ExecuteCommand(tc.cmd)
		if tc.expectError && err == nil {
			t.Errorf("Expected error for command '%s'", tc.cmd)
		}
		if !tc.expectError && err != nil {
			t.Errorf("Command '%s' failed: %v", tc.cmd, err)
		}
	}
}

// TestPromptBuilding tests prompt updates
func TestPromptBuilding(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Initial prompt - single-line format with spaced brackets (strip ANSI)
	prompt := stripAnsi(r.BuildContextualPrompt())
	if !strings.HasPrefix(prompt, "[") {
		t.Errorf("Expected prompt to start with '[', got: %s", prompt)
	}

	if strings.Contains(prompt, "\n") {
		t.Errorf("Expected single-line prompt, got multi-line: %s", prompt)
	}

	// Create and switch workspace
	r.ExecuteCommand("workspace create prompt-test")
	r.ExecuteCommand("workspace switch prompt-test")

	prompt = stripAnsi(r.BuildContextualPrompt())
	if !strings.Contains(prompt, "prompt-test") {
		t.Errorf("Expected prompt to contain workspace name, got: %s", prompt)
	}
}

// TestInitialPromptShowsWorkspace tests that the initial prompt shows workspace on startup
func TestInitialPromptShowsWorkspace(t *testing.T) {
	r, sm, im, cleanup := setupTest(t)
	defer cleanup()

	// Verify initial prompt includes default workspace (strip ANSI)
	initialPrompt := stripAnsi(r.BuildContextualPrompt())
	if !strings.Contains(initialPrompt, "default") {
		t.Errorf("Expected initial prompt to contain 'default' workspace, got: %s", initialPrompt)
	}

	// Add an identity and verify it appears in the prompt
	identity := &modules.Identity{
		Name:   "test-identity",
		Type:   "profile",
		Region: "us-east-1",
	}
	identities := map[string]*modules.Identity{"test-identity": identity}
	im.SetIdentities(identities)
	im.SetCurrent(identity)

	// Save current state to session
	currentSession := sm.GetCurrentSession()
	currentSession.Identities = identities
	currentSession.CurrentIdentity = "test-identity"
	sm.SaveSession(currentSession)

	// Build prompt and verify it contains both workspace and identity (strip ANSI)
	prompt := stripAnsi(r.BuildContextualPrompt())
	if !strings.Contains(prompt, "default") {
		t.Errorf("Expected prompt to contain workspace 'default', got: %s", prompt)
	}
	if !strings.Contains(prompt, "test-identity") {
		t.Errorf("Expected prompt to contain identity 'test-identity', got: %s", prompt)
	}

	// Check single-line format includes spaced brackets
	if !strings.Contains(prompt, "] [") {
		t.Errorf("Expected prompt to contain '] [' separators, got: %s", prompt)
	}
	if !strings.HasSuffix(prompt, "] > ") {
		t.Errorf("Expected prompt to end with '] > ', got: %s", prompt)
	}
	if strings.Contains(prompt, "\n") {
		t.Errorf("Expected single-line prompt, got multi-line: %s", prompt)
	}
}

// TestSubcommandHelp tests that all subcommands support a trailing "help" argument
func TestSubcommandHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	helpCommands := []struct {
		command     string
		expectInOutput string
	}{
		// Workspace subcommands
		{"workspace create help", "workspace create"},
		{"workspace switch help", "workspace switch"},
		{"workspace delete help", "workspace delete"},
		{"workspace cleanup help", "workspace cleanup"},
		{"workspace history help", "workspace history"},
		{"workspace help", "Workspace Management"},
		// Identity subcommands
		{"identity add help", "identity add"},
		{"identity switch help", "identity switch"},
		{"identity clear help", "identity clear"},
		{"identity help", "Identity Management"},
		// Top-level commands
		{"help identity", "Identity Management"},
		{"help workspace", "Workspace Management"},
		{"help show", "Show Commands"},
		{"help exploit", "Exploit Command"},
		{"help whoami", "Whoami Command"},
		{"help context", "Context Command"},
		{"help search", "Search Command"},
		{"help modules", "Modules Command"},
		{"help payloads", "Payloads Command"},
		{"help set", "Set Command"},
		{"help unset", "Unset Command"},
	}

	for _, tc := range helpCommands {
		t.Run(tc.command, func(t *testing.T) {
			err := r.ExecuteCommand(tc.command)
			if err != nil {
				t.Errorf("'%s' returned error: %v", tc.command, err)
			}
		})
	}
}
