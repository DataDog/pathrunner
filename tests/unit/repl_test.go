package unit

import (
	"pathrunner/pkg/core/repl"
	"pathrunner/pkg/modules"
	"testing"
)

// Mock implementations for testing
type MockIdentityManager struct{}

func (m *MockIdentityManager) GetCurrent() *modules.Identity {
	return &modules.Identity{
		Name:   "test-identity",
		Type:   "test",
		Region: "us-east-1",
	}
}

func (m *MockIdentityManager) GetIdentities() map[string]*modules.Identity {
	return make(map[string]*modules.Identity)
}

func (m *MockIdentityManager) ListIdentities() error {
	return nil
}

func (m *MockIdentityManager) ShowCurrent() error {
	return nil
}

func (m *MockIdentityManager) AddIdentity(args []string) error {
	return nil
}

func (m *MockIdentityManager) AddIdentityFromCredentials(accessKey, secret, token, region, name string) error {
	return nil
}

func (m *MockIdentityManager) SwitchIdentity(name string) error {
	return nil
}

func (m *MockIdentityManager) RemoveIdentity(args []string) error {
	return nil
}

func (m *MockIdentityManager) RefreshCurrentIdentity() error {
	return nil
}

func (m *MockIdentityManager) CheckAdmin(identityName string) error {
	return nil
}

func (m *MockIdentityManager) SetIdentities(identities map[string]*modules.Identity) {
}

func (m *MockIdentityManager) SetCurrent(identity *modules.Identity) {
}

func (m *MockIdentityManager) GetAttackerIdentity() *modules.Identity {
	return nil
}

func (m *MockIdentityManager) SetAttackerIdentity(identity *modules.Identity) {
}

func (m *MockIdentityManager) ClearAttackerIdentity() {
}

type MockSessionManager struct{}

func (m *MockSessionManager) GetCurrentSession() repl.Session {
	return &MockSession{}
}

func (m *MockSessionManager) CreateSession(name string) error {
	return nil
}

func (m *MockSessionManager) SwitchSession(name string) error {
	return nil
}

func (m *MockSessionManager) ListSessions() ([]repl.Session, error) {
	return []repl.Session{&MockSession{}}, nil
}

func (m *MockSessionManager) DeleteSession(name string) error {
	return nil
}

func (m *MockSessionManager) SaveSession(session repl.Session) error {
	return nil
}

func (m *MockSessionManager) LogCommand(command string, success bool, errorMsg, output string) {
}

func (m *MockSessionManager) AddCreatedResource(resource repl.CreatedResource) {
}

func (m *MockSessionManager) RemoveCreatedResource(resourceName string) {
}

func (m *MockSessionManager) GetCreatedResources() []repl.CreatedResource {
	return []repl.CreatedResource{}
}

func (m *MockSessionManager) TrackResource(resource modules.CreatedResource) {
}

type MockSession struct{}

func (m *MockSession) GetName() string {
	return "test-session"
}

func (m *MockSession) GetCreated() string {
	return "2023-01-01 00:00"
}

func (m *MockSession) GetLastAccessed() string {
	return "2023-01-01 00:00"
}

func (m *MockSession) GetCommandCount() int {
	return 0
}

func (m *MockSession) GetResourceCount() int {
	return 0
}

func (m *MockSession) GetIdentities() map[string]*modules.Identity {
	return make(map[string]*modules.Identity)
}

func (m *MockSession) GetCurrentIdentity() string {
	return "test-identity"
}

func (m *MockSession) GetCurrentModule() string {
	return ""
}

func (m *MockSession) GetOptions() map[string]string {
	return make(map[string]string)
}

func (m *MockSession) SetCurrentModule(module string) {
}

func (m *MockSession) SetOptions(options map[string]string) {
}

func (m *MockSession) SetIdentities(identities map[string]*modules.Identity) {
}

func (m *MockSession) SetCurrentIdentity(name string) {
}

func (m *MockSession) GetAttackerIdentity() *modules.Identity {
	return nil
}

func (m *MockSession) SetAttackerIdentity(identity *modules.Identity) {
}

func (m *MockSession) GetCommandLog() []repl.CommandLogEntry {
	return []repl.CommandLogEntry{}
}

func TestREPLCreation(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	if replInstance == nil {
		t.Fatal("Expected REPL instance, got nil")
	}

	// Test that options are initialized
	options := replInstance.GetOptions()
	if options == nil {
		t.Fatal("Expected options map to be initialized")
	}
}

func TestREPLCommands(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	commands := replInstance.GetCommands()

	expectedCommands := []string{
		"help", "exit", "identity", "use", "show", "set", "unset", "exploit", "whoami", "workspace", "context",
	}

	for _, expectedCmd := range expectedCommands {
		if _, exists := commands[expectedCmd]; !exists {
			t.Errorf("Expected command '%s' not found", expectedCmd)
		}
	}
}

func TestREPLSetOption(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}

	replInstance := repl.NewREPL(identityManager, sessionManager)

	// Test setting an option
	replInstance.SetOption("TEST_OPTION", "test_value")

	options := replInstance.GetOptions()
	if value, exists := options["TEST_OPTION"]; !exists || value != "test_value" {
		t.Errorf("Expected option 'TEST_OPTION' to be 'test_value', got '%s'", value)
	}

	// Test unsetting an option
	replInstance.UnsetOption("TEST_OPTION")

	options = replInstance.GetOptions()
	if _, exists := options["TEST_OPTION"]; exists {
		t.Error("Expected option 'TEST_OPTION' to be removed")
	}
}

func TestErrorTypes(t *testing.T) {
	// Test that our error types work correctly
	err := repl.NewCommandNotFoundError("nonexistent")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Test error message
	expectedMsg := "command 'nonexistent' not found. Type 'help' for available commands"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}

	// Test error context
	if err.Context["command"] != "nonexistent" {
		t.Errorf("Expected error context to contain command 'nonexistent'")
	}
}