package unit

import (
	"pathrunner/pkg/core/repl"
	"pathrunner/pkg/modules"
	"testing"
)

func TestAttackerHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker help")
	if err != nil {
		t.Errorf("Expected attacker help to succeed, got: %v", err)
	}
}

func TestAttackerShowNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Should succeed even with no attacker identity
	err := r.ExecuteCommand("attacker show")
	if err != nil {
		t.Errorf("Expected attacker show to succeed, got: %v", err)
	}
}

func TestAttackerShowDefault(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Running 'attacker' with no subcommand defaults to show
	err := r.ExecuteCommand("attacker")
	if err != nil {
		t.Errorf("Expected attacker (default show) to succeed, got: %v", err)
	}
}

func TestAttackerClearNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker clear")
	if err != nil {
		t.Errorf("Expected attacker clear to succeed when no identity configured, got: %v", err)
	}
}

func TestAttackerSetMissingArgs(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set")
	if err == nil {
		t.Error("Expected error for attacker set with no args")
	}
}

func TestAttackerSetProfileMissingName(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set profile")
	if err == nil {
		t.Error("Expected error for attacker set profile with no profile name")
	}
}

func TestAttackerSetKeysMissingFlags(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set keys")
	if err == nil {
		t.Error("Expected error for attacker set keys with no flags")
	}
}

func TestAttackerSetUnknownSource(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set banana")
	if err == nil {
		t.Error("Expected error for unknown attacker set source")
	}
}

func TestAttackerUnknownSubcommand(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker banana")
	if err == nil {
		t.Error("Expected error for unknown attacker subcommand")
	}
}

func TestAttackerValidateNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker validate")
	if err == nil {
		t.Error("Expected error when validating with no attacker identity")
	}
}

func TestAttackerCommandRegistered(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	commands := r.GetCommands()
	if _, exists := commands["attacker"]; !exists {
		t.Error("Expected 'attacker' command to be registered")
	}
}

func TestExecutionContextAttackerIdentity(t *testing.T) {
	// Verify that ExecutionContext correctly holds attacker identity
	attackerIdentity := &modules.Identity{
		Name:   "attacker-test",
		Type:   "keys",
		Region: "us-west-2",
	}

	ctx := modules.ExecutionContext{
		Identity:         &modules.Identity{Name: "victim", Type: "keys"},
		Options:          map[string]string{"ROLE_ARN": "arn:aws:iam::123:role/test"},
		AttackerIdentity: attackerIdentity,
	}

	if ctx.AttackerIdentity == nil {
		t.Fatal("Expected attacker identity to be set")
	}
	if ctx.AttackerIdentity.Name != "attacker-test" {
		t.Errorf("Expected attacker identity name 'attacker-test', got '%s'", ctx.AttackerIdentity.Name)
	}
	if ctx.AttackerIdentity.Region != "us-west-2" {
		t.Errorf("Expected attacker region 'us-west-2', got '%s'", ctx.AttackerIdentity.Region)
	}
}

func TestExecutionContextNoAttackerIdentity(t *testing.T) {
	// Verify that modules without attacker identity see nil
	ctx := modules.ExecutionContext{
		Identity: &modules.Identity{Name: "victim", Type: "keys"},
		Options:  map[string]string{},
	}

	if ctx.AttackerIdentity != nil {
		t.Error("Expected attacker identity to be nil when not set")
	}
}

func TestCreatedResourceAccountContext(t *testing.T) {
	// Verify AccountContext field on CreatedResource
	resource := modules.CreatedResource{
		Type:           "s3_bucket",
		Name:           "pathrunner-test123",
		Region:         "us-east-1",
		CleanupMethod:  "delete_s3_bucket",
		AccountContext: "attacker",
	}

	if resource.AccountContext != "attacker" {
		t.Errorf("Expected AccountContext 'attacker', got '%s'", resource.AccountContext)
	}

	// Default (empty) should be treated as victim
	victimResource := modules.CreatedResource{
		Type:   "lambda_function",
		Name:   "test-func",
		Region: "us-east-1",
	}

	if victimResource.AccountContext != "" {
		t.Errorf("Expected empty AccountContext for victim resources, got '%s'", victimResource.AccountContext)
	}
}
