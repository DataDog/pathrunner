// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/core/repl"
	"github.com/DataDog/pathrunner/pkg/modules"
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

func TestAttackerIdentityShowNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity show")
	if err != nil {
		t.Errorf("Expected attacker identity show to succeed, got: %v", err)
	}
}

func TestAttackerIdentityShowDefault(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Running 'attacker' with no subcommand defaults to identity show
	err := r.ExecuteCommand("attacker")
	if err != nil {
		t.Errorf("Expected attacker (default identity show) to succeed, got: %v", err)
	}
}

func TestAttackerIdentityDefaultShow(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Running 'attacker identity' with no subcommand defaults to show
	err := r.ExecuteCommand("attacker identity")
	if err != nil {
		t.Errorf("Expected attacker identity (default show) to succeed, got: %v", err)
	}
}

func TestAttackerIdentityRemoveNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity remove")
	if err != nil {
		t.Errorf("Expected attacker identity remove to succeed when no identity configured, got: %v", err)
	}
}

func TestAttackerIdentityAddMissingArgs(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity add")
	if err == nil {
		t.Error("Expected error for attacker identity add with no args")
	}
}

func TestAttackerIdentityAddProfileMissingName(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity add profile")
	if err == nil {
		t.Error("Expected error for attacker identity add profile with no profile name")
	}
}

func TestAttackerIdentityAddKeysMissingFlags(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity add keys")
	if err == nil {
		t.Error("Expected error for attacker identity add keys with no flags")
	}
}

func TestAttackerIdentityAddUnknownSource(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity add banana")
	if err == nil {
		t.Error("Expected error for unknown attacker identity add source")
	}
}

func TestAttackerIdentityUnknownSubcommand(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity banana")
	if err == nil {
		t.Error("Expected error for unknown attacker identity subcommand")
	}
}

func TestAttackerIdentityHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity help")
	if err != nil {
		t.Errorf("Expected attacker identity help to succeed, got: %v", err)
	}
}

func TestAttackerIdentityAddHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity add help")
	if err != nil {
		t.Errorf("Expected attacker identity add help to succeed, got: %v", err)
	}
}

func TestAttackerIdentityValidateNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker identity validate")
	if err == nil {
		t.Error("Expected error when validating with no attacker identity")
	}
}

// Legacy alias tests — ensure old commands still work

func TestAttackerLegacyShowAlias(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker show")
	if err != nil {
		t.Errorf("Expected attacker show (legacy) to succeed, got: %v", err)
	}
}

func TestAttackerLegacyClearAlias(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker clear")
	if err != nil {
		t.Errorf("Expected attacker clear (legacy) to succeed, got: %v", err)
	}
}

func TestAttackerLegacySetMissingArgs(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set")
	if err == nil {
		t.Error("Expected error for attacker set with no args")
	}
}

func TestAttackerLegacySetProfileMissingName(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set profile")
	if err == nil {
		t.Error("Expected error for attacker set profile with no profile name")
	}
}

func TestAttackerLegacySetKeysMissingFlags(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set keys")
	if err == nil {
		t.Error("Expected error for attacker set keys with no flags")
	}
}

func TestAttackerLegacySetHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker set help")
	if err != nil {
		t.Errorf("Expected attacker set help to succeed, got: %v", err)
	}
}

func TestAttackerLegacyValidateNoIdentity(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker validate")
	if err == nil {
		t.Error("Expected error when validating with no attacker identity")
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
	ctx := modules.ExecutionContext{
		Identity: &modules.Identity{Name: "victim", Type: "keys"},
		Options:  map[string]string{},
	}

	if ctx.AttackerIdentity != nil {
		t.Error("Expected attacker identity to be nil when not set")
	}
}

func TestCreatedResourceAccountContext(t *testing.T) {
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

	victimResource := modules.CreatedResource{
		Type:   "lambda_function",
		Name:   "test-func",
		Region: "us-east-1",
	}

	if victimResource.AccountContext != "" {
		t.Errorf("Expected empty AccountContext for victim resources, got '%s'", victimResource.AccountContext)
	}
}
