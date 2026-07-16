package integration

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/core"
	"github.com/DataDog/pathrunner/pkg/core/repl"
	"testing"
)

// setupTest creates a test environment with REPL
func setupTest(t *testing.T) (*repl.REPL, *core.SessionManager, *core.IdentityManager, func()) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)

	sessionManager := core.NewSessionManager()
	identityManager := core.NewIdentityManager(
		func() string { return "" },
		func() {},
	)

	sessionAdapter := core.NewSessionAdapter(sessionManager)
	identityAdapter := core.NewIdentityManagerAdapter(identityManager)

	r := repl.NewREPL(identityAdapter, sessionAdapter)

	cleanup := func() {
		os.Setenv("HOME", originalHome)
	}

	return r, sessionManager, identityManager, cleanup
}
