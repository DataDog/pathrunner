// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

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
	_ = os.Setenv("HOME", tempDir)

	sessionManager := core.NewSessionManager()
	identityManager := core.NewIdentityManager(
		func() string { return "" },
		func() {},
	)

	sessionAdapter := core.NewSessionAdapter(sessionManager)
	identityAdapter := core.NewIdentityManagerAdapter(identityManager)

	r := repl.NewREPL(identityAdapter, sessionAdapter)

	cleanup := func() {
		_ = os.Setenv("HOME", originalHome)
	}

	return r, sessionManager, identityManager, cleanup
}
