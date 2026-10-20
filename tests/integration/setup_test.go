// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/DataDog/pathrunner/pkg/core"
	"github.com/DataDog/pathrunner/pkg/core/repl"
	"github.com/DataDog/pathrunner/pkg/status"
)

// setupTest creates a test environment with REPL
func setupTest(t *testing.T) (*repl.REPL, *core.SessionManager, *core.IdentityManager, func()) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)

	// Isolate the module status manifest: commands like `modules mark-tested`
	// write it back, and without this they would mutate the repo's checked-in
	// testdata/module-status.json. Point the status package at a temp copy of
	// the real fixture so reads still work and writes stay contained.
	originalManifest := os.Getenv(status.ManifestPathEnv)
	tempManifest := filepath.Join(tempDir, "module-status.json")
	if err := copyFile(realManifestPath(t), tempManifest); err != nil {
		t.Fatalf("Failed to seed temp status manifest: %v", err)
	}
	_ = os.Setenv(status.ManifestPathEnv, tempManifest)

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
		if originalManifest == "" {
			_ = os.Unsetenv(status.ManifestPathEnv)
		} else {
			_ = os.Setenv(status.ManifestPathEnv, originalManifest)
		}
	}

	return r, sessionManager, identityManager, cleanup
}

// realManifestPath returns the repo's checked-in module status manifest,
// located relative to this source file so it resolves from any test cwd.
func realManifestPath(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve caller for manifest path")
	}
	// tests/integration/ -> up two to the project root.
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
	return filepath.Join(projectRoot, "testdata", "module-status.json")
}

// copyFile copies src to dst, creating or truncating dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
