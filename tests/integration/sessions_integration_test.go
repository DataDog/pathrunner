// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"
)

func TestSessionsCommandNoListener(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// sessions with no listener should not error but should print message
	err := r.ExecuteCommand("sessions")
	if err != nil {
		t.Errorf("expected no error from sessions with no listener, got: %v", err)
	}
}

func TestSessionsListNoListener(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions list")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestSessionsInteractNoListener(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions interact 1")
	if err == nil {
		t.Error("expected error when interacting with no listener running")
	}
}

func TestSessionsKillNoListener(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions kill 1")
	if err == nil {
		t.Error("expected error when killing with no listener running")
	}
}

func TestSessionsInteractMissingID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions interact")
	if err == nil {
		t.Error("expected error for missing session ID")
	}
}

func TestSessionsKillMissingID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions kill")
	if err == nil {
		t.Error("expected error for missing session ID")
	}
}

func TestSessionsInteractInvalidID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions interact abc")
	if err == nil {
		t.Error("expected error for non-numeric session ID")
	}
}

func TestSessionsKillInvalidID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions kill abc")
	if err == nil {
		t.Error("expected error for non-numeric session ID")
	}
}

func TestSessionsHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions help")
	if err != nil {
		t.Errorf("expected no error from sessions help, got: %v", err)
	}
}

func TestSessionsUnknownSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("sessions foobar")
	if err == nil {
		t.Error("expected error for unknown subcommand")
	}
}

func TestSessionsShorthandFlags(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// -i without listener should error
	err := r.ExecuteCommand("sessions -i 1")
	if err == nil {
		t.Error("expected error for -i with no listener")
	}

	// -k without listener should error
	err = r.ExecuteCommand("sessions -k 1")
	if err == nil {
		t.Error("expected error for -k with no listener")
	}
}

func TestSessionsCommandRegistered(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	commands := r.GetCommands()
	if _, exists := commands["sessions"]; !exists {
		t.Error("sessions command not registered")
	}
}
