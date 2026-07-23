// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/attacker"
	"testing"
)

func TestListenerStateSaveAndLoad(t *testing.T) {
	// Use temp dir as HOME so we don't pollute real config
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	state := &attacker.ListenerState{
		Enabled:   true,
		HTTPSPort: 8443,
		ShellPort: 4444,
		BindAddr:  "0.0.0.0",
		PublicIP:  "203.0.113.5",
	}

	if err := attacker.SaveListenerState(state); err != nil {
		t.Fatalf("SaveListenerState failed: %v", err)
	}

	loaded, err := attacker.LoadListenerState()
	if err != nil {
		t.Fatalf("LoadListenerState failed: %v", err)
	}

	if loaded == nil {
		t.Fatal("expected non-nil state after save")
	}
	if !loaded.Enabled {
		t.Error("expected Enabled to be true")
	}
	if loaded.HTTPSPort != 8443 {
		t.Errorf("expected HTTPSPort 8443, got %d", loaded.HTTPSPort)
	}
	if loaded.ShellPort != 4444 {
		t.Errorf("expected ShellPort 4444, got %d", loaded.ShellPort)
	}
	if loaded.PublicIP != "203.0.113.5" {
		t.Errorf("expected PublicIP 203.0.113.5, got %s", loaded.PublicIP)
	}
}

func TestListenerStateLoadNoFile(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	state, err := attacker.LoadListenerState()
	if err != nil {
		t.Fatalf("LoadListenerState should not error for missing file: %v", err)
	}
	if state != nil {
		t.Error("expected nil state when file doesn't exist")
	}
}

func TestListenerStateRemove(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	state := &attacker.ListenerState{
		Enabled:   true,
		HTTPSPort: 8443,
		ShellPort: 4444,
		BindAddr:  "0.0.0.0",
		PublicIP:  "10.0.0.1",
	}

	_ = attacker.SaveListenerState(state)

	if err := attacker.RemoveListenerState(); err != nil {
		t.Fatalf("RemoveListenerState failed: %v", err)
	}

	loaded, _ := attacker.LoadListenerState()
	if loaded != nil {
		t.Error("expected nil state after remove")
	}
}

func TestListenerStateRemoveNoFile(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Should not error even if file doesn't exist
	if err := attacker.RemoveListenerState(); err != nil {
		t.Errorf("RemoveListenerState should not error for missing file: %v", err)
	}
}

func TestListenerStateToConfig(t *testing.T) {
	state := &attacker.ListenerState{
		Enabled:   true,
		HTTPSPort: 9443,
		ShellPort: 5555,
		BindAddr:  "127.0.0.1",
		PublicIP:  "198.51.100.1",
	}

	config := state.ToConfig()

	if config.HTTPSPort != 9443 {
		t.Errorf("expected HTTPSPort 9443, got %d", config.HTTPSPort)
	}
	if config.ShellPort != 5555 {
		t.Errorf("expected ShellPort 5555, got %d", config.ShellPort)
	}
	if config.BindAddr != "127.0.0.1" {
		t.Errorf("expected BindAddr 127.0.0.1, got %s", config.BindAddr)
	}
	if config.PublicIP != "198.51.100.1" {
		t.Errorf("expected PublicIP 198.51.100.1, got %s", config.PublicIP)
	}
}

func TestNewListenerStateFromConfig(t *testing.T) {
	config := attacker.ListenerConfig{
		HTTPSPort: 8443,
		ShellPort: 4444,
		BindAddr:  "0.0.0.0",
		PublicIP:  "35.92.156.59",
	}

	state := attacker.NewListenerStateFromConfig(config)

	if !state.Enabled {
		t.Error("expected Enabled to be true")
	}
	if state.HTTPSPort != 8443 {
		t.Errorf("expected HTTPSPort 8443, got %d", state.HTTPSPort)
	}
	if state.PublicIP != "35.92.156.59" {
		t.Errorf("expected PublicIP 35.92.156.59, got %s", state.PublicIP)
	}
}

func TestListenerStateRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	// Create from config, save, load, convert back to config
	originalConfig := attacker.ListenerConfig{
		HTTPSPort: 9443,
		ShellPort: 5555,
		BindAddr:  "0.0.0.0",
		PublicIP:  "203.0.113.10",
	}

	state := attacker.NewListenerStateFromConfig(originalConfig)
	_ = attacker.SaveListenerState(state)

	loaded, err := attacker.LoadListenerState()
	if err != nil {
		t.Fatalf("LoadListenerState failed: %v", err)
	}

	restoredConfig := loaded.ToConfig()

	if restoredConfig.HTTPSPort != originalConfig.HTTPSPort {
		t.Errorf("HTTPSPort mismatch: %d vs %d", restoredConfig.HTTPSPort, originalConfig.HTTPSPort)
	}
	if restoredConfig.ShellPort != originalConfig.ShellPort {
		t.Errorf("ShellPort mismatch: %d vs %d", restoredConfig.ShellPort, originalConfig.ShellPort)
	}
	if restoredConfig.BindAddr != originalConfig.BindAddr {
		t.Errorf("BindAddr mismatch: %s vs %s", restoredConfig.BindAddr, originalConfig.BindAddr)
	}
	if restoredConfig.PublicIP != originalConfig.PublicIP {
		t.Errorf("PublicIP mismatch: %s vs %s", restoredConfig.PublicIP, originalConfig.PublicIP)
	}
}
