// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ListenerState persists the listener configuration to disk so it can be
// auto-restarted when pathrunner launches. Stored at ~/.pathrunner/listener.json,
// shared across workspaces (like deploy.json).
type ListenerState struct {
	Enabled   bool   `json:"enabled"`
	HTTPSPort int    `json:"https_port"`
	ShellPort int    `json:"shell_port"`
	BindAddr  string `json:"bind_addr"`
	PublicIP  string `json:"public_ip"`
}

func listenerStatePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	return filepath.Join(homeDir, ".pathrunner", "listener.json"), nil
}

// LoadListenerState reads the listener state from disk. Returns nil if
// the file doesn't exist.
func LoadListenerState() (*ListenerState, error) {
	path, err := listenerStatePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read listener state: %v", err)
	}

	var state ListenerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse listener state: %v", err)
	}

	return &state, nil
}

// SaveListenerState writes the listener state to disk.
func SaveListenerState(state *ListenerState) error {
	path, err := listenerStatePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal listener state: %v", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write listener state: %v", err)
	}

	return nil
}

// RemoveListenerState deletes the listener state file from disk.
func RemoveListenerState() error {
	path, err := listenerStatePath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove listener state: %v", err)
	}
	return nil
}

// ToConfig converts persisted state back to a ListenerConfig for restarting.
func (s *ListenerState) ToConfig() ListenerConfig {
	return ListenerConfig{
		HTTPSPort: s.HTTPSPort,
		ShellPort: s.ShellPort,
		BindAddr:  s.BindAddr,
		PublicIP:  s.PublicIP,
	}
}

// NewListenerStateFromConfig creates a ListenerState from a running config.
func NewListenerStateFromConfig(config ListenerConfig) *ListenerState {
	return &ListenerState{
		Enabled:   true,
		HTTPSPort: config.HTTPSPort,
		ShellPort: config.ShellPort,
		BindAddr:  config.BindAddr,
		PublicIP:  config.PublicIP,
	}
}
