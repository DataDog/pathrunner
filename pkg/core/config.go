// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// workspaceEnvVar is the environment variable that overrides the persisted
// current-workspace pointer. When set, pathrunner uses this workspace for all
// operations without touching config.json. This allows test scripts (e.g.,
// scripts/test-module.sh) to give each concurrent agent its own isolated
// workspace without racing on the shared config file.
const workspaceEnvVar = "PATHRUNNER_WORKSPACE"

// Config stores persistent configuration
type Config struct {
	CurrentWorkspace string `json:"current_workspace"`
}

// ConfigManager manages the persistent config file
type ConfigManager struct {
	configPath string
	config     *Config
}

// NewConfigManager creates a new config manager
func NewConfigManager() *ConfigManager {
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, ".pathrunner", "config.json")

	// Create .pathrunner directory if it doesn't exist
	_ = os.MkdirAll(filepath.Dir(configPath), 0700)

	cm := &ConfigManager{
		configPath: configPath,
	}

	// Load existing config or create default
	if err := cm.Load(); err != nil {
		// Create default config
		cm.config = &Config{
			CurrentWorkspace: "default",
		}
		_ = cm.Save()
	}

	return cm
}

// Load loads the config from disk
func (cm *ConfigManager) Load() error {
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	cm.config = &config
	return nil
}

// Save saves the config to disk
func (cm *ConfigManager) Save() error {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(cm.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// GetCurrentWorkspace returns the current workspace name.
// If the PATHRUNNER_WORKSPACE environment variable is set it takes precedence
// over the persisted value in config.json. This lets test scripts give each
// concurrent agent an isolated workspace without racing on the shared file.
func (cm *ConfigManager) GetCurrentWorkspace() string {
	if envWs := os.Getenv(workspaceEnvVar); envWs != "" {
		return envWs
	}
	if cm.config == nil {
		return "default"
	}
	return cm.config.CurrentWorkspace
}

// SetCurrentWorkspace persists the current workspace to config.json.
// When PATHRUNNER_WORKSPACE is set the write is skipped — the env var is the
// source of truth and concurrent agents must not overwrite each other's config.
func (cm *ConfigManager) SetCurrentWorkspace(name string) error {
	if os.Getenv(workspaceEnvVar) != "" {
		return nil
	}
	if cm.config == nil {
		cm.config = &Config{}
	}
	cm.config.CurrentWorkspace = name
	return cm.Save()
}
