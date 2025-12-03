package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
	os.MkdirAll(filepath.Dir(configPath), 0700)

	cm := &ConfigManager{
		configPath: configPath,
	}

	// Load existing config or create default
	if err := cm.Load(); err != nil {
		// Create default config
		cm.config = &Config{
			CurrentWorkspace: "default",
		}
		cm.Save()
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

// GetCurrentWorkspace returns the current workspace name
func (cm *ConfigManager) GetCurrentWorkspace() string {
	if cm.config == nil {
		return "default"
	}
	return cm.config.CurrentWorkspace
}

// SetCurrentWorkspace sets the current workspace and saves
func (cm *ConfigManager) SetCurrentWorkspace(name string) error {
	if cm.config == nil {
		cm.config = &Config{}
	}
	cm.config.CurrentWorkspace = name
	return cm.Save()
}
