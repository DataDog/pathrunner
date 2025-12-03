package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config represents the application configuration
type Config struct {
	// Paths
	SessionsDir  string `json:"sessions_dir"`
	HistoryFile  string `json:"history_file"`
	ConfigDir    string `json:"config_dir"`

	// AWS Settings
	DefaultRegion  string `json:"default_region"`
	DefaultProfile string `json:"default_profile"`

	// Limits
	MaxSessions    int `json:"max_sessions"`
	MaxHistory     int `json:"max_history"`
	MaxResources   int `json:"max_resources"`

	// Timeouts (in seconds)
	CommandTimeout int `json:"command_timeout"`
	NetworkTimeout int `json:"network_timeout"`

	// UI Settings
	UseColors    bool `json:"use_colors"`
	AutoComplete bool `json:"auto_complete"`
	PromptStyle  string `json:"prompt_style"`

	// Logging
	LogLevel    string `json:"log_level"`
	LogFile     string `json:"log_file"`
	EnableDebug bool   `json:"enable_debug"`

	// Security
	AutoSave           bool          `json:"auto_save"`
	SessionTimeout     time.Duration `json:"session_timeout"`
	CredentialTimeout  time.Duration `json:"credential_timeout"`
	RequireValidation  bool          `json:"require_validation"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".pathrunner")

	return &Config{
		// Paths
		SessionsDir: filepath.Join(configDir, "sessions"),
		HistoryFile: filepath.Join(configDir, "history"),
		ConfigDir:   configDir,

		// AWS Settings
		DefaultRegion:  "us-east-1",
		DefaultProfile: "",

		// Limits
		MaxSessions:  50,
		MaxHistory:   1000,
		MaxResources: 500,

		// Timeouts
		CommandTimeout: 300,  // 5 minutes
		NetworkTimeout: 30,   // 30 seconds

		// UI Settings
		UseColors:    true,
		AutoComplete: true,
		PromptStyle:  "default",

		// Logging
		LogLevel:    "info",
		LogFile:     filepath.Join(configDir, "pathrunner.log"),
		EnableDebug: false,

		// Security
		AutoSave:           true,
		SessionTimeout:     24 * time.Hour,
		CredentialTimeout:  1 * time.Hour,
		RequireValidation:  true,
	}
}

// Load loads configuration from file, falling back to defaults
func Load() (*Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return DefaultConfig(), nil
	}

	configFile := filepath.Join(homeDir, ".pathrunner", "config.json")

	// If config file doesn't exist, return defaults
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	// Read config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Start with defaults and override with file values
	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate and create directories
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// Save saves the configuration to file
func (c *Config) Save() error {
	configFile := filepath.Join(c.ConfigDir, "config.json")

	// Ensure config directory exists
	if err := os.MkdirAll(c.ConfigDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Marshal config to JSON
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write to file
	if err := os.WriteFile(configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// Validate validates the configuration and creates necessary directories
func (c *Config) Validate() error {
	// Create necessary directories
	dirs := []string{
		c.ConfigDir,
		c.SessionsDir,
		filepath.Dir(c.HistoryFile),
		filepath.Dir(c.LogFile),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Validate limits
	if c.MaxSessions < 1 {
		return fmt.Errorf("max_sessions must be at least 1")
	}
	if c.MaxHistory < 10 {
		return fmt.Errorf("max_history must be at least 10")
	}
	if c.MaxResources < 10 {
		return fmt.Errorf("max_resources must be at least 10")
	}

	// Validate timeouts
	if c.CommandTimeout < 1 {
		return fmt.Errorf("command_timeout must be at least 1 second")
	}
	if c.NetworkTimeout < 1 {
		return fmt.Errorf("network_timeout must be at least 1 second")
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal"}
	if !contains(validLogLevels, c.LogLevel) {
		return fmt.Errorf("invalid log_level: %s", c.LogLevel)
	}

	// Validate prompt style
	validPromptStyles := []string{"default", "minimal", "full"}
	if !contains(validPromptStyles, c.PromptStyle) {
		return fmt.Errorf("invalid prompt_style: %s", c.PromptStyle)
	}

	return nil
}

// GetSessionsDir returns the sessions directory path
func (c *Config) GetSessionsDir() string {
	return c.SessionsDir
}

// GetHistoryFile returns the history file path
func (c *Config) GetHistoryFile() string {
	return c.HistoryFile
}

// GetLogFile returns the log file path
func (c *Config) GetLogFile() string {
	return c.LogFile
}

// IsDebugEnabled returns whether debug mode is enabled
func (c *Config) IsDebugEnabled() bool {
	return c.EnableDebug || c.LogLevel == "debug"
}

// GetCommandTimeoutDuration returns command timeout as duration
func (c *Config) GetCommandTimeoutDuration() time.Duration {
	return time.Duration(c.CommandTimeout) * time.Second
}

// GetNetworkTimeoutDuration returns network timeout as duration
func (c *Config) GetNetworkTimeoutDuration() time.Duration {
	return time.Duration(c.NetworkTimeout) * time.Second
}

// contains checks if a string slice contains a value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Global config instance
var globalConfig *Config

// Init initializes the global configuration
func Init() error {
	var err error
	globalConfig, err = Load()
	return err
}

// Get returns the global configuration instance
func Get() *Config {
	if globalConfig == nil {
		globalConfig = DefaultConfig()
	}
	return globalConfig
}