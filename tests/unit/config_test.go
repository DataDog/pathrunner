package unit

import (
	"os"
	"path/filepath"
	"pathrunner/pkg/config"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg == nil {
		t.Fatal("Expected default config, got nil")
	}

	// Test default values
	if cfg.DefaultRegion != "us-east-1" {
		t.Errorf("Expected default region 'us-east-1', got '%s'", cfg.DefaultRegion)
	}

	if cfg.MaxSessions != 50 {
		t.Errorf("Expected max sessions 50, got %d", cfg.MaxSessions)
	}

	if cfg.CommandTimeout != 300 {
		t.Errorf("Expected command timeout 300, got %d", cfg.CommandTimeout)
	}

	if !cfg.UseColors {
		t.Error("Expected colors to be enabled by default")
	}
}

func TestConfigPaths(t *testing.T) {
	cfg := config.DefaultConfig()

	homeDir, _ := os.UserHomeDir()
	expectedConfigDir := filepath.Join(homeDir, ".pathrunner")

	if cfg.GetSessionsDir() != filepath.Join(expectedConfigDir, "sessions") {
		t.Errorf("Expected sessions dir '%s', got '%s'",
			filepath.Join(expectedConfigDir, "sessions"), cfg.GetSessionsDir())
	}

	if cfg.GetHistoryFile() != filepath.Join(expectedConfigDir, "history") {
		t.Errorf("Expected history file '%s', got '%s'",
			filepath.Join(expectedConfigDir, "history"), cfg.GetHistoryFile())
	}
}

func TestConfigTimeouts(t *testing.T) {
	cfg := config.DefaultConfig()

	cmdTimeout := cfg.GetCommandTimeoutDuration()
	expectedCmdTimeout := time.Duration(300) * time.Second

	if cmdTimeout != expectedCmdTimeout {
		t.Errorf("Expected command timeout %v, got %v", expectedCmdTimeout, cmdTimeout)
	}

	netTimeout := cfg.GetNetworkTimeoutDuration()
	expectedNetTimeout := time.Duration(30) * time.Second

	if netTimeout != expectedNetTimeout {
		t.Errorf("Expected network timeout %v, got %v", expectedNetTimeout, netTimeout)
	}
}

func TestConfigDebugMode(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test default debug mode
	if cfg.IsDebugEnabled() {
		t.Error("Expected debug to be disabled by default")
	}

	// Test explicit debug enable
	cfg.EnableDebug = true
	if !cfg.IsDebugEnabled() {
		t.Error("Expected debug to be enabled when EnableDebug is true")
	}

	// Test debug via log level
	cfg.EnableDebug = false
	cfg.LogLevel = "debug"
	if !cfg.IsDebugEnabled() {
		t.Error("Expected debug to be enabled when LogLevel is 'debug'")
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test valid config
	if err := cfg.Validate(); err != nil {
		t.Errorf("Expected valid config to pass validation, got error: %v", err)
	}

	// Test invalid max sessions
	cfg.MaxSessions = 0
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation to fail with max_sessions = 0")
	}

	// Reset and test invalid log level
	cfg = config.DefaultConfig()
	cfg.LogLevel = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation to fail with invalid log level")
	}

	// Reset and test invalid timeout
	cfg = config.DefaultConfig()
	cfg.CommandTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation to fail with command_timeout = 0")
	}
}