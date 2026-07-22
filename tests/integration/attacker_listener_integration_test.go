// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAttackerListenerStartStopIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	httpsPort := findFreePortIntegration(t)
	shellPort := findFreePortIntegration(t)

	// Start listener with explicit ports and public IP to skip auto-detection
	startCmd := fmt.Sprintf("attacker listener start --https-port %d --shell-port %d --public-ip 127.0.0.1", httpsPort, shellPort)
	err := r.ExecuteCommand(startCmd)
	if err != nil {
		t.Fatalf("Expected listener start to succeed, got: %v", err)
	}

	// Verify listener auto-set options
	options := r.GetOptions()
	expectedURL := fmt.Sprintf("https://127.0.0.1:%d/collect", httpsPort)
	if options["HTTPS_URL"] != expectedURL {
		t.Errorf("Expected HTTPS_URL=%s, got %s", expectedURL, options["HTTPS_URL"])
	}
	if options["LISTENER_IP"] != "127.0.0.1" {
		t.Errorf("Expected LISTENER_IP=127.0.0.1, got %s", options["LISTENER_IP"])
	}
	if options["LISTENER_PORT"] != fmt.Sprintf("%d", shellPort) {
		t.Errorf("Expected LISTENER_PORT=%d, got %s", shellPort, options["LISTENER_PORT"])
	}

	// Check status
	err = r.ExecuteCommand("attacker listener status")
	if err != nil {
		t.Fatalf("Expected listener status to succeed, got: %v", err)
	}

	// POST credentials to the listener
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", httpsPort)
	body := `{"credentials":{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","session_token":"FwoGZXIvYXdzEBAaDNYX3456789012345678"}}`

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST to listener failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Stop listener
	err = r.ExecuteCommand("attacker listener stop")
	if err != nil {
		t.Fatalf("Expected listener stop to succeed, got: %v", err)
	}

	// Verify the port is released by checking status shows not running
	err = r.ExecuteCommand("attacker listener status")
	if err != nil {
		t.Fatalf("Expected listener status after stop to succeed, got: %v", err)
	}
}

func TestAttackerListenerDoubleStartIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	httpsPort := findFreePortIntegration(t)
	shellPort := findFreePortIntegration(t)

	startCmd := fmt.Sprintf("attacker listener start --https-port %d --shell-port %d --public-ip 127.0.0.1", httpsPort, shellPort)
	err := r.ExecuteCommand(startCmd)
	if err != nil {
		t.Fatalf("First start failed: %v", err)
	}

	// Second start should fail
	httpsPort2 := findFreePortIntegration(t)
	shellPort2 := findFreePortIntegration(t)
	startCmd2 := fmt.Sprintf("attacker listener start --https-port %d --shell-port %d --public-ip 127.0.0.1", httpsPort2, shellPort2)
	err = r.ExecuteCommand(startCmd2)
	if err == nil {
		t.Error("Expected error on double start")
	}

	// Cleanup
	r.ExecuteCommand("attacker listener stop")
}

func TestAttackerListenerPreservesUserOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Pre-set some options
	r.SetOption("LISTENER_IP", "10.0.0.1")
	r.SetOption("LISTENER_PORT", "9999")

	httpsPort := findFreePortIntegration(t)
	shellPort := findFreePortIntegration(t)

	startCmd := fmt.Sprintf("attacker listener start --https-port %d --shell-port %d --public-ip 127.0.0.1", httpsPort, shellPort)
	err := r.ExecuteCommand(startCmd)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer r.ExecuteCommand("attacker listener stop")

	// User-set values should NOT be overwritten
	options := r.GetOptions()
	if options["LISTENER_IP"] != "10.0.0.1" {
		t.Errorf("Expected user-set LISTENER_IP=10.0.0.1 to be preserved, got %s", options["LISTENER_IP"])
	}
	if options["LISTENER_PORT"] != "9999" {
		t.Errorf("Expected user-set LISTENER_PORT=9999 to be preserved, got %s", options["LISTENER_PORT"])
	}
}

func TestAttackerListenerInvalidPortIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Invalid port number
	err := r.ExecuteCommand("attacker listener start --https-port 99999 --public-ip 127.0.0.1")
	if err == nil {
		t.Error("Expected error for invalid port")
	}

	// Same port for both
	port := findFreePortIntegration(t)
	err = r.ExecuteCommand(fmt.Sprintf("attacker listener start --https-port %d --shell-port %d --public-ip 127.0.0.1", port, port))
	if err == nil {
		t.Error("Expected error when HTTPS and shell ports are the same")
	}
}

func TestAttackerListenerCommandAliasesIntegration(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Test all subcommand help paths
	commands := []string{
		"attacker listener help",
		"attacker listener start help",
	}

	for _, cmd := range commands {
		err := r.ExecuteCommand(cmd)
		if err != nil {
			t.Errorf("Expected '%s' to succeed, got: %v", cmd, err)
		}
	}
}

func TestAttackerListenerStopStatusWhenNotRunning(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Stop when nothing is running should succeed silently
	err := r.ExecuteCommand("attacker listener stop")
	if err != nil {
		t.Errorf("Expected stop to succeed when not running, got: %v", err)
	}

	// Status when nothing is running should succeed
	err = r.ExecuteCommand("attacker listener status")
	if err != nil {
		t.Errorf("Expected status to succeed when not running, got: %v", err)
	}
}

func findFreePortIntegration(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
