// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ReceivedCredentials represents AWS credentials received from a payload callback.
type ReceivedCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	Region          string `json:"region"`
	ARN             string `json:"arn"`
	SourceIP        string `json:"source_ip"`
}

// credentialsHandler returns an HTTP handler that accepts credential POSTs at /collect.
// Calls onReceived for each valid credential set parsed from the request body.
// Calls emitEvent for every inbound request for operational logging.
func credentialsHandler(onReceived func(ReceivedCredentials), emitEvent func(ListenerEvent)) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		sourceIP := extractSourceIP(r)

		emitEvent(ListenerEvent{
			Type:     EventHTTPRequest,
			SourceIP: sourceIP,
			Method:   r.Method,
			Path:     r.URL.Path,
			Message:  fmt.Sprintf("%s %s from %s", r.Method, r.URL.Path, sourceIP),
		})

		if r.Method != http.MethodPost {
			emitEvent(ListenerEvent{
				Type:     EventCredsError,
				SourceIP: sourceIP,
				Message:  "Rejected request",
				Error:    fmt.Sprintf("method %s not allowed", r.Method),
			})
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
		if err != nil {
			emitEvent(ListenerEvent{
				Type:     EventCredsError,
				SourceIP: sourceIP,
				Message:  "Failed to read request body",
				Error:    err.Error(),
			})
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()

		creds, err := parseCredentials(body)
		if err != nil {
			emitEvent(ListenerEvent{
				Type:     EventCredsError,
				SourceIP: sourceIP,
				Message:  "Failed to parse credentials",
				Error:    fmt.Sprintf("%v (body: %s)", err, truncateForLog(string(body), 200)),
			})
			http.Error(w, fmt.Sprintf("failed to parse credentials: %v", err), http.StatusBadRequest)
			return
		}

		creds.SourceIP = sourceIP

		keyPreview := creds.AccessKeyID
		if len(keyPreview) > 8 {
			keyPreview = creds.AccessKeyID[:4] + "..." + creds.AccessKeyID[len(creds.AccessKeyID)-4:]
		}
		emitEvent(ListenerEvent{
			Type:     EventCredsParsed,
			SourceIP: sourceIP,
			Message:  fmt.Sprintf("Credentials received from %s (key: %s)", sourceIP, keyPreview),
		})

		onReceived(creds)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Catch-all for unexpected paths
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sourceIP := extractSourceIP(r)
		emitEvent(ListenerEvent{
			Type:     EventHTTPRequest,
			SourceIP: sourceIP,
			Method:   r.Method,
			Path:     r.URL.Path,
			Message:  fmt.Sprintf("Unexpected request: %s %s from %s", r.Method, r.URL.Path, sourceIP),
		})
		http.Error(w, "not found", http.StatusNotFound)
	})

	return mux
}

// truncateForLog truncates a string for log output, adding an ellipsis if truncated.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// parseCredentials attempts to extract AWS credentials from a JSON body.
// Supports multiple key naming conventions used by different payload types.
func parseCredentials(body []byte) (ReceivedCredentials, error) {
	var creds ReceivedCredentials

	// Try parsing as a flat object first
	var flat map[string]interface{}
	if err := json.Unmarshal(body, &flat); err != nil {
		return creds, fmt.Errorf("invalid JSON: %v", err)
	}

	// Check for nested "credentials" or "Credentials" key
	credMap := flat
	if nested, ok := flat["credentials"].(map[string]interface{}); ok {
		credMap = nested
	} else if nested, ok := flat["Credentials"].(map[string]interface{}); ok {
		credMap = nested
	}

	// Extract access key ID (multiple naming conventions)
	creds.AccessKeyID = extractStringField(credMap,
		"access_key_id", "AccessKeyId", "access_key", "accessKeyId",
		"aws_access_key_id", "AWS_ACCESS_KEY_ID")

	// Extract secret access key
	creds.SecretAccessKey = extractStringField(credMap,
		"secret_access_key", "SecretAccessKey", "secret_key", "secretAccessKey",
		"aws_secret_access_key", "AWS_SECRET_ACCESS_KEY")

	// Extract session token
	creds.SessionToken = extractStringField(credMap,
		"session_token", "SessionToken", "token", "Token",
		"aws_session_token", "AWS_SESSION_TOKEN")

	// Extract optional fields - check credentials object, then metadata, then top-level
	creds.Region = extractStringField(credMap, "region", "Region", "aws_region", "AWS_REGION")
	if creds.Region == "" {
		if metadata, ok := flat["metadata"].(map[string]interface{}); ok {
			creds.Region = extractStringField(metadata, "region", "Region")
		}
	}
	if creds.Region == "" {
		creds.Region = extractStringField(flat, "region", "Region", "aws_region", "AWS_REGION")
	}
	creds.ARN = extractStringField(credMap, "arn", "ARN", "Arn", "caller_arn")

	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return creds, fmt.Errorf("missing required credential fields (access_key_id, secret_access_key)")
	}

	// Validate extracted fields against expected AWS credential formats.
	// This prevents injection attacks from the internet-facing /collect endpoint.
	if err := validateCredentialFields(creds); err != nil {
		return creds, err
	}

	return creds, nil
}

var (
	accessKeyPattern    = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	secretKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9/+=]{20,128}$`)
	sessionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9/+=]+$`)
	regionPattern       = regexp.MustCompile(`^[a-z]{2}(-[a-z]+-\d+)?$`)
	arnPrefixPattern    = regexp.MustCompile(`^arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:`)
)

// validateCredentialFields checks that extracted credential values match expected
// AWS formats. Rejects values that could be injection attempts (flags, escape
// sequences, etc.) while accepting all valid AWS credential strings.
func validateCredentialFields(creds ReceivedCredentials) error {
	if !accessKeyPattern.MatchString(creds.AccessKeyID) {
		return fmt.Errorf("invalid access key format")
	}
	if !secretKeyPattern.MatchString(creds.SecretAccessKey) {
		return fmt.Errorf("invalid secret key format")
	}
	if creds.SessionToken != "" {
		if len(creds.SessionToken) > 2048 {
			return fmt.Errorf("session token too long")
		}
		if !sessionTokenPattern.MatchString(creds.SessionToken) {
			return fmt.Errorf("invalid session token format")
		}
	}
	if creds.Region != "" {
		if !regionPattern.MatchString(creds.Region) {
			return fmt.Errorf("invalid region format")
		}
	}
	if creds.ARN != "" {
		if !arnPrefixPattern.MatchString(creds.ARN) {
			return fmt.Errorf("invalid ARN format")
		}
	}
	return nil
}

// extractStringField returns the first non-empty string value found for any of the given keys.
func extractStringField(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
		}
	}
	return ""
}

// extractSourceIP gets the client IP from the request.
// Does not trust X-Forwarded-For since this is a direct TLS listener, not behind a proxy.
func extractSourceIP(r *http.Request) string {
	host, _, err := SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SplitHostPort wraps net.SplitHostPort but handles addresses without ports.
func SplitHostPort(addr string) (string, string, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return addr, "", nil
	}
	return host, port, nil
}

func splitHostPort(addr string) (string, string, error) {
	if !strings.Contains(addr, ":") {
		return addr, "", nil
	}
	// Use standard library for proper parsing
	host, port, err := func() (string, string, error) {
		lastColon := strings.LastIndex(addr, ":")
		if lastColon == -1 {
			return addr, "", nil
		}
		// Handle IPv6 [::1]:port
		if addr[0] == '[' {
			bracket := strings.Index(addr, "]")
			if bracket == -1 {
				return addr, "", fmt.Errorf("missing closing bracket")
			}
			if bracket+1 < len(addr) && addr[bracket+1] == ':' {
				return addr[1:bracket], addr[bracket+2:], nil
			}
			return addr[1:bracket], "", nil
		}
		// If multiple colons without brackets, it's IPv6 without port
		if strings.Count(addr, ":") > 1 {
			return addr, "", nil
		}
		return addr[:lastColon], addr[lastColon+1:], nil
	}()
	return host, port, err
}
