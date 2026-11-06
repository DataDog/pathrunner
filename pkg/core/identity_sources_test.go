// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeEnv builds an os.Getenv-style lookup over a static map
func fakeEnv(vars map[string]string) func(string) string {
	return func(key string) string { return vars[key] }
}

func TestBuildEnvVarsIdentityMissingRequiredVars(t *testing.T) {
	_, err := buildEnvVarsIdentity(fakeEnv(map[string]string{}), "")
	if err == nil {
		t.Fatal("expected error when AWS environment variables are missing")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") || !strings.Contains(err.Error(), "AWS_SECRET_ACCESS_KEY") {
		t.Errorf("expected error to name the required environment variables, got: %v", err)
	}
}

func TestBuildEnvVarsIdentityMissingSecretKey(t *testing.T) {
	vars := map[string]string{"AWS_ACCESS_KEY_ID": "ASIAEXAMPLEKEYID"}
	if _, err := buildEnvVarsIdentity(fakeEnv(vars), ""); err == nil {
		t.Fatal("expected error when AWS_SECRET_ACCESS_KEY is missing")
	}
}

func TestBuildEnvVarsIdentitySnapshotsCredentials(t *testing.T) {
	vars := map[string]string{
		"AWS_ACCESS_KEY_ID":     "ASIAEXAMPLEKEYID",
		"AWS_SECRET_ACCESS_KEY": "secretvalue",
		"AWS_SESSION_TOKEN":    "sessiontoken",
		"AWS_REGION":           "us-west-2",
	}
	identity, err := buildEnvVarsIdentity(fakeEnv(vars), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.Name != "env" {
		t.Errorf("expected default name 'env', got %q", identity.Name)
	}
	if identity.Type != "env" {
		t.Errorf("expected type 'env', got %q", identity.Type)
	}
	if identity.AccessKeyID != "ASIAEXAMPLEKEYID" || identity.SecretKey != "secretvalue" || identity.SessionToken != "sessiontoken" {
		t.Error("expected credentials to be snapshotted into static fields")
	}
	if identity.Region != "us-west-2" {
		t.Errorf("expected region us-west-2, got %q", identity.Region)
	}
	// Session creds are short-lived; an expiry must be recorded
	if identity.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set for session credentials")
	}
}

func TestBuildEnvVarsIdentityCustomNameAndRegionDefaults(t *testing.T) {
	vars := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAEXAMPLEKEYID",
		"AWS_SECRET_ACCESS_KEY": "secretvalue",
		"AWS_DEFAULT_REGION":    "eu-west-1",
	}
	identity, err := buildEnvVarsIdentity(fakeEnv(vars), "lambda-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.Name != "lambda-role" {
		t.Errorf("expected custom name 'lambda-role', got %q", identity.Name)
	}
	// AWS_DEFAULT_REGION should be honored when AWS_REGION is absent
	if identity.Region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %q", identity.Region)
	}
	// Long-lived access keys have no expiry
	if identity.ExpiresAt != nil {
		t.Error("expected no expiry for credentials without a session token")
	}
}

func TestBuildEnvVarsIdentityFallsBackToDefaultRegion(t *testing.T) {
	vars := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAEXAMPLEKEYID",
		"AWS_SECRET_ACCESS_KEY": "secretvalue",
	}
	identity, err := buildEnvVarsIdentity(fakeEnv(vars), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Region != "us-east-1" {
		t.Errorf("expected fallback region us-east-1, got %q", identity.Region)
	}
}

func TestBuildEnvVarsIdentityParsesCredentialExpiration(t *testing.T) {
	expected := time.Now().Add(90 * time.Minute).UTC().Truncate(time.Second)
	vars := map[string]string{
		"AWS_ACCESS_KEY_ID":         "ASIAEXAMPLEKEYID",
		"AWS_SECRET_ACCESS_KEY":     "secretvalue",
		"AWS_SESSION_TOKEN":         "sessiontoken",
		"AWS_CREDENTIAL_EXPIRATION": expected.Format(time.RFC3339),
	}
	identity, err := buildEnvVarsIdentity(fakeEnv(vars), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt parsed from AWS_CREDENTIAL_EXPIRATION")
	}
	if !identity.ExpiresAt.Equal(expected) {
		t.Errorf("expected expiry %v, got %v", expected, identity.ExpiresAt)
	}
}

func TestAddIdentityFromEnvVarsRequiresEnvVars(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	im := NewIdentityManager(func() string { return "" }, func() {})

	err := im.AddIdentity([]string{"--from-env-vars"})
	if err == nil {
		t.Fatal("expected error when environment variables are not set")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("expected error to mention AWS_ACCESS_KEY_ID, got: %v", err)
	}
	if len(im.GetIdentities()) != 0 {
		t.Error("expected no identity to be stored on failure")
	}
}

func TestAddIdentityUnknownOptionUnchanged(t *testing.T) {
	im := NewIdentityManager(func() string { return "" }, func() {})
	err := im.AddIdentity([]string{"--from-nonsense"})
	if err == nil || !strings.Contains(err.Error(), "unknown add option") {
		t.Fatalf("expected unknown add option error, got: %v", err)
	}
}

func TestARNResourceName(t *testing.T) {
	cases := []struct {
		arn      string
		expected string
	}{
		{"arn:aws:iam::123456789012:instance-profile/pl-lab-ec2-role", "pl-lab-ec2-role"},
		{"arn:aws:iam::123456789012:role/nested/path/role-name", "role-name"},
		{"no-slashes-at-all", "no-slashes-at-all"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := arnResourceName(tc.arn); got != tc.expected {
			t.Errorf("arnResourceName(%q) = %q, expected %q", tc.arn, got, tc.expected)
		}
	}
}

func TestProbeIMDSRoleUnreachable(t *testing.T) {
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := probeIMDSRole(probeCtx)
	if err == nil {
		// IMDS is reachable and an instance role is attached; the probe
		// legitimately succeeded (test host is an EC2 instance).
		t.Skip("IMDS available; running on an EC2 instance with an attached role")
	}
	if !strings.Contains(err.Error(), "instance metadata") && !strings.Contains(err.Error(), "identity document") {
		t.Errorf("expected IMDS failure message, got: %v", err)
	}
}
