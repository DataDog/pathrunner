// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package repl

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseExportArgsDefaults(t *testing.T) {
	format, name, copy, err := parseExportArgs([]string{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if format != "env" {
		t.Errorf("expected default format 'env', got '%s'", format)
	}
	if name != "" {
		t.Errorf("expected empty name, got '%s'", name)
	}
	if copy {
		t.Error("expected copy flag to default false")
	}
}

func TestParseExportArgsFormatVariants(t *testing.T) {
	cases := []struct {
		args   []string
		format string
	}{
		{[]string{"--format", "profile"}, "profile"},
		{[]string{"--format=profile"}, "profile"},
		{[]string{"-f", "json"}, "json"},
		{[]string{"--copy"}, "env"},
		{[]string{"my-identity"}, "env"},
	}

	for _, tc := range cases {
		format, _, _, err := parseExportArgs(tc.args)
		if err != nil {
			t.Errorf("parseExportArgs(%v) returned error: %v", tc.args, err)
			continue
		}
		if format != tc.format {
			t.Errorf("parseExportArgs(%v) format = '%s', expected '%s'", tc.args, format, tc.format)
		}
	}
}

func TestParseExportArgsNameAndCopy(t *testing.T) {
	format, name, copy, err := parseExportArgs([]string{"stolen-role", "--copy", "--format", "profile"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if format != "profile" {
		t.Errorf("expected format 'profile', got '%s'", format)
	}
	if name != "stolen-role" {
		t.Errorf("expected name 'stolen-role', got '%s'", name)
	}
	if !copy {
		t.Error("expected copy flag true")
	}
}

func TestParseExportArgsErrors(t *testing.T) {
	cases := [][]string{
		{"--format"},
		{"--format", "yaml"},
		{"--format=yaml"},
		{"--unknown-flag"},
		{"one-identity", "another-identity"},
	}

	for _, args := range cases {
		_, _, _, err := parseExportArgs(args)
		if err == nil {
			t.Errorf("parseExportArgs(%v) expected error, got none", args)
		}
	}
}

func TestBuildExportLinesEnvFormat(t *testing.T) {
	creds := resolvedCredentials{
		AccessKeyID:  "ASIAEXAMPLE",
		SecretKey:    "wJalrXUtnFEMI",
		SessionToken: "FwoGZXIvYXdzE",
		Region:       "us-east-1",
	}

	lines, err := buildExportLines("test", creds, "env")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	expected := []string{
		"export AWS_ACCESS_KEY_ID=ASIAEXAMPLE",
		"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
		"export AWS_SESSION_TOKEN=FwoGZXIvYXdzE",
		"export AWS_DEFAULT_REGION=us-east-1",
	}
	if !reflect.DeepEqual(lines, expected) {
		t.Errorf("env format mismatch:\n got: %v\nwant: %v", lines, expected)
	}
}

func TestBuildExportLinesEnvFormatOmitsOptional(t *testing.T) {
	creds := resolvedCredentials{
		AccessKeyID: "AKIAEXAMPLE",
		SecretKey:   "secret",
	}

	lines, err := buildExportLines("test", creds, "env")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(lines) != 2 {
		t.Errorf("expected 2 lines without token/region, got %d: %v", len(lines), lines)
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line != "export AWS_ACCESS_KEY_ID=AKIAEXAMPLE" && line != "export AWS_SECRET_ACCESS_KEY=secret" {
			t.Errorf("unexpected line: %s", line)
		}
	}
}

func TestBuildExportLinesProfileFormat(t *testing.T) {
	creds := resolvedCredentials{
		AccessKeyID:  "ASIAEXAMPLE",
		SecretKey:    "wJalrXUtnFEMI",
		SessionToken: "FwoGZXIvYXdzE",
		Region:       "us-west-2",
	}

	lines, err := buildExportLines("stolen-role", creds, "profile")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	expected := []string{
		"[stolen-role]",
		"aws_access_key_id = ASIAEXAMPLE",
		"aws_secret_access_key = wJalrXUtnFEMI",
		"aws_session_token = FwoGZXIvYXdzE",
		"region = us-west-2",
	}
	if !reflect.DeepEqual(lines, expected) {
		t.Errorf("profile format mismatch:\n got: %v\nwant: %v", lines, expected)
	}
}

func TestBuildExportLinesProfileFormatDefaultName(t *testing.T) {
	creds := resolvedCredentials{
		AccessKeyID: "AKIAEXAMPLE",
		SecretKey:   "secret",
		Region:      "us-east-1",
	}

	lines, err := buildExportLines("", creds, "profile")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if lines[0] != "[pathrunner]" {
		t.Errorf("expected default profile name '[pathrunner]', got '%s'", lines[0])
	}
}

func TestBuildExportLinesJsonFormat(t *testing.T) {
	creds := resolvedCredentials{
		AccessKeyID:  "ASIAEXAMPLE",
		SecretKey:    "wJalrXUtnFEMI",
		SessionToken: "FwoGZXIvYXdzE",
		Region:       "us-east-1",
	}

	lines, err := buildExportLines("test", creds, "json")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("json output not valid JSON: %v\n%s", err, lines[0])
	}

	if parsed["AWS_ACCESS_KEY_ID"] != "ASIAEXAMPLE" {
		t.Errorf("expected AWS_ACCESS_KEY_ID in json, got: %v", parsed)
	}
	if parsed["AWS_SESSION_TOKEN"] != "FwoGZXIvYXdzE" {
		t.Errorf("expected AWS_SESSION_TOKEN in json, got: %v", parsed)
	}
	if parsed["AWS_DEFAULT_REGION"] != "us-east-1" {
		t.Errorf("expected AWS_DEFAULT_REGION in json, got: %v", parsed)
	}
}

func TestBuildExportLinesInvalidFormat(t *testing.T) {
	_, err := buildExportLines("test", resolvedCredentials{}, "yaml")
	if err == nil {
		t.Error("expected error for invalid format, got none")
	}
}
