// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/pathrunner/pkg/modules"
)

// addSampleData seeds a session with one created resource, one modified resource, and one CloudTrail event.
func addSampleData(sm interface {
	TrackResource(modules.CreatedResource)
	LogCloudTrailEvent(service, operation, region, description string, metadata map[string]string)
}) {
	sm.TrackResource(modules.CreatedResource{
		Type:          "lambda:function",
		Name:          "pathrunner-export-test-fn",
		ARN:           "arn:aws:lambda:us-east-1:123456789012:function:pathrunner-export-test-fn",
		Region:        "us-east-1",
		CleanupMethod: "delete the Lambda function",
		ModuleID:      "lambda-001",
		Created:       time.Now(),
	})
	sm.LogCloudTrailEvent("lambda", "CreateFunction", "us-east-1",
		"Created exploit Lambda function", map[string]string{"function_name": "pathrunner-export-test-fn"})
}

// TestWorkspaceReport_HTMLExport verifies that --output <file.html> writes a valid HTML report.
func TestWorkspaceReport_HTMLExport(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	addSampleData(sm)

	outputPath := filepath.Join(t.TempDir(), "report.html")

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report --output " + outputPath)
	})

	if !strings.Contains(output, "Report written to") {
		t.Errorf("expected confirmation message, got: %q", output)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("HTML report not written: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected HTML doctype")
	}
	if !strings.Contains(html, "pathrunner-export-test-fn") {
		t.Error("expected resource name in HTML output")
	}
	if !strings.Contains(html, "CreateFunction") {
		t.Error("expected CloudTrail event in HTML output")
	}
	if !strings.Contains(html, "aws lambda delete-function") {
		t.Error("expected cleanup command in HTML output")
	}
}

// TestWorkspaceReport_MarkdownExport verifies that --output <file.md> writes a valid Markdown report.
func TestWorkspaceReport_MarkdownExport(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	addSampleData(sm)

	outputPath := filepath.Join(t.TempDir(), "report.md")

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report --output " + outputPath)
	})

	if !strings.Contains(output, "Report written to") {
		t.Errorf("expected confirmation message, got: %q", output)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Markdown report not written: %v", err)
	}

	md := string(data)
	if !strings.Contains(md, "# Pathrunner Workspace Report") {
		t.Error("expected Markdown h1 heading")
	}
	if !strings.Contains(md, "pathrunner-export-test-fn") {
		t.Error("expected resource name in Markdown output")
	}
	if !strings.Contains(md, "CreateFunction") {
		t.Error("expected CloudTrail event in Markdown output")
	}
	if !strings.Contains(md, "aws lambda delete-function") {
		t.Error("expected cleanup command in Markdown output")
	}
}

// TestWorkspaceReport_HTMLExportWithModuleFilter verifies that --module filtering works with --output.
func TestWorkspaceReport_HTMLExportWithModuleFilter(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	addSampleData(sm)
	// Add a second resource with a different module ID
	sm.TrackResource(modules.CreatedResource{
		Type:          "iam:role",
		Name:          "other-module-role",
		Region:        "us-east-1",
		CleanupMethod: "delete the IAM role",
		ModuleID:      "iam-001",
		Created:       time.Now(),
	})

	outputPath := filepath.Join(t.TempDir(), "filtered.html")

	captureOutput(func() {
		_ = r.ExecuteCommand("workspace report --module lambda-001 --output " + outputPath)
	})

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("HTML report not written: %v", err)
	}

	html := string(data)
	// The lambda resource should be in the report
	if !strings.Contains(html, "pathrunner-export-test-fn") {
		t.Error("expected lambda-001 resource in filtered output")
	}
	// The iam-001 resource should NOT be in the report
	if strings.Contains(html, "other-module-role") {
		t.Error("expected iam-001 resource to be excluded by module filter")
	}
}

// TestWorkspaceReport_UnknownExtension verifies that unsupported extensions return an error.
func TestWorkspaceReport_UnknownExtension(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	addSampleData(sm)

	outputPath := filepath.Join(t.TempDir(), "report.csv")

	output := captureOutput(func() {
		err := r.ExecuteCommand("workspace report --output " + outputPath)
		if err == nil {
			t.Error("expected error for unsupported extension, got nil")
		}
	})

	// File should not have been created
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("expected output file to not exist for unsupported format")
	}
	// Should not print a success message
	if strings.Contains(output, "Report written to") {
		t.Errorf("unexpected success message for unsupported format: %q", output)
	}
}

// TestWorkspaceReport_TerminalRenderingUnchanged verifies that plain `workspace report` still
// renders to the terminal when no --output flag is provided.
func TestWorkspaceReport_TerminalRenderingUnchanged(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	addSampleData(sm)

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report")
	})

	if !strings.Contains(output, "CREATED RESOURCES") {
		t.Error("expected terminal report to still contain CREATED RESOURCES section")
	}
	if !strings.Contains(output, "CLOUDTRAIL EVENTS") {
		t.Error("expected terminal report to still contain CLOUDTRAIL EVENTS section")
	}
	if strings.Contains(output, "Report written to") {
		t.Error("unexpected file-write message in terminal mode")
	}
}
