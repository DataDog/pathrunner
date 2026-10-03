// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/pathrunner/pkg/modules"
)

// captureOutput redirects stdout to capture printed output during a function call.
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// TestWorkspaceReportShowsCloudTrailSection verifies that workspace report
// includes the CloudTrail events section when events have been logged.
func TestWorkspaceReportShowsCloudTrailSection(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	// Log CloudTrail events into the session manager
	sm.LogCloudTrailEvent("iam", "CreateAccessKey", "us-east-1",
		"Created access key for IAM user alice", map[string]string{"target_user": "alice"})
	sm.LogCloudTrailEvent("sts", "GetCallerIdentity", "us-east-1",
		"Verified new credentials work", nil)

	// Also add a resource so the report does not early-exit
	sm.TrackResource(modules.CreatedResource{
		Type:          "iam:access-key",
		Name:          "AKIA1234567890",
		Region:        "us-east-1",
		Created:       time.Now(),
		CleanupMethod: "iam:DeleteAccessKey",
		ModuleID:      "iam-002",
	})

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report")
	})

	if !strings.Contains(output, "CLOUDTRAIL EVENTS") {
		t.Errorf("Expected 'CLOUDTRAIL EVENTS' section in report output, got:\n%s", output)
	}
	if !strings.Contains(output, "CreateAccessKey") {
		t.Errorf("Expected 'CreateAccessKey' in report output, got:\n%s", output)
	}
	if !strings.Contains(output, "GetCallerIdentity") {
		t.Errorf("Expected 'GetCallerIdentity' in report output, got:\n%s", output)
	}
	if !strings.Contains(output, "blue team") {
		t.Errorf("Expected 'blue team' label in CloudTrail section header, got:\n%s", output)
	}
}

// TestWorkspaceReportCloudTrailOnlyNoResources verifies that the report shows
// CloudTrail events even when there are no created resources.
func TestWorkspaceReportCloudTrailOnlyNoResources(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	sm.LogCloudTrailEvent("sts", "AssumeRole", "us-east-1",
		"Assumed target role arn:aws:iam::123456789012:role/Target",
		map[string]string{"role_arn": "arn:aws:iam::123456789012:role/Target"})

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report")
	})

	if strings.Contains(output, "Nothing to report") {
		t.Error("Expected report to show content when CloudTrail events exist, not 'Nothing to report'")
	}
	if !strings.Contains(output, "CLOUDTRAIL EVENTS") {
		t.Errorf("Expected 'CLOUDTRAIL EVENTS' section, got:\n%s", output)
	}
	if !strings.Contains(output, "AssumeRole") {
		t.Errorf("Expected 'AssumeRole' in output, got:\n%s", output)
	}
}

// TestWorkspaceReportNothingWhenEmpty verifies the early-exit message appears
// when there are no resources AND no CloudTrail events.
func TestWorkspaceReportNothingWhenEmpty(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	output := captureOutput(func() {
		err := r.ExecuteCommand("workspace report")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	if !strings.Contains(output, "Nothing to report") {
		t.Errorf("Expected 'Nothing to report' when workspace is empty, got:\n%s", output)
	}
}

// TestWorkspaceReportModuleFilterIncludesEvents verifies that --module filter
// applies to CloudTrail events as well as resources.
func TestWorkspaceReportModuleFilterIncludesEvents(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	// Log event for iam-002 by setting CurrentModule before logging
	session := sm.GetCurrentSession()
	session.CurrentModule = "iam-002"
	sm.LogCloudTrailEvent("iam", "CreateAccessKey", "us-east-1",
		"Created access key for user alice", nil)

	// Log event for sts-001
	session.CurrentModule = "sts-001"
	sm.LogCloudTrailEvent("sts", "AssumeRole", "us-east-1",
		"Assumed target role", nil)

	sm.TrackResource(modules.CreatedResource{
		Type:          "iam:access-key",
		Name:          "AKIA1234",
		Region:        "us-east-1",
		Created:       time.Now(),
		CleanupMethod: "iam:DeleteAccessKey",
		ModuleID:      "iam-002",
	})

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report --module iam-002")
	})

	if !strings.Contains(output, "CreateAccessKey") {
		t.Errorf("Expected iam-002 event 'CreateAccessKey' in filtered report, got:\n%s", output)
	}
	if strings.Contains(output, "AssumeRole") {
		t.Errorf("Expected sts-001 event 'AssumeRole' to be filtered out, but it appeared:\n%s", output)
	}
}

// TestWorkspaceReportDescriptionAppears verifies that the description field
// is rendered in the CloudTrail events table.
func TestWorkspaceReportDescriptionAppears(t *testing.T) {
	r, sm, _, cleanup := setupTest(t)
	defer cleanup()

	sm.LogCloudTrailEvent("lambda", "CreateFunction", "us-west-2",
		"Created payload Lambda function for code execution", nil)

	output := captureOutput(func() {
		_ = r.ExecuteCommand("workspace report")
	})

	if !strings.Contains(output, "Created payload Lambda function") {
		t.Errorf("Expected description in report output, got:\n%s", output)
	}
}
