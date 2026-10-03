// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"os"
	"testing"

	"github.com/DataDog/pathrunner/pkg/core"
)

func TestLogCloudTrailEvent(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	sm.LogCloudTrailEvent("iam", "CreateAccessKey", "us-east-1",
		"Created access key for IAM user alice",
		map[string]string{"target_user": "alice"})

	events := sm.GetCloudTrailEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 CloudTrail event, got %d", len(events))
	}

	ev := events[0]
	if ev.Service != "iam" {
		t.Errorf("Expected service 'iam', got '%s'", ev.Service)
	}
	if ev.Operation != "CreateAccessKey" {
		t.Errorf("Expected operation 'CreateAccessKey', got '%s'", ev.Operation)
	}
	if ev.Region != "us-east-1" {
		t.Errorf("Expected region 'us-east-1', got '%s'", ev.Region)
	}
	if ev.Description != "Created access key for IAM user alice" {
		t.Errorf("Unexpected description: %s", ev.Description)
	}
	if ev.Metadata["target_user"] != "alice" {
		t.Errorf("Expected metadata target_user 'alice', got '%s'", ev.Metadata["target_user"])
	}
}

func TestLogCloudTrailEventSetsModuleID(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	// Simulate the session having a current module set (as the REPL does before Execute())
	session := sm.GetCurrentSession()
	session.CurrentModule = "iam-002"

	sm.LogCloudTrailEvent("iam", "CreateAccessKey", "us-east-1",
		"Created access key", nil)

	events := sm.GetCloudTrailEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].ModuleID != "iam-002" {
		t.Errorf("Expected module ID 'iam-002', got '%s'", events[0].ModuleID)
	}
}

func TestLogMultipleCloudTrailEvents(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	sm.LogCloudTrailEvent("sts", "GetCallerIdentity", "us-east-1", "Verified caller", nil)
	sm.LogCloudTrailEvent("iam", "AttachRolePolicy", "us-east-1", "Attached policy to role", nil)
	sm.LogCloudTrailEvent("sts", "AssumeRole", "us-east-1", "Assumed target role", nil)

	events := sm.GetCloudTrailEvents()
	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(events))
	}
	if events[0].Operation != "GetCallerIdentity" {
		t.Errorf("Expected first event GetCallerIdentity, got %s", events[0].Operation)
	}
	if events[2].Operation != "AssumeRole" {
		t.Errorf("Expected third event AssumeRole, got %s", events[2].Operation)
	}
}

func TestGetCloudTrailEventsEmptyByDefault(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()
	events := sm.GetCloudTrailEvents()

	// Should return empty slice (or nil), not panic
	if len(events) != 0 {
		t.Errorf("Expected no events initially, got %d", len(events))
	}
}

func TestCloudTrailEventTimestamp(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()
	sm.LogCloudTrailEvent("iam", "CreateUser", "us-east-1", "Created IAM user", nil)

	events := sm.GetCloudTrailEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if events[0].Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp on CloudTrail event")
	}
}

func TestCloudTrailEventsWorkspaceIsolation(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	// Log event in workspace A (default)
	sm.LogCloudTrailEvent("iam", "CreateAccessKey", "us-east-1", "Event in default", nil)

	// Switch to workspace B
	_ = sm.CreateSession("workspace-b")
	_ = sm.SwitchSession("workspace-b")

	// Events in workspace B should be empty
	eventsB := sm.GetCloudTrailEvents()
	if len(eventsB) != 0 {
		t.Errorf("Expected no events in workspace-b, got %d", len(eventsB))
	}

	// Log a different event in workspace B
	sm.LogCloudTrailEvent("sts", "AssumeRole", "us-east-1", "Event in workspace-b", nil)

	// Switch back to default
	_ = sm.SwitchSession("default")

	// Default workspace should still only have its original event
	eventsDefault := sm.GetCloudTrailEvents()
	if len(eventsDefault) != 1 {
		t.Errorf("Expected 1 event in default workspace, got %d", len(eventsDefault))
	}
	if eventsDefault[0].Operation != "CreateAccessKey" {
		t.Errorf("Expected CreateAccessKey in default, got %s", eventsDefault[0].Operation)
	}
}
