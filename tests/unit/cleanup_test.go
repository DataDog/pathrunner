// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/core"
	"github.com/DataDog/pathrunner/pkg/modules"
	"testing"
)

func TestModuleIDFieldPersistence(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	// Track a resource with ModuleID
	resource := modules.CreatedResource{
		Type:          "lambda:function",
		Name:          "test-function",
		ARN:           "arn:aws:lambda:us-east-1:123456789012:function:test-function",
		Region:        "us-east-1",
		CleanupMethod: "lambda:DeleteFunction",
		ModuleID:      "lambda-001",
		Metadata: map[string]string{
			"runtime": "python3.9",
		},
	}

	sm.TrackResource(resource)

	// Save session
	current := sm.GetCurrentSession()
	err := sm.SaveSession(current)
	if err != nil {
		t.Fatalf("Expected no error saving session, got: %v", err)
	}

	// Create new session manager (simulates restart)
	sm2 := core.NewSessionManager()

	// Verify ModuleID was persisted
	resources := sm2.GetCreatedResources()
	if len(resources) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(resources))
	}

	if resources[0].ModuleID != "lambda-001" {
		t.Errorf("Expected ModuleID 'lambda-001', got '%s'", resources[0].ModuleID)
	}

	if resources[0].Name != "test-function" {
		t.Errorf("Expected Name 'test-function', got '%s'", resources[0].Name)
	}
}

func TestModuleIDFieldEmpty(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	// Track a resource without ModuleID (backward compatibility)
	resource := modules.CreatedResource{
		Type:          "iam:role",
		Name:          "test-role",
		Region:        "us-east-1",
		CleanupMethod: "iam:DeleteRole",
	}

	sm.TrackResource(resource)

	resources := sm.GetCreatedResources()
	if len(resources) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(resources))
	}

	if resources[0].ModuleID != "" {
		t.Errorf("Expected empty ModuleID, got '%s'", resources[0].ModuleID)
	}
}

func TestMultipleResourcesWithModuleFilter(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	_ = os.Setenv("HOME", tempDir)
	defer func() { _ = os.Setenv("HOME", originalHome) }()

	sm := core.NewSessionManager()

	// Track resources from different modules
	sm.TrackResource(modules.CreatedResource{
		Type:     "lambda:function",
		Name:     "func1",
		Region:   "us-east-1",
		ModuleID: "lambda-001",
	})
	sm.TrackResource(modules.CreatedResource{
		Type:     "ec2:instance",
		Name:     "inst1",
		Region:   "us-east-1",
		ModuleID: "ec2-001",
	})
	sm.TrackResource(modules.CreatedResource{
		Type:     "lambda:function",
		Name:     "func2",
		Region:   "us-east-1",
		ModuleID: "lambda-001",
	})

	resources := sm.GetCreatedResources()
	if len(resources) != 3 {
		t.Fatalf("Expected 3 resources, got %d", len(resources))
	}

	// Verify we can filter by ModuleID manually (simulates what cleanup does)
	var lambdaResources []core.CreatedResource
	for _, r := range resources {
		if r.ModuleID == "lambda-001" {
			lambdaResources = append(lambdaResources, r)
		}
	}

	if len(lambdaResources) != 2 {
		t.Errorf("Expected 2 lambda-001 resources, got %d", len(lambdaResources))
	}

	var ec2Resources []core.CreatedResource
	for _, r := range resources {
		if r.ModuleID == "ec2-001" {
			ec2Resources = append(ec2Resources, r)
		}
	}

	if len(ec2Resources) != 1 {
		t.Errorf("Expected 1 ec2-001 resource, got %d", len(ec2Resources))
	}
}

func TestCreatedResourceModuleIDInStruct(t *testing.T) {
	// Verify both modules and core CreatedResource have ModuleID
	t.Run("modules.CreatedResource", func(t *testing.T) {
		r := modules.CreatedResource{
			Type:     "test",
			Name:     "test",
			ModuleID: "test-001",
		}
		if r.ModuleID != "test-001" {
			t.Errorf("Expected ModuleID 'test-001', got '%s'", r.ModuleID)
		}
	})

	t.Run("core.CreatedResource", func(t *testing.T) {
		r := core.CreatedResource{
			Type:     "test",
			Name:     "test",
			ModuleID: "test-001",
		}
		if r.ModuleID != "test-001" {
			t.Errorf("Expected ModuleID 'test-001', got '%s'", r.ModuleID)
		}
	})
}
