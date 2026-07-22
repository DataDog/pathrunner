// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/bedrock_startsession_invoke"
)

func TestBedrockStartSessionInvokeModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by primary ID
	if err := r.ExecuteCommand("use bedrock-002"); err != nil {
		t.Fatalf("Failed to use bedrock-002: %v", err)
	}
}

func TestBedrockStartSessionInvokeModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Should be able to select the module by alias
	if err := r.ExecuteCommand("use bedrock-startsession-invoke"); err != nil {
		t.Fatalf("Failed to use bedrock-startsession-invoke alias: %v", err)
	}
}

func TestBedrockStartSessionInvokeModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-002"); err != nil {
		t.Fatalf("Failed to use bedrock-002: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockStartSessionInvokeModuleShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-002"); err != nil {
		t.Fatalf("Failed to use bedrock-002: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockStartSessionInvokeModuleSetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-002"); err != nil {
		t.Fatalf("Failed to use bedrock-002: %v", err)
	}

	// Set INTERPRETER_ID
	if err := r.ExecuteCommand("set INTERPRETER_ID pl-prod-bedrock-002-to-admin-target-interpreter"); err != nil {
		t.Fatalf("Expected set INTERPRETER_ID to succeed: %v", err)
	}

	// Set REGION
	if err := r.ExecuteCommand("set REGION us-east-1"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestBedrockStartSessionInvokeExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-002"); err != nil {
		t.Fatalf("Failed to use bedrock-002: %v", err)
	}

	if err := r.ExecuteCommand("set INTERPRETER_ID pl-prod-bedrock-002-to-admin-target-interpreter"); err != nil {
		t.Fatalf("Failed to set INTERPRETER_ID: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockStartSessionInvokeSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Search for bedrock modules should include bedrock-002
	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockStartSessionInvokeModuleUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-002"); err != nil {
		t.Fatalf("Failed to use bedrock-002: %v", err)
	}

	if err := r.ExecuteCommand("set INTERPRETER_ID pl-prod-bedrock-002-to-admin-target-interpreter"); err != nil {
		t.Fatalf("Failed to set INTERPRETER_ID: %v", err)
	}

	// Unset should work
	if err := r.ExecuteCommand("unset INTERPRETER_ID"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}
