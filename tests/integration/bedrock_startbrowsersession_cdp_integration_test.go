// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/bedrock_startbrowsersession_cdp"
)

func TestBedrockStartBrowserSessionCDPModuleUse(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPModuleUseAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-startbrowsersession-cdp"); err != nil {
		t.Fatalf("Failed to use 'bedrock-startbrowsersession-cdp' alias: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPModuleInfo(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}

	if err := r.ExecuteCommand("info"); err != nil {
		t.Fatalf("Expected info to succeed: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPShowOptions(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}

	if err := r.ExecuteCommand("show options"); err != nil {
		t.Fatalf("Expected show options to succeed: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPSetBrowserID(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}

	if err := r.ExecuteCommand("set BROWSER_ID test-browser-id-12345"); err != nil {
		t.Fatalf("Expected set BROWSER_ID to succeed: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPSetRegion(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}

	if err := r.ExecuteCommand("set REGION us-west-2"); err != nil {
		t.Fatalf("Expected set REGION to succeed: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPExploitNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}

	if err := r.ExecuteCommand("set BROWSER_ID test-browser-id-12345"); err != nil {
		t.Fatalf("Failed to set BROWSER_ID: %v", err)
	}

	// Exploit without identity should fail
	err := r.ExecuteCommand("exploit")
	if err == nil {
		t.Error("Expected exploit to fail without identity")
	}
}

func TestBedrockStartBrowserSessionCDPSearchable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("search bedrock"); err != nil {
		t.Fatalf("Expected search to succeed: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPUnsetOption(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use bedrock-007"); err != nil {
		t.Fatalf("Failed to use bedrock-007: %v", err)
	}

	if err := r.ExecuteCommand("set BROWSER_ID test-browser-id-12345"); err != nil {
		t.Fatalf("Failed to set BROWSER_ID: %v", err)
	}

	if err := r.ExecuteCommand("unset BROWSER_ID"); err != nil {
		t.Fatalf("Expected unset to succeed: %v", err)
	}
}

func TestBedrockStartBrowserSessionCDPSecondAlias(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	if err := r.ExecuteCommand("use exploit/bedrock_startbrowsersession_cdp"); err != nil {
		t.Fatalf("Failed to use 'exploit/bedrock_startbrowsersession_cdp' alias: %v", err)
	}
}
