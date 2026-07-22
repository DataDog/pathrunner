// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"testing"

	"github.com/DataDog/pathrunner/pkg/exploits/ssm_sendcommand"
)

func TestSSMSendCommandModuleInit(t *testing.T) {
	mod := ssm_sendcommand.NewModule()

	if mod.Name() != "ssm-002" {
		t.Errorf("Expected name 'ssm-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ssm-002" {
		t.Errorf("Expected ID 'ssm-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestSSMSendCommandDescription(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestSSMSendCommandServices(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "ssm": true}
	for _, svc := range pathInfo.Services {
		if !expectedServices[svc] {
			t.Errorf("Unexpected service: %s", svc)
		}
		delete(expectedServices, svc)
	}
	for svc := range expectedServices {
		t.Errorf("Missing expected service: %s", svc)
	}
}

func TestSSMSendCommandOptions(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	options := mod.Options()

	requiredOptions := map[string]bool{}
	optionalOptions := map[string]bool{}

	for _, opt := range options {
		if opt.Required {
			requiredOptions[opt.Name] = true
		} else {
			optionalOptions[opt.Name] = true
		}
	}

	// INSTANCE_ID is the only required option.
	if !requiredOptions["INSTANCE_ID"] {
		t.Error("Expected INSTANCE_ID to be required")
	}

	// REGION should be optional with a default.
	if !optionalOptions["REGION"] {
		t.Error("Expected REGION to be optional")
	}

	// Verify REGION default.
	for _, opt := range options {
		if opt.Name == "REGION" && opt.Default != "us-east-1" {
			t.Errorf("Expected REGION default 'us-east-1', got '%s'", opt.Default)
		}
	}
}

func TestSSMSendCommandAliases(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	pathInfo := mod.PathInfo()

	expectedAliases := map[string]bool{
		"ssm-sendcommand":           true,
		"exploit/ssm_sendcommand":   true,
	}

	for _, alias := range pathInfo.Aliases {
		delete(expectedAliases, alias)
	}

	for alias := range expectedAliases {
		t.Errorf("Missing expected alias: %s", alias)
	}
}

func TestSSMSendCommandPermissions(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Permissions.Required) == 0 {
		t.Error("Expected at least one required permission")
	}

	// ssm:SendCommand must be in required permissions.
	found := false
	for _, perm := range pathInfo.Permissions.Required {
		if perm.Permission == "ssm:SendCommand" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'ssm:SendCommand' in required permissions")
	}
}

func TestSSMSendCommandMITRE(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	pathInfo := mod.PathInfo()

	if pathInfo.MITRE == nil {
		t.Fatal("Expected MITRE mapping to be non-nil")
	}

	if len(pathInfo.MITRE.Tactics) == 0 {
		t.Error("Expected at least one MITRE tactic")
	}

	if len(pathInfo.MITRE.Techniques) == 0 {
		t.Error("Expected at least one MITRE technique")
	}
}

func TestSSMSendCommandDiscoverableOptions(t *testing.T) {
	mod := ssm_sendcommand.NewModule()

	discoverable := mod.DiscoverableOptions()
	if len(discoverable) == 0 {
		t.Error("Expected at least one discoverable option")
	}

	found := false
	for _, opt := range discoverable {
		if opt == "INSTANCE_ID" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected INSTANCE_ID in discoverable options")
	}
}

func TestSSMSendCommandPrerequisites(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected at least one admin prerequisite")
	}

	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected at least one lateral prerequisite")
	}
}

func TestSSMSendCommandRelatedPaths(t *testing.T) {
	mod := ssm_sendcommand.NewModule()
	pathInfo := mod.PathInfo()

	found := false
	for _, related := range pathInfo.RelatedPaths {
		if related == "ssm-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'ssm-001' in related paths")
	}
}
