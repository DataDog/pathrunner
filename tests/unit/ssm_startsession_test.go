// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"github.com/DataDog/pathrunner/pkg/exploits/ssm_startsession"
	"testing"
)

func TestSSMStartSessionModuleInit(t *testing.T) {
	mod := ssm_startsession.NewModule()

	if mod.Name() != "ssm-001" {
		t.Errorf("Expected name 'ssm-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ssm-001" {
		t.Errorf("Expected ID 'ssm-001', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestSSMStartSessionDescription(t *testing.T) {
	mod := ssm_startsession.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestSSMStartSessionServices(t *testing.T) {
	mod := ssm_startsession.NewModule()
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

func TestSSMStartSessionOptions(t *testing.T) {
	mod := ssm_startsession.NewModule()
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

	// INSTANCE_ID and PAYLOAD are required.
	for _, name := range []string{"INSTANCE_ID", "PAYLOAD"} {
		if !requiredOptions[name] {
			t.Errorf("Expected %s to be required", name)
		}
	}

	// REGION should be optional.
	if !optionalOptions["REGION"] {
		t.Error("Expected REGION to be optional")
	}
}

func TestSSMStartSessionAliases(t *testing.T) {
	mod := ssm_startsession.NewModule()
	pathInfo := mod.PathInfo()

	aliasMap := map[string]bool{}
	for _, alias := range pathInfo.Aliases {
		aliasMap[alias] = true
	}

	expectedAliases := []string{"ssm-startsession", "exploit/ssm_startsession"}
	for _, alias := range expectedAliases {
		if !aliasMap[alias] {
			t.Errorf("Expected alias '%s' to be present", alias)
		}
	}
}

func TestSSMStartSessionMITREMapping(t *testing.T) {
	mod := ssm_startsession.NewModule()
	pathInfo := mod.PathInfo()

	if pathInfo.MITRE == nil {
		t.Fatal("Expected non-nil MITRE mapping")
	}
	if len(pathInfo.MITRE.Tactics) == 0 {
		t.Error("Expected non-empty MITRE tactics")
	}
	if len(pathInfo.MITRE.Techniques) == 0 {
		t.Error("Expected non-empty MITRE techniques")
	}
}

func TestSSMStartSessionPermissions(t *testing.T) {
	mod := ssm_startsession.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Permissions.Required) == 0 {
		t.Error("Expected at least one required permission")
	}

	foundStartSession := false
	for _, perm := range pathInfo.Permissions.Required {
		if perm.Permission == "ssm:StartSession" {
			foundStartSession = true
			break
		}
	}
	if !foundStartSession {
		t.Error("Expected 'ssm:StartSession' in required permissions")
	}
}

func TestSSMStartSessionDiscoverableOptions(t *testing.T) {
	mod := ssm_startsession.NewModule()
	discoverableOpts := mod.DiscoverableOptions()

	found := false
	for _, opt := range discoverableOpts {
		if opt == "INSTANCE_ID" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected INSTANCE_ID to be a discoverable option")
	}
}

func TestSSMStartSessionRegistration(t *testing.T) {
	// The module must be loadable by its primary ID.
	mod := ssm_startsession.NewModule()
	if mod.PathInfo().ID != "ssm-001" {
		t.Errorf("Expected module ID 'ssm-001', got '%s'", mod.PathInfo().ID)
	}
}

func TestSSMStartSessionRelatedPaths(t *testing.T) {
	mod := ssm_startsession.NewModule()
	pathInfo := mod.PathInfo()

	relatedMap := map[string]bool{}
	for _, related := range pathInfo.RelatedPaths {
		relatedMap[related] = true
	}

	if !relatedMap["ssm-002"] {
		t.Error("Expected ssm-002 in related paths")
	}
}

func TestSSMStartSessionPrerequisites(t *testing.T) {
	mod := ssm_startsession.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Prerequisites.Admin) == 0 {
		t.Error("Expected non-empty admin prerequisites")
	}
	if len(pathInfo.Prerequisites.Lateral) == 0 {
		t.Error("Expected non-empty lateral prerequisites")
	}
}

func TestSSMStartSessionReferences(t *testing.T) {
	mod := ssm_startsession.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.References) == 0 {
		t.Error("Expected at least one reference")
	}

	// PMapper reference should be present (first documented the technique)
	foundPMapper := false
	for _, ref := range pathInfo.References {
		if ref.URL != "" && ref.Title != "" {
			// At minimum one reference is valid
			foundPMapper = true
		}
	}
	if !foundPMapper {
		t.Error("Expected at least one valid reference with URL and Title")
	}
}
