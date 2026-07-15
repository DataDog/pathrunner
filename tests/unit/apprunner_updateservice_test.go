package unit

import (
	"pathrunner/pkg/exploits/apprunner_updateservice"
	_ "pathrunner/pkg/payloads/apprunner"
	"testing"
)

func TestAppRunnerUpdateServiceModuleInit(t *testing.T) {
	mod := apprunner_updateservice.NewModule()

	if mod.Name() != "apprunner-002" {
		t.Errorf("Expected name 'apprunner-002', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "apprunner-002" {
		t.Errorf("Expected ID 'apprunner-002', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestAppRunnerUpdateServiceDescription(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestAppRunnerUpdateServiceServices(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "apprunner": true}
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

func TestAppRunnerUpdateServiceOptions(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
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

	// SERVICE_ARN and PAYLOAD are required
	if !requiredOptions["SERVICE_ARN"] {
		t.Error("Expected SERVICE_ARN to be required")
	}
	if !requiredOptions["PAYLOAD"] {
		t.Error("Expected PAYLOAD to be required")
	}

	// These should be optional
	expectedOptional := []string{"REGION", "TARGET_ARN", "CONTAINER_IMAGE", "CLEANUP"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestAppRunnerUpdateServiceAliases(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
	pathInfo := mod.PathInfo()

	aliasMap := map[string]bool{}
	for _, alias := range pathInfo.Aliases {
		aliasMap[alias] = true
	}

	expectedAliases := []string{"apprunner-updateservice", "exploit/apprunner_updateservice"}
	for _, alias := range expectedAliases {
		if !aliasMap[alias] {
			t.Errorf("Expected alias '%s' to be present", alias)
		}
	}
}

func TestAppRunnerUpdateServiceCleanupDefault(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "CLEANUP" {
			if opt.Default != "false" {
				t.Errorf("Expected CLEANUP default to be 'false', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("Expected CLEANUP option to be present")
}

func TestAppRunnerUpdateServiceDiscoverableOptions(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
	discoverableOpts := mod.DiscoverableOptions()

	found := false
	for _, opt := range discoverableOpts {
		if opt == "SERVICE_ARN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected SERVICE_ARN to be a discoverable option")
	}
}

func TestAppRunnerUpdateServicePayloadCompatible(t *testing.T) {
	mod := apprunner_updateservice.NewModule()

	tags := mod.GetCompatibleTags()
	if len(tags) == 0 {
		t.Error("Expected non-empty compatible tags")
	}

	foundAppRunner := false
	for _, tag := range tags {
		if tag == "apprunner" {
			foundAppRunner = true
			break
		}
	}
	if !foundAppRunner {
		t.Error("Expected 'apprunner' service tag in compatible tags")
	}
}

func TestAppRunnerUpdateServiceMITREMapping(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
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

func TestAppRunnerUpdateServicePermissions(t *testing.T) {
	mod := apprunner_updateservice.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Permissions.Required) == 0 {
		t.Error("Expected at least one required permission")
	}

	foundUpdateService := false
	for _, perm := range pathInfo.Permissions.Required {
		if perm.Permission == "apprunner:UpdateService" {
			foundUpdateService = true
			break
		}
	}
	if !foundUpdateService {
		t.Error("Expected 'apprunner:UpdateService' in required permissions")
	}
}
