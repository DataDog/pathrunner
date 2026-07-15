package unit

import (
	"pathrunner/pkg/exploits/ec2_instanceconnect"
	"testing"
)

func TestEC2InstanceConnectModuleInit(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()

	if mod.Name() != "ec2-003" {
		t.Errorf("Expected name 'ec2-003', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if pathInfo.ID != "ec2-003" {
		t.Errorf("Expected ID 'ec2-003', got '%s'", pathInfo.ID)
	}
	if pathInfo.Category != "existing-passrole" {
		t.Errorf("Expected category 'existing-passrole', got '%s'", pathInfo.Category)
	}
}

func TestEC2InstanceConnectDescription(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
	desc := mod.Description()

	if desc == "" {
		t.Error("Expected non-empty description")
	}
}

func TestEC2InstanceConnectServices(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
	pathInfo := mod.PathInfo()

	expectedServices := map[string]bool{"iam": true, "ec2": true}
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

func TestEC2InstanceConnectOptions(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
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

	// These should be optional.
	expectedOptional := []string{"REGION", "EC2_USER", "TARGET_USER", "SSH_TIMEOUT"}
	for _, name := range expectedOptional {
		if !optionalOptions[name] {
			t.Errorf("Expected %s to be optional", name)
		}
	}
}

func TestEC2InstanceConnectAliases(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
	pathInfo := mod.PathInfo()

	aliasMap := map[string]bool{}
	for _, alias := range pathInfo.Aliases {
		aliasMap[alias] = true
	}

	expectedAliases := []string{"ec2-instanceconnect", "exploit/ec2_instanceconnect"}
	for _, alias := range expectedAliases {
		if !aliasMap[alias] {
			t.Errorf("Expected alias '%s' to be present", alias)
		}
	}
}

func TestEC2InstanceConnectMITREMapping(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
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

func TestEC2InstanceConnectPermissions(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
	pathInfo := mod.PathInfo()

	if len(pathInfo.Permissions.Required) == 0 {
		t.Error("Expected at least one required permission")
	}

	foundSendSSHPublicKey := false
	for _, perm := range pathInfo.Permissions.Required {
		if perm.Permission == "ec2-instance-connect:SendSSHPublicKey" {
			foundSendSSHPublicKey = true
			break
		}
	}
	if !foundSendSSHPublicKey {
		t.Error("Expected 'ec2-instance-connect:SendSSHPublicKey' in required permissions")
	}
}

func TestEC2InstanceConnectDiscoverableOptions(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
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

func TestEC2InstanceConnectEC2UserDefault(t *testing.T) {
	mod := ec2_instanceconnect.NewModule()
	options := mod.Options()

	for _, opt := range options {
		if opt.Name == "EC2_USER" {
			if opt.Default != "ec2-user" {
				t.Errorf("Expected EC2_USER default to be 'ec2-user', got '%s'", opt.Default)
			}
			return
		}
	}
	t.Error("Expected EC2_USER option to be present")
}

func TestEC2InstanceConnectRegistration(t *testing.T) {
	// The module must be loadable by its primary ID.
	mod := ec2_instanceconnect.NewModule()
	if mod.PathInfo().ID != "ec2-003" {
		t.Errorf("Expected module ID 'ec2-003', got '%s'", mod.PathInfo().ID)
	}
}
