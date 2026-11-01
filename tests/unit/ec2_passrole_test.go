// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	ec2_passrole "github.com/DataDog/pathrunner/pkg/exploits/ec2_passrole"
	"github.com/DataDog/pathrunner/pkg/modules"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"
	"testing"
)

func TestEc2PassroleModuleInit(t *testing.T) {
	mod := ec2_passrole.NewModule()

	if mod.Name() != "ec2-001" {
		t.Errorf("Expected name 'ec2-001', got '%s'", mod.Name())
	}

	pathInfo := mod.PathInfo()
	if len(pathInfo.Aliases) == 0 {
		t.Error("Expected at least one alias")
	}
}

func TestEc2PassroleDiscoverableOptions(t *testing.T) {
	mod := ec2_passrole.NewModule()

	discoverable, ok := any(mod).(modules.Discoverable)
	if !ok {
		t.Fatal("Expected module to implement Discoverable interface")
	}

	options := discoverable.DiscoverableOptions()
	optionSet := map[string]bool{}
	for _, opt := range options {
		optionSet[opt] = true
	}

	for _, expected := range []string{"INSTANCE_PROFILE", "SUBNET_ID", "SECURITY_GROUP_ID"} {
		if !optionSet[expected] {
			t.Errorf("Expected %s in discoverable options", expected)
		}
	}
}

func TestEc2PassroleNetworkingOptionsAreOptional(t *testing.T) {
	mod := ec2_passrole.NewModule()

	// The discover wizard auto-discovers required options but prompts y/N
	// for optional ones. SUBNET_ID and SECURITY_GROUP_ID must stay optional
	// so the wizard defaults to leaving them blank (EC2 then uses the default
	// VPC subnet and default security group).
	for _, opt := range mod.Options() {
		if opt.Name == "SUBNET_ID" || opt.Name == "SECURITY_GROUP_ID" {
			if opt.Required {
				t.Errorf("Expected %s to be optional", opt.Name)
			}
			if opt.Default != "" {
				t.Errorf("Expected %s default to be empty", opt.Name)
			}
		}
	}
}
