// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"github.com/DataDog/pathrunner/pkg/modules"
	"strings"
	"testing"

	// Import modules and payloads to register them
	_ "github.com/DataDog/pathrunner/pkg/exploits/ec2_passrole"
	_ "github.com/DataDog/pathrunner/pkg/exploits/ec2_passrole_requestspotinstances"
	_ "github.com/DataDog/pathrunner/pkg/exploits/lambda_passrole"
	_ "github.com/DataDog/pathrunner/pkg/exploits/lambda_passrole_esm"
	_ "github.com/DataDog/pathrunner/pkg/exploits/sts_assume_role"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"
	_ "github.com/DataDog/pathrunner/pkg/payloads/lambda"
)

func TestDiscoverOptionalOptionsSkippedInWizardEc2004(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-004")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Set the required option so the wizard has nothing live to do; SUBNET_ID
	// stays unset and must be skipped (non-interactive) rather than prompted,
	// leaving it blank so the spot request uses the default VPC subnet.
	err = r.ExecuteCommand("set INSTANCE_PROFILE pl-prod-ec2-004-to-admin-instance-profile")
	if err != nil {
		t.Fatalf("Failed to set option: %v", err)
	}

	err = r.ExecuteCommand("discover")
	if err != nil {
		t.Fatalf("Expected no error from discover wizard, got: %v", err)
	}

	if r.GetOptions()["SUBNET_ID"] != "" {
		t.Errorf("Expected SUBNET_ID to remain blank, got %q", r.GetOptions()["SUBNET_ID"])
	}
}

func TestDiscoverNoModule(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("discover")
	if err == nil {
		t.Error("Expected error when no module selected")
	}
	if !strings.Contains(err.Error(), "no module selected") {
		t.Errorf("Expected 'no module selected' error, got: %v", err)
	}
}

func TestDiscoverNoIdentity(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	err = r.ExecuteCommand("discover")
	if err == nil {
		t.Error("Expected error when no identity configured")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("Expected identity-related error, got: %v", err)
	}
}

func TestDiscoverHelp(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// discover help should work via help command
	err := r.ExecuteCommand("help discover")
	if err != nil {
		t.Errorf("Expected no error from help discover, got: %v", err)
	}
}

func TestDiscoverHelpSubcommand(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// discover help should work even without module or identity
	// because help check is first in the handler
	err := r.ExecuteCommand("discover help")
	if err != nil {
		t.Errorf("Expected no error from discover help, got: %v", err)
	}
}

func TestDiscoverSTS001InvalidOption(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use sts-001")
	if err != nil {
		t.Fatalf("Failed to use sts-001: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// SESSION_NAME is not discoverable on sts-001
	err = r.ExecuteCommand("discover SESSION_NAME")
	if err == nil {
		t.Error("Expected error for non-discoverable option SESSION_NAME")
	}
}

func TestDiscoverInvalidOption(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	err = r.ExecuteCommand("discover FUNCTION_NAME")
	if err == nil {
		t.Error("Expected error for non-discoverable option FUNCTION_NAME")
	}
	if !strings.Contains(err.Error(), "does not support auto-discovery") {
		t.Errorf("Expected 'does not support auto-discovery' error, got: %v", err)
	}
}

func TestShowOptionsDiscoveryIndicator(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Use a discoverable module
	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	// show options should work without error (verifies the [auto] annotation path doesn't break)
	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options, got: %v", err)
	}
}

func TestShowOptionsSTS001Discoverable(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// sts-001 now implements Discoverable
	err := r.ExecuteCommand("use sts-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	// show options should work without error and display [auto] marker for ROLE_ARN
	err = r.ExecuteCommand("show options")
	if err != nil {
		t.Errorf("Expected no error from show options, got: %v", err)
	}
}

func TestDiscoverCommandRegistered(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	// Verify discover is recognized as a command (not "command not found")
	// Without a module, it should fail validation, not fail as unknown command
	err := r.ExecuteCommand("discover")
	if err == nil {
		t.Fatal("Expected error from discover without module")
	}
	if strings.Contains(err.Error(), "unknown command") || strings.Contains(err.Error(), "not found") {
		t.Error("discover should be a recognized command, but got 'command not found'")
	}
}

func TestDiscoverEc2InvalidOption(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Try to discover an invalid option
	err = r.ExecuteCommand("discover AMI_ID")
	if err == nil {
		t.Error("Expected error for non-discoverable AMI_ID option")
	}
}

func TestDiscoverEc2ExtendedOptions(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Verify that INSTANCE_TYPE is not discoverable (only INSTANCE_PROFILE, SUBNET_ID, SECURITY_GROUP_ID are)
	err = r.ExecuteCommand("discover INSTANCE_TYPE")
	if err == nil {
		t.Error("Expected error for non-discoverable INSTANCE_TYPE option")
	}
}

func TestDiscoverLambda002InvalidOption(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-002")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	err = r.ExecuteCommand("discover FUNCTION_NAME")
	if err == nil {
		t.Error("Expected error for non-discoverable FUNCTION_NAME option on lambda-002")
	}
}

func TestDiscoverSkipsAlreadySet(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use lambda-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Set the discoverable option manually
	err = r.ExecuteCommand("set ROLE_ARN arn:aws:iam::123456789012:role/MyRole")
	if err != nil {
		t.Fatalf("Failed to set option: %v", err)
	}

	// discover should skip already-set options (prints message, no error)
	err = r.ExecuteCommand("discover")
	if err != nil {
		t.Errorf("Expected no error when all discoverable options already set, got: %v", err)
	}
}

func TestDiscoverOptionalOptionsSkippedInWizard(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Set the required option so discovery has nothing live to do for it.
	// SUBNET_ID and SECURITY_GROUP_ID stay unset: in the test environment
	// (non-interactive stdin) the wizard must skip them instead of prompting,
	// leaving them blank so the exploit uses EC2's defaults.
	err = r.ExecuteCommand("set INSTANCE_PROFILE pl-prod-ec2-001-to-admin-instance-profile")
	if err != nil {
		t.Fatalf("Failed to set option: %v", err)
	}

	err = r.ExecuteCommand("discover")
	if err != nil {
		t.Fatalf("Expected no error from discover wizard, got: %v", err)
	}

	// Optional networking options must remain untouched (blank = default
	// VPC subnet / default security group at exploit time).
	if r.GetOptions()["SUBNET_ID"] != "" {
		t.Errorf("Expected SUBNET_ID to remain blank, got %q", r.GetOptions()["SUBNET_ID"])
	}
	if r.GetOptions()["SECURITY_GROUP_ID"] != "" {
		t.Errorf("Expected SECURITY_GROUP_ID to remain blank, got %q", r.GetOptions()["SECURITY_GROUP_ID"])
	}
}

func TestDiscoverAllCommand(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	// Pre-set every discoverable option so 'discover all' skips them all
	// (avoiding live AWS calls with test credentials).
	for _, opt := range []string{"INSTANCE_PROFILE", "SUBNET_ID", "SECURITY_GROUP_ID"} {
		if err := r.ExecuteCommand("set " + opt + " value-" + opt); err != nil {
			t.Fatalf("Failed to set %s: %v", opt, err)
		}
	}

	// 'discover all' should run without error and skip everything
	err = r.ExecuteCommand("discover all")
	if err != nil {
		t.Errorf("Expected no error from discover all, got: %v", err)
	}
}

func TestDiscoverAllCaseInsensitive(t *testing.T) {
	r, _, im, cleanup := setupTest(t)
	defer cleanup()

	err := r.ExecuteCommand("use ec2-001")
	if err != nil {
		t.Fatalf("Failed to use module: %v", err)
	}

	identity := &modules.Identity{
		Name:        "test",
		Type:        "keys",
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:      "us-east-1",
	}
	im.SetCurrent(identity)

	for _, opt := range []string{"INSTANCE_PROFILE", "SUBNET_ID", "SECURITY_GROUP_ID"} {
		if err := r.ExecuteCommand("set " + opt + " value-" + opt); err != nil {
			t.Fatalf("Failed to set %s: %v", opt, err)
		}
	}

	// Uppercase variant must also be treated as the 'all' keyword
	err = r.ExecuteCommand("discover ALL")
	if err != nil {
		t.Errorf("Expected no error from discover ALL, got: %v", err)
	}
}
