// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package docs

import (
	"strings"
	"testing"

	"github.com/DataDog/pathrunner/pkg/payloads"

	"github.com/spf13/cobra"
)

// newTestRoot builds a small synthetic Cobra tree that exercises the walker:
// a visible grouped command with a flag and a subcommand, a hidden alias
// command (must be skipped), and a "completion" command (must be skipped).
func newTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "pathrunner"}

	modulesCmd := &cobra.Command{Use: "modules", Short: "Manage modules", GroupID: "core"}
	modulesCmd.Flags().String("filter", "all", "filter expression")
	listCmd := &cobra.Command{Use: "list", Short: "List modules"}
	modulesCmd.AddCommand(listCmd)

	hidden := &cobra.Command{Use: "identities", Short: "alias", Hidden: true}
	completion := &cobra.Command{Use: "completion", Short: "gen completions"}

	root.AddCommand(modulesCmd, hidden, completion)
	return root
}

func TestBuildCommandsSkipsHiddenAndCompletion(t *testing.T) {
	cmds := buildCommands(newTestRoot())

	if len(cmds) != 1 {
		t.Fatalf("expected 1 visible command, got %d: %+v", len(cmds), cmds)
	}
	got := cmds[0]
	if got.Name != "modules" {
		t.Fatalf("expected 'modules', got %q", got.Name)
	}
	if got.Group != "core" {
		t.Errorf("expected group 'core', got %q", got.Group)
	}
	if got.Path != "pathrunner modules" {
		t.Errorf("expected path 'pathrunner modules', got %q", got.Path)
	}
	if len(got.Subcommands) != 1 || got.Subcommands[0].Name != "list" {
		t.Errorf("expected single subcommand 'list', got %+v", got.Subcommands)
	}
}

func TestBuildFlagsExtractsLocalFlagsAndSkipsHelp(t *testing.T) {
	cmd := &cobra.Command{Use: "demo"}
	cmd.Flags().StringP("output", "o", "out.json", "output file")
	cmd.InitDefaultHelpFlag() // adds the --help flag that must be excluded

	flags := buildFlags(cmd)
	if len(flags) != 1 {
		t.Fatalf("expected 1 flag (help excluded), got %d: %+v", len(flags), flags)
	}
	f := flags[0]
	if f.Name != "output" || f.Shorthand != "o" || f.Default != "out.json" || f.Type != "string" {
		t.Errorf("unexpected flag extracted: %+v", f)
	}
}

func TestServiceFromTags(t *testing.T) {
	if got := serviceFromTags([]string{"python", payloads.TagServiceLambda, "exfil"}); got != "lambda" {
		t.Errorf("expected 'lambda', got %q", got)
	}
	if got := serviceFromTags([]string{"python", "exfil"}); got != "" {
		t.Errorf("expected empty service for unknown tags, got %q", got)
	}
}

func TestCountServicesDeduplicates(t *testing.T) {
	mods := []Module{{Services: []string{"iam", "ec2"}}, {Services: []string{"ec2"}}}
	pls := []Payload{{Service: "lambda"}, {Service: "ec2"}, {Service: ""}}
	if got := countServices(mods, pls); got != 3 { // iam, ec2, lambda
		t.Errorf("expected 3 distinct services, got %d", got)
	}
}

func TestBuildReferenceOnEmptyRegistriesSetsGeneratorAndCounts(t *testing.T) {
	ref := BuildReference(newTestRoot())

	if ref.Generator.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema version %q, got %q", SchemaVersion, ref.Generator.SchemaVersion)
	}
	// GeneratedAt is intentionally empty unless PATHRUNNER_DOCS_DATE is set, so
	// the committed artifact stays byte-for-byte reproducible for the fail-stale
	// CI check. Verify the env override is honored when present.
	t.Setenv("PATHRUNNER_DOCS_DATE", "2026-01-02T00:00:00Z")
	if stamped := BuildReference(newTestRoot()); stamped.Generator.GeneratedAt != "2026-01-02T00:00:00Z" {
		t.Errorf("expected GeneratedAt from env, got %q", stamped.Generator.GeneratedAt)
	}
	if ref.Counts.Commands != len(ref.Commands) || ref.Counts.Commands != 1 {
		t.Errorf("expected command count 1 matching Commands slice, got count=%d len=%d",
			ref.Counts.Commands, len(ref.Commands))
	}
	// Registries are empty in this package's test (exploits not imported).
	if ref.Counts.Modules != 0 || ref.Counts.Payloads != 0 {
		t.Errorf("expected zero modules/payloads with empty registry, got %d/%d",
			ref.Counts.Modules, ref.Counts.Payloads)
	}
}

func TestRenderModuleMarkdownContainsSections(t *testing.T) {
	m := Module{
		ID:                  "lambda-001",
		Name:                "iam:PassRole + lambda:CreateFunction",
		Description:         "Create a Lambda with a passed role.",
		Category:            "new-passrole",
		Services:            []string{"iam", "lambda"},
		PathfindingCloudURL: "https://pathfinding.cloud/paths/lambda-001",
		Permissions: Permissions{
			Required: []Permission{{Permission: "iam:PassRole", Description: "on target role"}},
		},
		Options:  []Option{{Name: "ROLE_ARN", Required: true, Description: "role to pass"}},
		Payloads: []PayloadRef{{Name: "exfil/response", Description: "return creds"}},
	}

	md := RenderModuleMarkdown(m)
	for _, want := range []string{
		"# `lambda-001`",
		"## Required permissions",
		"`iam:PassRole`",
		"## Options",
		"`ROLE_ARN`",
		"## Compatible payloads",
		"pathfinding.cloud/paths/lambda-001",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("module markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestMockValueForOptionCoversKnownNames(t *testing.T) {
	cases := []struct {
		name      string
		wantEmpty bool
	}{
		{"ROLE_ARN", false},
		{"TARGET_ARN", false},
		{"LISTENER_IP", false},
		{"HTTPS_URL", false},
		{"INSTANCE_ID", false},
		{"PAYLOAD", true},  // handled specially in buildCLISteps
		{"REGION", true},   // has a default; not in the mock map (callers use default)
	}
	for _, tc := range cases {
		got := mockValueForOption(tc.name)
		if tc.wantEmpty && got != "" {
			t.Errorf("mockValueForOption(%q): expected empty, got %q", tc.name, got)
		}
		if !tc.wantEmpty && got == "" {
			t.Errorf("mockValueForOption(%q): expected non-empty mock value, got empty", tc.name)
		}
	}
}

func TestBuildCLIStepsNoPayloads(t *testing.T) {
	opts := []Option{
		{Name: "ROLE_ARN", Required: true, MockValue: "arn:aws:iam::123456789012:role/TargetRoleName"},
		{Name: "REGION", Required: false, Default: "us-east-1"},
	}
	steps := buildCLISteps("glue-001", opts, nil, nil)

	if steps[0] != "pathrunner use glue-001" {
		t.Errorf("first step should be 'use', got %q", steps[0])
	}
	if steps[len(steps)-1] != "pathrunner exploit" {
		t.Errorf("last step should be 'exploit', got %q", steps[len(steps)-1])
	}
	// show payloads should not appear with no payloads
	for _, s := range steps {
		if strings.Contains(s, "show payloads") {
			t.Errorf("unexpected 'show payloads' step with no payloads: %v", steps)
		}
	}
	// required option should appear
	found := false
	for _, s := range steps {
		if s == "pathrunner set ROLE_ARN arn:aws:iam::123456789012:role/TargetRoleName" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ROLE_ARN set step, steps: %v", steps)
	}
}

func TestBuildCLIStepsPicksPreferredPayload(t *testing.T) {
	payloads := []PayloadRef{
		{Name: "revshell/tls"},
		{Name: "exfil/response"},
		{Name: "exfil/https"},
	}
	steps := buildCLISteps("lambda-001", nil, payloads, nil)

	// Should pick exfil/response (first in preferred list).
	found := false
	for _, s := range steps {
		if s == "pathrunner set PAYLOAD exfil/response" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected exfil/response to be preferred payload, steps: %v", steps)
	}
}

func TestBuildCLIStepsIncludesPayloadOptions(t *testing.T) {
	payloadRefs := []PayloadRef{{Name: "exfil/https"}}
	index := map[string]Payload{
		"exfil/https": {
			Name: "exfil/https",
			Options: []Option{
				{Name: "HTTPS_URL", Required: true, MockValue: "https://1.2.3.4:8443/collect"},
			},
		},
	}
	steps := buildCLISteps("lambda-001", nil, payloadRefs, index)

	found := false
	for _, s := range steps {
		if s == "pathrunner set HTTPS_URL https://1.2.3.4:8443/collect" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HTTPS_URL payload option in steps: %v", steps)
	}
}

func TestRenderCommandMarkdownContainsUsageFlagsAndSubcommands(t *testing.T) {
	c := Command{
		Name:  "modules",
		Path:  "pathrunner modules",
		Short: "Manage modules",
		Usage: "pathrunner modules [flags]",
		Flags: []Flag{{Name: "filter", Shorthand: "f", Type: "string", Default: "all", Usage: "filter"}},
		Subcommands: []Command{
			{Name: "list", Path: "pathrunner modules list", Short: "List modules", Usage: "pathrunner modules list"},
		},
	}

	md := RenderCommandMarkdown(c)
	for _, want := range []string{
		"# `pathrunner modules`",
		"## Usage",
		"`--filter`",
		"## Subcommands",
		"`pathrunner modules list`",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("command markdown missing %q\n---\n%s", want, md)
		}
	}
}
