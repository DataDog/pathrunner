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
