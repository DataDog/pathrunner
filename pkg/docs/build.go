// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package docs

import (
	"os"
	"sort"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"github.com/DataDog/pathrunner/pkg/version"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// generatedAtEnv optionally stamps the artifact with a build date. It is left
// UNSET in normal generation so pathrunner-reference.json is byte-for-byte
// reproducible for the same commit — which is what makes the CI fail-stale
// check (git diff on docs/reference) meaningful. Set it to stamp a release.
const generatedAtEnv = "PATHRUNNER_DOCS_DATE"

// serviceTagSet mirrors the service tags the payload registry recognizes
// (see extractServiceTag in pkg/payloads/registry.go). A payload whose tags
// contain none of these gets an empty Service and is grouped under "other"
// by the frontend — matching the registry's own behavior rather than guessing.
var serviceTagSet = map[string]struct{}{
	payloads.TagServiceLambda: {}, payloads.TagServiceEC2: {}, payloads.TagServiceECS: {},
	payloads.TagServiceAppRunner: {}, payloads.TagServiceBatch: {}, payloads.TagServiceCodeBuild: {},
	payloads.TagServiceGlue: {}, payloads.TagServiceSageMaker: {}, payloads.TagServiceCloudFormation: {},
	payloads.TagServiceSSM: {}, payloads.TagServiceSSMAutomation: {}, payloads.TagServiceBedrock: {},
	payloads.TagServiceBraket: {}, payloads.TagServiceImageBuilder: {}, payloads.TagServiceEMR: {},
	payloads.TagServiceGameLift: {}, payloads.TagServiceKinesisAnalytics: {},
}

// BuildReference assembles the full documentation Reference by introspecting the
// provided Cobra command tree and the global module/payload registries. The
// caller is responsible for ensuring every module/payload package has been
// imported (so their init() registrations have fired) before calling this —
// cmd/gendocs does so via the same blank imports as cmd/pathrunner.
func BuildReference(root *cobra.Command) Reference {
	commands := buildCommands(root)
	modulesOut := buildModules()
	payloadsOut := buildPayloads()

	return Reference{
		Generator: Generator{
			SchemaVersion:     SchemaVersion,
			PathrunnerVersion: version.Version,
			GitCommit:         version.GitCommit,
			GeneratedAt:       os.Getenv(generatedAtEnv),
		},
		Counts: Counts{
			Commands: len(commands),
			Modules:  len(modulesOut),
			Payloads: len(payloadsOut),
			Services: countServices(modulesOut, payloadsOut),
		},
		Commands: commands,
		Modules:  modulesOut,
		Payloads: payloadsOut,
	}
}

// buildCommands returns the visible top-level commands of root, each with its
// subcommand tree. Hidden commands (the plural aliases) and Cobra's built-in
// help/completion commands are omitted.
func buildCommands(root *cobra.Command) []Command {
	var out []Command
	for _, child := range root.Commands() {
		if skipCommand(child) {
			continue
		}
		out = append(out, buildCommand(child))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// skipCommand reports whether a command should be excluded from the reference.
func skipCommand(cmd *cobra.Command) bool {
	if cmd.Hidden {
		return true
	}
	switch cmd.Name() {
	case "help", "completion":
		return true
	}
	return false
}

// buildCommand converts one Cobra command (and its subcommands, recursively)
// into a documentation Command.
func buildCommand(cmd *cobra.Command) Command {
	c := Command{
		Name:    cmd.Name(),
		Path:    cmd.CommandPath(),
		Group:   cmd.GroupID,
		Short:   cmd.Short,
		Long:    cmd.Long,
		Usage:   cmd.UseLine(),
		Aliases: cmd.Aliases,
		Flags:   buildFlags(cmd),
	}
	for _, child := range cmd.Commands() {
		if skipCommand(child) {
			continue
		}
		c.Subcommands = append(c.Subcommands, buildCommand(child))
	}
	sort.Slice(c.Subcommands, func(i, j int) bool { return c.Subcommands[i].Name < c.Subcommands[j].Name })
	return c
}

// buildFlags extracts a command's local flags, skipping the auto-added help flag.
func buildFlags(cmd *cobra.Command) []Flag {
	var flags []Flag
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		flags = append(flags, Flag{
			Name:      f.Name,
			Shorthand: f.Shorthand,
			Usage:     f.Usage,
			Default:   f.DefValue,
			Type:      f.Value.Type(),
		})
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	return flags
}

// buildModules converts every registered exploit module into a documentation
// Module, pulling static metadata from PathInfo and runtime metadata (options,
// compatible payloads) from a freshly-constructed module instance. Constructing
// a module is a plain struct literal and makes no AWS calls.
func buildModules() []Module {
	infos := modules.ListPathInfos()
	out := make([]Module, 0, len(infos))
	for _, info := range infos {
		m := Module{
			ID:                  info.ID,
			Name:                info.Name,
			Description:         info.Description,
			Category:            info.Category,
			Services:            info.Services,
			Aliases:             info.Aliases,
			Author:              info.Author,
			PathfindingCloudURL: info.PathfindingCloudURL(),
			Permissions:         convertPermissions(info.Permissions),
			Prerequisites:       Prerequisites{Admin: info.Prerequisites.Admin, Lateral: info.Prerequisites.Lateral},
			References:          convertReferences(info.References),
			RelatedPaths:        info.RelatedPaths,
			MITRE:               convertMITRE(info.MITRE),
		}
		if len(info.Services) > 0 {
			m.PrimaryService = info.Services[0]
		}

		// Options and payloads come from a constructed instance (no AWS calls).
		if mod, err := modules.LoadModule(info.ID); err == nil && mod != nil {
			m.Options = convertOptions(mod.Options())
			for _, p := range mod.ListPayloads() {
				m.Payloads = append(m.Payloads, PayloadRef{Name: p.Name, Description: p.Description})
			}
		}
		out = append(out, m)
	}
	return out
}

// buildPayloads converts every registered payload into a documentation Payload.
func buildPayloads() []Payload {
	all := payloads.ListAllPayloads()
	out := make([]Payload, 0, len(all))
	for _, p := range all {
		tags := p.GetTags()
		service := serviceFromTags(tags)
		pd := Payload{
			Name:        p.GetName(),
			Service:     service,
			Description: p.GetDescription(),
			Tags:        tags,
			Options:     convertOptions(p.GetOptions()),
		}
		if service != "" {
			pd.QualifiedName = payloads.QualifiedName(service, p.GetName())
		}
		out = append(out, pd)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// serviceFromTags returns the service tag present in a payload's tags, or "".
func serviceFromTags(tags []string) string {
	for _, t := range tags {
		if _, ok := serviceTagSet[t]; ok {
			return t
		}
	}
	return ""
}

func convertPermissions(p modules.PermissionSet) Permissions {
	return Permissions{
		Required:   convertPermissionList(p.Required),
		Additional: convertPermissionList(p.Additional),
	}
}

func convertPermissionList(in []modules.Permission) []Permission {
	if len(in) == 0 {
		return nil
	}
	out := make([]Permission, 0, len(in))
	for _, p := range in {
		out = append(out, Permission{Permission: p.Permission, Description: p.Description})
	}
	return out
}

func convertReferences(in []modules.Reference) []Link {
	if len(in) == 0 {
		return nil
	}
	out := make([]Link, 0, len(in))
	for _, r := range in {
		out = append(out, Link{Title: r.Title, URL: r.URL})
	}
	return out
}

func convertMITRE(in *modules.MITREMapping) *MITRE {
	if in == nil {
		return nil
	}
	return &MITRE{Tactics: in.Tactics, Techniques: in.Techniques}
}

func convertOptions(in []modules.Option) []Option {
	if len(in) == 0 {
		return nil
	}
	out := make([]Option, 0, len(in))
	for _, o := range in {
		out = append(out, Option{Name: o.Name, Description: o.Description, Required: o.Required, Default: o.Default})
	}
	return out
}

// countServices returns the number of distinct AWS services referenced across
// all modules and payloads.
func countServices(mods []Module, pls []Payload) int {
	seen := map[string]struct{}{}
	for _, m := range mods {
		for _, s := range m.Services {
			if s != "" {
				seen[s] = struct{}{}
			}
		}
	}
	for _, p := range pls {
		if p.Service != "" {
			seen[p.Service] = struct{}{}
		}
	}
	return len(seen)
}
