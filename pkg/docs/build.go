// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package docs

import (
	"os"
	"sort"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"github.com/DataDog/pathrunner/pkg/version"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// preferredPayloads is the priority order for selecting a default payload in
// CLI examples. Payloads requiring fewer extra options are preferred so examples
// stay minimal. The first match found in a module's payload list wins.
var preferredPayloads = []string{
	"exfil/response",        // no extra required options
	"backdoor/attach-policy", // no extra required options
	"exfil/https",            // requires HTTPS_URL
	"revshell/tls",           // requires LISTENER_IP
}

// mockValueForOption returns a realistic-looking placeholder value for
// documentation examples. Returns "" for options handled specially elsewhere
// (PAYLOAD is chosen separately in buildCLISteps).
func mockValueForOption(name string) string {
	switch name {
	case "PAYLOAD":
		return "" // chosen separately per module in buildCLISteps
	case "ROLE_ARN", "EXECUTION_ROLE_ARN", "ADMIN_ROLE_ARN":
		return "arn:aws:iam::123456789012:role/TargetRoleName"
	case "SERVICE_ROLE":
		return "arn:aws:iam::123456789012:role/TargetServiceRole"
	case "TARGET_ARN":
		return "arn:aws:iam::123456789012:role/TargetRoleName"
	case "TARGET_ROLE":
		return "TargetRoleName"
	case "TRUST_PRINCIPAL":
		return "arn:aws:iam::123456789012:root"
	case "TARGET_USER":
		return "target-iam-user"
	case "POLICY_ARN":
		return "arn:aws:iam::123456789012:policy/TargetPolicy"
	case "GROUP_NAME":
		return "target-iam-group"
	case "EXECUTION_ROLE_NAME":
		return "TargetExecutionRoleName"
	case "INSTANCE_PROFILE":
		return "arn:aws:iam::123456789012:instance-profile/TargetInstanceProfile"
	case "INSTANCE_ID":
		return "i-0123456789abcdef0"
	case "LAUNCH_TEMPLATE_NAME":
		return "target-launch-template"
	case "ASG_NAME":
		return "target-auto-scaling-group"
	case "SUBNET_ID":
		return "subnet-0123456789abcdef0"
	case "SECURITY_GROUP_ID":
		return "sg-0123456789abcdef0"
	case "CLUSTER_NAME":
		return "target-ecs-cluster"
	case "CLUSTER_ARN":
		return "arn:aws:ecs::123456789012:cluster/target-ecs-cluster"
	case "CONTAINER_INSTANCE_ARN":
		return "arn:aws:ecs::123456789012:container-instance/target-ecs-cluster/abc1234567890"
	case "TASK_DEFINITION":
		return "target-task-def:1"
	case "CONTAINER_NAME":
		return "target-container"
	case "CONTAINER_URI":
		return "123456789012.dkr.ecr.us-east-1.amazonaws.com/target-image:latest"
	case "FUNCTION_NAME":
		return "target-lambda-function"
	case "JOB_NAME":
		return "target-glue-job"
	case "JOB_QUEUE":
		return "target-batch-job-queue"
	case "JOB_DEFINITION":
		return "target-job-definition:1"
	case "PROJECT_NAME":
		return "target-codebuild-project"
	case "STACK_NAME":
		return "target-cloudformation-stack"
	case "STACKSET_NAME":
		return "target-stackset"
	case "APP_NAME":
		return "target-app"
	case "DEPLOYMENT_GROUP":
		return "target-deployment-group"
	case "BUCKET", "EXFIL_BUCKET":
		return "target-s3-bucket-123456789012"
	case "TABLE_NAME":
		return "target-dynamodb-table"
	case "EVENT_SOURCE_ARN":
		return "arn:aws:dynamodb::123456789012:table/target-table/stream/2026-01-01T00:00:00.000"
	case "IDENTITY_POOL_ID":
		return "us-east-1:12345678-1234-1234-1234-123456789012"
	case "TARGET_RUNTIME_ARN":
		return "arn:aws:bedrock::123456789012:provisioned-model/target-model"
	case "INTERPRETER_ID":
		return "target-interpreter-id"
	case "BROWSER_ID":
		return "target-browser-id"
	case "LISTENER_IP":
		return "1.2.3.4"
	case "HTTPS_URL":
		return "https://1.2.3.4:8443/collect"
	}
	// Fallback: pattern-match on suffix.
	switch {
	case strings.HasSuffix(name, "_ARN"):
		return "arn:aws:iam::123456789012:resource/target-resource"
	case strings.HasSuffix(name, "_URL"):
		return "https://1.2.3.4:8443"
	case strings.HasSuffix(name, "_BUCKET"):
		return "target-bucket-123456789012"
	case strings.HasSuffix(name, "_ID"):
		return "target-resource-id"
	case strings.HasSuffix(name, "_NAME"):
		return "target-resource-name"
	}
	return ""
}

// buildCLISteps returns the ordered sequence of CLI commands to run a module
// end-to-end. It picks the simplest available payload (fewest extra required
// options) and emits "pathrunner set …" for each required option with a mock
// value. The final entry is always "pathrunner exploit".
func buildCLISteps(moduleID string, opts []Option, payloadRefs []PayloadRef, payloadIndex map[string]Payload) []string {
	var steps []string
	steps = append(steps, "pathrunner use "+moduleID)

	// Choose and announce the payload if the module has any.
	selectedPayload := ""
	if len(payloadRefs) > 0 {
		steps = append(steps, "pathrunner show payloads")
		// Pick the preferred payload from the priority list.
		for _, pref := range preferredPayloads {
			for _, ref := range payloadRefs {
				if ref.Name == pref {
					selectedPayload = pref
					break
				}
			}
			if selectedPayload != "" {
				break
			}
		}
		if selectedPayload == "" {
			selectedPayload = payloadRefs[0].Name
		}
		steps = append(steps, "pathrunner set PAYLOAD "+selectedPayload)
	}

	// Set required module options (PAYLOAD is handled above).
	for _, opt := range opts {
		if !opt.Required || opt.Name == "PAYLOAD" || opt.MockValue == "" {
			continue
		}
		steps = append(steps, "pathrunner set "+opt.Name+" "+opt.MockValue)
	}

	// Set required options for the selected payload.
	if selectedPayload != "" {
		if pl, ok := payloadIndex[selectedPayload]; ok {
			for _, opt := range pl.Options {
				if opt.Required && opt.MockValue != "" {
					steps = append(steps, "pathrunner set "+opt.Name+" "+opt.MockValue)
				}
			}
		}
	}

	steps = append(steps, "pathrunner exploit")
	return steps
}

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
	payloadsOut := buildPayloads()

	// Build a name-keyed index of payloads so buildModules can look up payload
	// options when constructing CLISteps. Keyed by short name ("exfil/response")
	// because that is what PayloadRef.Name and ListPayloads() return.
	payloadIndex := make(map[string]Payload, len(payloadsOut))
	for _, p := range payloadsOut {
		payloadIndex[p.Name] = p
	}

	modulesOut := buildModules(payloadIndex)

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
// a module is a plain struct literal and makes no AWS calls. payloadIndex is
// keyed by short payload name and is used to look up payload option mock values
// when building CLISteps.
func buildModules(payloadIndex map[string]Payload) []Module {
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
		// Group by the compute service, not Services[0]. Services[0] is almost
		// always "iam" on PassRole modules (iam:PassRole + ec2:RunInstances), which
		// would dump every PassRole module into the iam group. The module ID prefix
		// already encodes the compute service per the pathfinding.cloud convention
		// (iam:PassRole + lambda:CreateFunction -> lambda-001), so derive from that.
		// Pure-IAM modules (iam-001, ...) correctly stay in the iam group.
		m.PrimaryService = info.ID
		if dashIdx := strings.Index(info.ID, "-"); dashIdx != -1 {
			m.PrimaryService = info.ID[:dashIdx]
		}

		// Options and payloads come from a constructed instance (no AWS calls).
		if mod, err := modules.LoadModule(info.ID); err == nil && mod != nil {
			m.Options = convertOptions(mod.Options())
			for _, p := range mod.ListPayloads() {
				m.Payloads = append(m.Payloads, PayloadRef{Name: p.Name, Description: p.Description})
			}
			m.CLISteps = buildCLISteps(info.ID, m.Options, m.Payloads, payloadIndex)
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
		out = append(out, Option{
			Name:        o.Name,
			Description: o.Description,
			Required:    o.Required,
			Default:     o.Default,
			MockValue:   mockValueForOption(o.Name),
		})
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
