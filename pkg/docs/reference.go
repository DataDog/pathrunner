// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

// Package docs builds the machine-readable command/module/payload reference that
// backs the pathrunner documentation site (pathfinding.cloud/pathrunner).
//
// The reference is produced by introspecting the live Cobra command tree and the
// module/payload registries — never by scraping --help text — so every field is
// structured and the counts can never drift from the code. It is emitted by the
// standalone cmd/gendocs binary (not a shipped pathrunner command) so that all
// module/payload init() registrations have already fired.
package docs

// SchemaVersion is the version of the pathrunner-reference.json contract.
// Bump it whenever the shape consumed by pathfinding.cloud changes so the
// frontend can detect and handle incompatibilities.
//
// 1.1.0 — added Option.MockValue and Module.CLISteps.
const SchemaVersion = "1.1.0"

// Reference is the top-level artifact written to pathrunner-reference.json.
// It is the single file pathfinding.cloud pulls to render the /pathrunner site.
type Reference struct {
	Generator Generator `json:"generator"`
	Counts    Counts    `json:"counts"`
	Commands  []Command `json:"commands"`
	Modules   []Module  `json:"modules"`
	Payloads  []Payload `json:"payloads"`
}

// Generator records provenance for the artifact so the frontend (and humans)
// can tell which build produced it and which schema it conforms to.
type Generator struct {
	SchemaVersion     string `json:"schemaVersion"`
	PathrunnerVersion string `json:"pathrunnerVersion"`
	GitCommit         string `json:"gitCommit,omitempty"`
	GeneratedAt       string `json:"generatedAt"`
}

// Counts are registry-derived totals. These replace the previously hardcoded
// (and stale) numbers in the README so coverage figures stay accurate.
type Counts struct {
	Commands int `json:"commands"`
	Modules  int `json:"modules"`
	Payloads int `json:"payloads"`
	Services int `json:"services"`
}

// Command mirrors one node of the Cobra command tree (a command or subcommand).
type Command struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`            // full invocation path, e.g. "pathrunner attacker listener start"
	Group       string    `json:"group,omitempty"` // Cobra GroupID ("core" / "module"); empty for subcommands
	Short       string    `json:"short,omitempty"`
	Long        string    `json:"long,omitempty"`
	Usage       string    `json:"usage,omitempty"` // Cobra UseLine
	Aliases     []string  `json:"aliases,omitempty"`
	Flags       []Flag    `json:"flags,omitempty"`
	Subcommands []Command `json:"subcommands,omitempty"`
}

// Flag describes a single command-line flag.
type Flag struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Usage     string `json:"usage,omitempty"`
	Default   string `json:"default,omitempty"`
	Type      string `json:"type,omitempty"`
}

// Module is the documentation view of one exploit module, drawn from its
// PathInfo plus its runtime Options() and ListPayloads(). The ID is the
// cross-project {service}-{NNN} key used to deep-link to pathfinding.cloud
// paths and pathfinding-labs labs.
type Module struct {
	ID                  string        `json:"id"`
	Name                string        `json:"name"`
	Description         string        `json:"description,omitempty"`
	Category            string        `json:"category,omitempty"`
	Services            []string      `json:"services,omitempty"`
	PrimaryService      string        `json:"primaryService,omitempty"` // compute-service prefix of ID; used for sidebar grouping
	Aliases             []string      `json:"aliases,omitempty"`
	Author              string        `json:"author,omitempty"`
	PathfindingCloudURL string        `json:"pathfindingCloudUrl,omitempty"`
	Permissions         Permissions   `json:"permissions"`
	Prerequisites       Prerequisites `json:"prerequisites"`
	References          []Link        `json:"references,omitempty"`
	RelatedPaths        []string      `json:"relatedPaths,omitempty"`
	MITRE               *MITRE        `json:"mitre,omitempty"`
	Options             []Option      `json:"options,omitempty"`
	Payloads            []PayloadRef  `json:"payloads,omitempty"`
	// CLISteps is the ordered sequence of CLI commands to run this module
	// end-to-end, with placeholder mock values for required options. Rendered
	// as a copy-pastable code block by the frontend. Includes "pathrunner exploit"
	// as the final step. Also drives the VHS tape generator for module GIFs.
	CLISteps []string `json:"cliSteps,omitempty"`
}

// Permissions groups the IAM permissions a module requires.
type Permissions struct {
	Required   []Permission `json:"required,omitempty"`
	Additional []Permission `json:"additional,omitempty"`
}

// Permission is a single IAM action with optional resource/constraint notes.
type Permission struct {
	Permission  string `json:"permission"`
	Description string `json:"description,omitempty"`
}

// Prerequisites describes setup that must already exist for a path to work.
type Prerequisites struct {
	Admin   []string `json:"admin,omitempty"`
	Lateral []string `json:"lateral,omitempty"`
}

// Link is an external reference (blog post, documentation, etc.).
type Link struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// MITRE holds MITRE ATT&CK tactic and technique references.
type MITRE struct {
	Tactics    []string `json:"tactics,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
}

// Option is a module or payload configuration option.
type Option struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
	// MockValue is a realistic-looking placeholder used in documentation code
	// examples and VHS tape generation. Empty for options that are context-
	// dependent (e.g. PAYLOAD, which is selected separately in CLISteps).
	MockValue string `json:"mockValue,omitempty"`
}

// PayloadRef is a payload surfaced by a module (name + description only).
type PayloadRef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Payload is the documentation view of one entry in the payload registry.
type Payload struct {
	Name          string   `json:"name"`
	QualifiedName string   `json:"qualifiedName,omitempty"` // service:name composite key
	Service       string   `json:"service,omitempty"`
	Description   string   `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Options       []Option `json:"options,omitempty"`
}
