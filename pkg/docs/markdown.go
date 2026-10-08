// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package docs

import (
	"fmt"
	"strings"
)

// RenderCommandMarkdown renders a command (and its subcommands) as a
// cloudfox-style reference entry.
func RenderCommandMarkdown(c Command) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# `%s`\n\n", c.Path)
	if c.Short != "" {
		fmt.Fprintf(&b, "%s\n\n", c.Short)
	}
	if c.Long != "" && c.Long != c.Short {
		fmt.Fprintf(&b, "%s\n\n", c.Long)
	}
	if len(c.Aliases) > 0 {
		fmt.Fprintf(&b, "**Aliases:** %s\n\n", strings.Join(backtickAll(c.Aliases), ", "))
	}
	if c.Usage != "" {
		fmt.Fprintf(&b, "## Usage\n\n```\n%s\n```\n\n", c.Usage)
	}
	writeFlags(&b, c.Flags)
	if len(c.Subcommands) > 0 {
		b.WriteString("## Subcommands\n\n")
		for _, sub := range c.Subcommands {
			renderSubcommand(&b, sub, 3)
		}
	}
	return b.String()
}

// renderSubcommand renders a nested subcommand at the given heading level.
func renderSubcommand(b *strings.Builder, c Command, level int) {
	fmt.Fprintf(b, "%s `%s`\n\n", strings.Repeat("#", level), c.Path)
	if c.Short != "" {
		fmt.Fprintf(b, "%s\n\n", c.Short)
	}
	if c.Usage != "" {
		fmt.Fprintf(b, "```\n%s\n```\n\n", c.Usage)
	}
	writeFlags(b, c.Flags)
	for _, sub := range c.Subcommands {
		renderSubcommand(b, sub, level+1)
	}
}

// writeFlags renders a flags table if the command has any.
func writeFlags(b *strings.Builder, flags []Flag) {
	if len(flags) == 0 {
		return
	}
	b.WriteString("| Flag | Short | Type | Default | Description |\n")
	b.WriteString("|------|-------|------|---------|-------------|\n")
	for _, f := range flags {
		short := ""
		if f.Shorthand != "" {
			short = "`-" + f.Shorthand + "`"
		}
		fmt.Fprintf(b, "| `--%s` | %s | %s | %s | %s |\n",
			f.Name, short, cell(f.Type), code(f.Default), cell(f.Usage))
	}
	b.WriteString("\n")
}

// RenderModuleMarkdown renders an exploit module as a cloudfox-style entry:
// a metadata table followed by permissions, prerequisites, options, payloads,
// references, and MITRE mappings.
func RenderModuleMarkdown(m Module) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# `%s` — %s\n\n", m.ID, m.Name)

	b.WriteString("|  |  |\n|---|---|\n")
	fmt.Fprintf(&b, "| ID | `%s` |\n", m.ID)
	if m.Category != "" {
		fmt.Fprintf(&b, "| Category | %s |\n", cell(m.Category))
	}
	if len(m.Services) > 0 {
		fmt.Fprintf(&b, "| Services | %s |\n", strings.Join(m.Services, ", "))
	}
	if m.Author != "" {
		fmt.Fprintf(&b, "| Author | %s |\n", cell(m.Author))
	}
	if len(m.Aliases) > 0 {
		fmt.Fprintf(&b, "| Aliases | %s |\n", strings.Join(backtickAll(m.Aliases), ", "))
	}
	if m.PathfindingCloudURL != "" {
		fmt.Fprintf(&b, "| pathfinding.cloud | %s |\n", m.PathfindingCloudURL)
	}
	b.WriteString("\n")

	if m.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", m.Description)
	}

	writePermissions(&b, "Required permissions", m.Permissions.Required)
	writePermissions(&b, "Additional permissions", m.Permissions.Additional)

	if len(m.Prerequisites.Admin) > 0 || len(m.Prerequisites.Lateral) > 0 {
		b.WriteString("## Prerequisites\n\n")
		if len(m.Prerequisites.Admin) > 0 {
			fmt.Fprintf(&b, "**Admin:**\n%s\n", bulletList(m.Prerequisites.Admin))
		}
		if len(m.Prerequisites.Lateral) > 0 {
			fmt.Fprintf(&b, "**Lateral:**\n%s\n", bulletList(m.Prerequisites.Lateral))
		}
	}

	writeOptions(&b, m.Options)

	if len(m.Payloads) > 0 {
		b.WriteString("## Compatible payloads\n\n")
		for _, p := range m.Payloads {
			if p.Description != "" {
				fmt.Fprintf(&b, "- `%s` — %s\n", p.Name, p.Description)
			} else {
				fmt.Fprintf(&b, "- `%s`\n", p.Name)
			}
		}
		b.WriteString("\n")
	}

	if len(m.References) > 0 {
		b.WriteString("## References\n\n")
		for _, r := range m.References {
			fmt.Fprintf(&b, "- [%s](%s)\n", r.Title, r.URL)
		}
		b.WriteString("\n")
	}

	if m.MITRE != nil {
		b.WriteString("## MITRE ATT&CK\n\n")
		if len(m.MITRE.Tactics) > 0 {
			fmt.Fprintf(&b, "- **Tactics:** %s\n", strings.Join(m.MITRE.Tactics, ", "))
		}
		if len(m.MITRE.Techniques) > 0 {
			fmt.Fprintf(&b, "- **Techniques:** %s\n", strings.Join(m.MITRE.Techniques, ", "))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func writePermissions(b *strings.Builder, heading string, perms []Permission) {
	if len(perms) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", heading)
	for _, p := range perms {
		if p.Description != "" {
			fmt.Fprintf(b, "- `%s` — %s\n", p.Permission, p.Description)
		} else {
			fmt.Fprintf(b, "- `%s`\n", p.Permission)
		}
	}
	b.WriteString("\n")
}

func writeOptions(b *strings.Builder, opts []Option) {
	if len(opts) == 0 {
		return
	}
	b.WriteString("## Options\n\n")
	b.WriteString("| Name | Required | Default | Description |\n")
	b.WriteString("|------|----------|---------|-------------|\n")
	for _, o := range opts {
		required := "no"
		if o.Required {
			required = "yes"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", o.Name, required, code(o.Default), cell(o.Description))
	}
	b.WriteString("\n")
}

func bulletList(items []string) string {
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "- %s\n", it)
	}
	return b.String()
}

func backtickAll(items []string) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = "`" + it + "`"
	}
	return out
}

// cell escapes a value for use inside a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// code wraps a non-empty value in backticks for a table cell, or returns a dash.
func code(s string) string {
	if s == "" {
		return "—"
	}
	return "`" + cell(s) + "`"
}
