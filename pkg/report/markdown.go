// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package report

import (
	"fmt"
	"strings"
)

// RenderMarkdown produces a Markdown-formatted workspace report.
func RenderMarkdown(data ReportData) string {
	var b strings.Builder

	// YAML frontmatter for tools that parse it (Obsidian, Jekyll, etc.)
	b.WriteString("---\n")
	fmt.Fprintf(&b, "workspace: %q\n", data.WorkspaceName)
	fmt.Fprintf(&b, "generated: %q\n", data.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	if data.ModuleFilter != "" {
		fmt.Fprintf(&b, "module_filter: %q\n", data.ModuleFilter)
	}
	fmt.Fprintf(&b, "created_resources: %d\n", len(data.Created))
	fmt.Fprintf(&b, "modified_resources: %d\n", len(data.Modified))
	fmt.Fprintf(&b, "cloudtrail_events: %d\n", len(data.Events))
	b.WriteString("---\n\n")

	b.WriteString("# Pathrunner Workspace Report\n\n")

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	fmt.Fprintf(&b, "| Workspace | %s |\n", data.WorkspaceName)
	fmt.Fprintf(&b, "| Generated | %s |\n", data.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	if data.ModuleFilter != "" {
		fmt.Fprintf(&b, "| Module filter | %s |\n", data.ModuleFilter)
	}
	fmt.Fprintf(&b, "| Created resources | %d |\n", len(data.Created))
	fmt.Fprintf(&b, "| Modified resources | %d |\n", len(data.Modified))
	fmt.Fprintf(&b, "| CloudTrail events | %d |\n", len(data.Events))
	b.WriteString("\n")

	if len(data.Created) > 0 {
		b.WriteString("## Created Resources\n\n")
		b.WriteString("These resources were created during exploitation and must be **deleted** to clean up.\n\n")
		for _, res := range data.Created {
			fmt.Fprintf(&b, "### `%s` — %s\n\n", res.Type, res.Name)
			if res.ARN != "" {
				fmt.Fprintf(&b, "- **ARN:** `%s`\n", res.ARN)
			}
			if res.Region != "" {
				fmt.Fprintf(&b, "- **Region:** `%s`\n", res.Region)
			}
			if res.ModuleID != "" {
				fmt.Fprintf(&b, "- **Module:** %s\n", res.ModuleID)
			}
			fmt.Fprintf(&b, "- **Cleanup:** %s\n", res.CleanupMethod)
			if res.Created != "" {
				fmt.Fprintf(&b, "- **Created:** %s\n", res.Created)
			}
			if cmd := CleanupCommand(res); cmd != "" {
				b.WriteString("\n**Manual cleanup command:**\n\n```bash\n")
				b.WriteString(cmd)
				b.WriteString("\n```\n")
			}
			b.WriteString("\n")
		}
	}

	if len(data.Modified) > 0 {
		b.WriteString("## Modified Resources\n\n")
		b.WriteString("These existing resources were modified and must be **reverted** to clean up.\n\n")
		for _, res := range data.Modified {
			principalName := res.Metadata["principal_name"]
			principalType := res.Metadata["principal_type"]
			displayName := res.Name
			if principalName != "" {
				displayName = principalName + " (" + principalType + ")"
			}
			fmt.Fprintf(&b, "### `%s` — %s\n\n", res.Type, displayName)
			if policyArn := res.Metadata["policy_arn"]; policyArn != "" {
				fmt.Fprintf(&b, "- **Policy:** `%s`\n", policyArn)
			}
			if res.Region != "" {
				fmt.Fprintf(&b, "- **Region:** `%s`\n", res.Region)
			}
			if res.ModuleID != "" {
				fmt.Fprintf(&b, "- **Module:** %s\n", res.ModuleID)
			}
			fmt.Fprintf(&b, "- **Reversal:** %s\n", res.CleanupMethod)
			if cmd := CleanupCommand(res); cmd != "" {
				b.WriteString("\n**Manual cleanup command:**\n\n```bash\n")
				b.WriteString(cmd)
				b.WriteString("\n```\n")
			}
			b.WriteString("\n")
		}
	}

	if len(data.Events) > 0 {
		b.WriteString("## CloudTrail Events\n\n")
		b.WriteString("API calls recorded during exploitation for blue team detection reference.\n\n")
		b.WriteString("| Timestamp | Module | Service | Operation | Principal | Description |\n")
		b.WriteString("|-----------|--------|---------|-----------|-----------|-------------|\n")
		for _, ev := range data.Events {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				mdCell(ev.Timestamp),
				mdCell(ev.ModuleID),
				mdCell(ev.Service),
				mdCell(ev.Operation),
				mdCell(ev.Principal),
				mdCell(ev.Description),
			)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// mdCell escapes pipe characters so they don't break Markdown table rendering.
func mdCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
