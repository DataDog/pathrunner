// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ui

import (
	"fmt"
	"strings"
)

// ContextPanel renders the context dashboard showing workspace, identity, module status.
func ContextPanel(workspace, identity, module, payload, status string) string {
	if !IsTTY() {
		return plainContext(workspace, identity, module, payload, status)
	}

	lines := []string{
		BoldCyan.Render("PATHRUNNER") + Muted.Render("  AWS Post-Exploitation"),
	}

	lines = append(lines, fmt.Sprintf("%s  %s", Muted.Render("Workspace:"), workspace))

	if identity != "" {
		lines = append(lines, fmt.Sprintf("%s   %s", Muted.Render("Identity:"), identity))
	} else {
		lines = append(lines, fmt.Sprintf("%s   %s", Muted.Render("Identity:"), Muted.Render("none")))
	}

	if module != "" {
		lines = append(lines, fmt.Sprintf("%s     %s", Muted.Render("Module:"), Accent.Render(module)))
	} else {
		lines = append(lines, fmt.Sprintf("%s     %s", Muted.Render("Module:"), Muted.Render("none")))
	}

	if payload != "" {
		lines = append(lines, fmt.Sprintf("%s    %s", Muted.Render("Payload:"), payload))
	}

	if status != "" {
		lines = append(lines, fmt.Sprintf("%s     %s", Muted.Render("Status:"), status))
	}

	content := strings.Join(lines, "\n")
	return BoxStyle.Render(content)
}

// plainContext renders context info without styling for non-TTY output.
func plainContext(workspace, identity, module, payload, status string) string {
	var lines []string
	lines = append(lines, "PATHRUNNER  AWS Post-Exploitation")
	lines = append(lines, fmt.Sprintf("Workspace:  %s", workspace))
	if identity != "" {
		lines = append(lines, fmt.Sprintf("Identity:   %s", identity))
	}
	if module != "" {
		lines = append(lines, fmt.Sprintf("Module:     %s", module))
	}
	if payload != "" {
		lines = append(lines, fmt.Sprintf("Payload:    %s", payload))
	}
	if status != "" {
		lines = append(lines, fmt.Sprintf("Status:     %s", status))
	}
	return strings.Join(lines, "\n")
}

// InfoCard renders a boxed info panel with a title.
func InfoCard(title string, lines []string) string {
	if !IsTTY() {
		result := title + "\n"
		for _, line := range lines {
			result += "  " + line + "\n"
		}
		return result
	}

	header := BoldCyan.Render(title)
	content := header + "\n" + strings.Join(lines, "\n")
	return BoxStyle.Render(content)
}

// Section prints a styled section heading.
func Section(title string) {
	if IsTTY() {
		fmt.Println(SectionStyle.Render(title))
	} else {
		fmt.Println(title)
		fmt.Println(strings.Repeat("-", len(title)))
	}
}

// StatusLine renders a single status line with an icon and message.
func StatusLine(icon, message string) string {
	return fmt.Sprintf("%s %s", icon, message)
}
