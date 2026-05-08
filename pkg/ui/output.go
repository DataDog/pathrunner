package ui

import (
	"fmt"
	"strings"

	"pathrunner/pkg/version"

	"charm.land/lipgloss/v2"
	"github.com/lucasb-eyer/go-colorful"
)

// Prompt builds the contextual REPL prompt string with lipgloss styling.
// Falls back to plain text when not a TTY.
func Prompt(workspace, identity, module string, expired, admin bool) string {
	if !IsTTY() {
		return plainPrompt(workspace, identity, module, expired, admin)
	}

	cyanStyle := Primary
	brightStyle := Accent

	var parts []string

	parts = append(parts, cyanStyle.Render("["+workspace+"]"))

	if identity != "" {
		suffix := ""
		if expired {
			suffix = "*"
		}
		if admin {
			suffix += "!"
		}
		parts = append(parts, cyanStyle.Render("["+identity+suffix+"]"))
	}

	if module != "" {
		// Extract last part after slash
		moduleParts := strings.Split(module, "/")
		shortName := moduleParts[len(moduleParts)-1]
		parts = append(parts, brightStyle.Render("["+shortName+"]"))
	}

	return strings.Join(parts, " ") + cyanStyle.Render(" > ")
}

// plainPrompt builds an unstyled prompt for piped/non-TTY contexts.
func plainPrompt(workspace, identity, module string, expired, admin bool) string {
	var parts []string
	parts = append(parts, "["+workspace+"]")

	if identity != "" {
		suffix := ""
		if expired {
			suffix = "*"
		}
		if admin {
			suffix += "!"
		}
		parts = append(parts, "["+identity+suffix+"]")
	}

	if module != "" {
		moduleParts := strings.Split(module, "/")
		shortName := moduleParts[len(moduleParts)-1]
		parts = append(parts, "["+shortName+"]")
	}

	return strings.Join(parts, " ") + " > "
}

// ClearScreen clears the terminal.
func ClearScreen() {
	fmt.Print("\033[2J\033[H")
}

// StartupBanner prints the integrated startup banner with context info.
func StartupBanner(workspace, identity, module, payload, status string) {
	if !IsTTY() {
		fmt.Println("Pathrunner AWS Post-Exploitation Framework")
		fmt.Printf("Version %s | By Seth Art at Datadog\n", version.Full())
		fmt.Printf("Workspace: %s\n", workspace)
		if identity != "" {
			fmt.Printf("Identity: %s\n", identity)
		}
		if module != "" {
			fmt.Printf("Module: %s\n", module)
		}
		fmt.Println("Type 'help' for available commands")
		return
	}

	cyan, _ := colorful.Hex("#00BFFF")
	green, _ := colorful.Hex("#00FF87")

	bright := lipgloss.NewStyle().Foreground(ColorBright)

	title := GradientText("PATHRUNNER", cyan, green, true) +
		Muted.Render("  "+version.Full())

	var lines []string
	lines = append(lines, title)
	lines = append(lines, Muted.Render("AWS Post-Exploitation Framework"))
	lines = append(lines, Muted.Render("By ")+bright.Render("Seth Art")+Muted.Render(" at ")+Accent.Render("Datadog"))
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("%s  %s", Muted.Render("Workspace:"), workspace))
	if identity != "" {
		lines = append(lines, fmt.Sprintf("%s   %s", Muted.Render("Identity:"), identity))
	}
	if module != "" {
		lines = append(lines, fmt.Sprintf("%s     %s", Muted.Render("Module:"), Accent.Render(module)))
	}
	if payload != "" {
		lines = append(lines, fmt.Sprintf("%s    %s", Muted.Render("Payload:"), payload))
	}
	if status != "" {
		lines = append(lines, fmt.Sprintf("%s     %s", Muted.Render("Status:"), status))
	}
	lines = append(lines, Muted.Render("Type 'help' for available commands"))

	fmt.Println(BoxStyle.Render(strings.Join(lines, "\n")))
	fmt.Println()
}

// Report renders a styled report header/footer for cleanup reports.
func ReportHeader(workspace, timestamp string, total, created, modified int) {
	if !IsTTY() {
		fmt.Println("===============================================================")
		fmt.Println("  PATHRUNNER CLEANUP REPORT")
		fmt.Println("===============================================================")
		fmt.Println()
		fmt.Printf("  Workspace:  %s\n", workspace)
		fmt.Printf("  Generated:  %s\n", timestamp)
		fmt.Printf("  Resources:  %d total (%d created, %d modified)\n", total, created, modified)
		fmt.Println()
		return
	}

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorWhite).
		Background(ColorPrimary).
		Padding(0, 2)

	fmt.Println(headerStyle.Render("PATHRUNNER CLEANUP REPORT"))
	fmt.Println()
	fmt.Printf("  %s  %s\n", Muted.Render("Workspace:"), workspace)
	fmt.Printf("  %s  %s\n", Muted.Render("Generated:"), timestamp)
	fmt.Printf("  %s  %s\n", Muted.Render("Resources:"),
		fmt.Sprintf("%d total (%d created, %d modified)", total, created, modified))
	fmt.Println()
}

// ReportSection renders a section heading in the cleanup report.
func ReportSection(title string) {
	if !IsTTY() {
		fmt.Printf("  %s\n", title)
		fmt.Println("  ---------------------------------------------------------")
		return
	}

	fmt.Println("  " + BoldCyan.Render(title))
	divider := Muted.Render("  " + strings.Repeat("─", 57))
	fmt.Println(divider)
}

// ReportFooter renders the report footer.
func ReportFooter() {
	if !IsTTY() {
		fmt.Println()
		fmt.Println("  Or run in pathrunner with an admin identity:")
		fmt.Println("    identity add --profile <admin-profile>")
		fmt.Println("    workspace cleanup --all")
		fmt.Println()
		fmt.Println("===============================================================")
		return
	}

	fmt.Println()
	fmt.Println("  " + Muted.Render("Or run in pathrunner with an admin identity:"))
	fmt.Println("    " + Primary.Render("identity add --profile <admin-profile>"))
	fmt.Println("    " + Primary.Render("workspace cleanup --all"))
	fmt.Println()
}
