package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/x/term"
)

// termWidth returns the current terminal width, defaulting to 80 if unavailable.
func termWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// Table renders a styled table to stdout.
// The table uses its natural width unless it would exceed the terminal,
// in which case it constrains to terminal width and wraps cell text.
func Table(headers []string, rows [][]string) {
	if !IsTTY() {
		plainTable(headers, rows)
		return
	}

	styleFunc := func(row, col int) lipgloss.Style {
		if row == table.HeaderRow {
			return lipgloss.NewStyle().Bold(true).Foreground(ColorWhite).Padding(0, 1)
		}
		return lipgloss.NewStyle().Padding(0, 1)
	}

	t := table.New().
		Headers(headers...).
		Rows(rows...).
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(ColorPrimary)).
		StyleFunc(styleFunc)

	rendered := t.String()
	firstLine := strings.SplitN(rendered, "\n", 2)[0]
	naturalWidth := lipgloss.Width(firstLine)

	w := termWidth()
	if naturalWidth > w {
		t = t.Width(w).Wrap(true)
	}

	fmt.Println(t)
}

// KeyValueTable renders a two-column "Property | Value" table.
func KeyValueTable(title string, pairs []KV) {
	if title != "" {
		fmt.Println(SectionStyle.Render(title))
	}

	rows := make([][]string, len(pairs))
	for i, kv := range pairs {
		rows[i] = []string{kv.Key, kv.Value}
	}

	Table([]string{"Property", "Value"}, rows)
}

// KV is a key-value pair for KeyValueTable.
type KV struct {
	Key   string
	Value string
}

// plainTable writes a simple tab-aligned table for non-TTY output.
func plainTable(headers []string, rows [][]string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	for i, h := range headers {
		if i > 0 {
			fmt.Fprint(os.Stdout, "  ")
		}
		fmt.Fprintf(os.Stdout, "%-*s", widths[i], h)
	}
	fmt.Fprintln(os.Stdout)

	// Print separator
	for i, w := range widths {
		if i > 0 {
			fmt.Fprint(os.Stdout, "  ")
		}
		for j := 0; j < w; j++ {
			fmt.Fprint(os.Stdout, "-")
		}
	}
	fmt.Fprintln(os.Stdout)

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Fprint(os.Stdout, "  ")
			}
			if i < len(widths) {
				fmt.Fprintf(os.Stdout, "%-*s", widths[i], cell)
			} else {
				fmt.Fprint(os.Stdout, cell)
			}
		}
		fmt.Fprintln(os.Stdout)
	}
}
