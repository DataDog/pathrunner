package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss/v2"
)

// PathViewStep represents one hop in an escalation chain for display.
type PathViewStep struct {
	Source, Destination     string // full ARNs
	SourceShort, DestShort string // short ARNs
	ModuleID               string // or ""
	Commands               []string
	Reason                 string
}

// PathViewRow represents one reachable target for display in the TUI.
type PathViewRow struct {
	Identity    string // populated in --all mode
	Target      string // short ARN
	TargetFull  string // full ARN
	IsAdmin     bool
	Hops        int
	Exploitable string // "full", "partial", "none"
	ModuleChain string // "lambda-001 -> sts-001" or "(no module)"
	Steps       []PathViewStep
}

type pathViewModel struct {
	rows        []PathViewRow
	cursor      int
	width       int
	height      int
	showAll     bool
	title       string
	tableOffset int // scroll offset for table rows

	// Computed column widths
	colNum     int
	colIdent   int
	colTarget  int
	colAdmin   int
	colHops    int
}

// RunPathView launches the interactive path viewer. Blocks until the user quits.
func RunPathView(title string, rows []PathViewRow, showAll bool) error {
	m := pathViewModel{
		rows:    rows,
		title:   title,
		showAll: showAll,
	}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m pathViewModel) Init() tea.Cmd {
	return nil
}

// computeColumns measures content and sets column widths.
func (m *pathViewModel) computeColumns() {
	const gutter = 2 // space between columns

	m.colNum = max(len("#"), len(fmt.Sprintf("%d", len(m.rows))))
	m.colAdmin = len("Admin")
	m.colHops = len("Hops")
	m.colTarget = len("Target")
	m.colIdent = len("Identity")

	for _, row := range m.rows {
		m.colTarget = max(m.colTarget, len(row.Target))
		if m.showAll {
			m.colIdent = max(m.colIdent, len(row.Identity))
		}
	}

	// Cap target width so it doesn't eat the whole terminal
	maxTarget := m.width - m.colNum - m.colAdmin - m.colHops - 20 - (4 * gutter)
	if m.showAll {
		maxTarget -= m.colIdent + gutter
	}
	if maxTarget < 20 {
		maxTarget = 20
	}
	m.colTarget = min(m.colTarget, maxTarget)
}

func (m pathViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.computeColumns()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				if m.cursor < m.tableOffset {
					m.tableOffset = m.cursor
				}
			}
		case "down", "j":
			if m.cursor < len(m.rows)-1 {
				m.cursor++
				maxVisible := m.maxTableRows()
				if m.cursor >= m.tableOffset+maxVisible {
					m.tableOffset = m.cursor - maxVisible + 1
				}
			}
		}
	}
	return m, nil
}

func (m pathViewModel) maxTableRows() int {
	// Reserve lines for: title(1) + blank(1) + header(2) + divider(1) + detail_header(2) + min_detail(3) + help(1) = 11
	available := max(m.height-11, 1)
	// Table gets at most half the available space, capped at row count
	maxRows := max(available/2, 1)
	return min(maxRows, len(m.rows))
}

func (m pathViewModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)
	countStr := fmt.Sprintf("%d reachable target%s", len(m.rows), pluralS(len(m.rows)))
	b.WriteString(titleStyle.Render(m.title) + "   " + Muted.Render(countStr))
	b.WriteString("\n\n")

	// Table header
	b.WriteString(m.renderTableHeader())
	b.WriteString("\n")

	// Table rows
	maxVisible := m.maxTableRows()
	end := min(m.tableOffset+maxVisible, len(m.rows))
	for i := m.tableOffset; i < end; i++ {
		b.WriteString(m.renderTableRow(i))
		b.WriteString("\n")
	}

	// Scroll indicators
	if m.tableOffset > 0 || end < len(m.rows) {
		fmt.Fprintf(&b, "%s\n", Muted.Render(fmt.Sprintf("  showing %d-%d of %d", m.tableOffset+1, end, len(m.rows))))
	}

	// Divider
	divWidth := max(min(m.width, 80), 20)
	b.WriteString(Muted.Render(strings.Repeat("─", divWidth)))
	b.WriteString("\n")

	// Detail pane for selected row
	b.WriteString(m.renderDetail())

	// Help bar at bottom
	b.WriteString("\n")
	b.WriteString(Muted.Render("↑/↓ navigate • q quit"))

	return b.String()
}

// padRight pads a plain string to width, then applies a style. This avoids
// ANSI escape codes breaking %-Ns alignment.
func padRight(s string, width int, style lipgloss.Style) string {
	if len(s) > width {
		s = s[:width-1] + "…"
	}
	padded := fmt.Sprintf("%-*s", width, s)
	return style.Render(padded)
}

func (m pathViewModel) renderTableHeader() string {
	g := "  " // gutter

	var cols []string
	cols = append(cols, padRight("#", m.colNum, Muted))
	if m.showAll {
		cols = append(cols, padRight("Identity", m.colIdent, Muted))
	}
	cols = append(cols,
		padRight("Target", m.colTarget, Muted),
		padRight("Admin", m.colAdmin, Muted),
		padRight("Hops", m.colHops, Muted),
		Muted.Render("Modules"),
	)

	header := "  " + strings.Join(cols, g)

	// Underline: thin dashes under each column
	var dashes []string
	dashes = append(dashes, Muted.Render(strings.Repeat("─", m.colNum)))
	if m.showAll {
		dashes = append(dashes, Muted.Render(strings.Repeat("─", m.colIdent)))
	}
	dashes = append(dashes,
		Muted.Render(strings.Repeat("─", m.colTarget)),
		Muted.Render(strings.Repeat("─", m.colAdmin)),
		Muted.Render(strings.Repeat("─", m.colHops)),
		Muted.Render(strings.Repeat("─", 7)),
	)
	underline := "  " + strings.Join(dashes, g)

	return header + "\n" + underline
}

func (m pathViewModel) renderTableRow(idx int) string {
	row := m.rows[idx]
	selected := idx == m.cursor
	g := "  " // gutter

	style := lipgloss.NewStyle()
	if selected {
		style = BoldCyan
	}

	cursor := "  "
	if selected {
		cursor = BoldCyan.Render("> ")
	}

	adminStr := "No"
	adminStyle := Muted
	if row.IsAdmin {
		adminStr = "Yes"
		adminStyle = Success
	}

	var moduleStyle lipgloss.Style
	switch row.Exploitable {
	case "full":
		moduleStyle = Success
	case "partial":
		moduleStyle = Warning
	default:
		moduleStyle = Muted
	}

	var cols []string
	cols = append(cols, padRight(fmt.Sprintf("%d", idx+1), m.colNum, style))
	if m.showAll {
		cols = append(cols, padRight(row.Identity, m.colIdent, style))
	}
	cols = append(cols,
		padRight(row.Target, m.colTarget, style),
		padRight(adminStr, m.colAdmin, adminStyle),
		padRight(fmt.Sprintf("%d", row.Hops), m.colHops, style),
		moduleStyle.Render(row.ModuleChain),
	)

	return cursor + strings.Join(cols, g)
}

func (m pathViewModel) renderDetail() string {
	if len(m.rows) == 0 {
		return Muted.Render("  No paths to display.")
	}

	row := m.rows[m.cursor]
	var b strings.Builder

	// Detail header
	adminLabel := ""
	if row.IsAdmin {
		adminLabel = " " + Success.Render("(admin)")
	}

	exploitLabel := ""
	switch row.Exploitable {
	case "full":
		exploitLabel = Success.Render("fully exploitable")
	case "partial":
		exploitLabel = Warning.Render("partially exploitable")
	default:
		exploitLabel = Muted.Render("no modules available")
	}

	fmt.Fprintf(&b, "%s%s — %d hop%s, %s\n\n",
		BoldWhite.Render(fmt.Sprintf(" Path to %s", row.Target)),
		adminLabel,
		row.Hops, pluralS(row.Hops), exploitLabel)

	// Steps
	linesLeft := m.height - m.usedLines() - 3 // reserve for help bar
	for i, step := range row.Steps {
		if linesLeft <= 0 {
			b.WriteString(Muted.Render("  ..."))
			break
		}

		fmt.Fprintf(&b, "   %s %s %s %s\n",
			Accent.Render(fmt.Sprintf("Step %d:", i+1)),
			step.SourceShort,
			Muted.Render("→"),
			BoldWhite.Render(step.DestShort))
		linesLeft--

		if step.ModuleID != "" {
			fmt.Fprintf(&b, "     %s %s\n", Success.Render("Module:"), step.ModuleID)
			linesLeft--

			for _, cmd := range step.Commands {
				if linesLeft <= 0 {
					break
				}
				fmt.Fprintf(&b, "       %s\n", Accent.Render(cmd))
				linesLeft--
			}
		} else {
			fmt.Fprintf(&b, "     %s\n", Warning.Render("(no module)"))
			linesLeft--
			if step.Reason != "" {
				fmt.Fprintf(&b, "     %s %s\n", Muted.Render("Reason:"), step.Reason)
				linesLeft--
			}
		}

		b.WriteString("\n")
		linesLeft--
	}

	return b.String()
}

// usedLines returns how many lines the non-detail portions consume.
func (m pathViewModel) usedLines() int {
	maxVisible := m.maxTableRows()
	lines := 2 // title + blank
	lines += 2 // header + underline
	lines += maxVisible
	if m.tableOffset > 0 || m.tableOffset+maxVisible < len(m.rows) {
		lines++ // scroll indicator
	}
	lines++ // divider
	return lines
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
