package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

var (
	// isTTY detects whether stdout is a terminal.
	// When false, all styling is stripped for pipe-friendly output.
	isTTY = lipgloss.HasDarkBackground()

	// Color palette — cyan-based to match existing brand
	ColorPrimary   = lipgloss.Color("#00BFFF") // deep sky blue / bright cyan
	ColorSecondary = lipgloss.Color("#00CED1") // dark turquoise
	ColorAccent    = lipgloss.Color("#5FAFFF") // softer blue for highlights
	ColorSuccess   = lipgloss.Color("#00FF87") // green
	ColorWarning   = lipgloss.Color("#FFD700") // gold
	ColorError     = lipgloss.Color("#FF5F5F") // red
	ColorMuted     = lipgloss.Color("#6C6C6C") // dim gray
	ColorWhite     = lipgloss.Color("#FFFFFF")
	ColorBright    = lipgloss.Color("#E0E0E0") // slightly dimmer white

	// Text styles
	Bold       = lipgloss.NewStyle().Bold(true)
	Muted      = lipgloss.NewStyle().Foreground(ColorMuted)
	Primary    = lipgloss.NewStyle().Foreground(ColorPrimary)
	Secondary  = lipgloss.NewStyle().Foreground(ColorSecondary)
	Accent     = lipgloss.NewStyle().Foreground(ColorAccent)
	Success    = lipgloss.NewStyle().Foreground(ColorSuccess)
	Warning    = lipgloss.NewStyle().Foreground(ColorWarning)
	Error      = lipgloss.NewStyle().Foreground(ColorError)
	BoldCyan   = lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary)
	BoldWhite  = lipgloss.NewStyle().Bold(true).Foreground(ColorWhite)
	BoldError  = lipgloss.NewStyle().Bold(true).Foreground(ColorError)

	// Status indicators
	StatusReady   = Success.Render("✅ Ready")
	StatusWarning = Warning.Render("⚠️ ")
	StatusError   = Error.Render("❌ ")

	// Section heading
	SectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1)

	// Box for context/info panels
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)
)

func init() {
	// Check if stdout is actually a TTY
	if fi, err := os.Stdout.Stat(); err == nil {
		isTTY = (fi.Mode() & os.ModeCharDevice) != 0
	}
}

// IsTTY returns true if stdout is a terminal
func IsTTY() bool {
	return isTTY
}

// SetTTY overrides TTY detection (useful for testing)
func SetTTY(v bool) {
	isTTY = v
}
