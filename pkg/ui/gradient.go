// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/lucasb-eyer/go-colorful"
)

// GradientText applies a horizontal color gradient across a single line of text.
func GradientText(text string, from, to colorful.Color, bold bool) string {
	runes := []rune(text)
	var b strings.Builder
	n := len(runes)
	if n == 0 {
		return ""
	}
	for i, r := range runes {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		t := float64(i) / float64(max(n-1, 1))
		c := from.BlendLuv(to, t)
		s := lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex()))
		if bold {
			s = s.Bold(true)
		}
		b.WriteString(s.Render(string(r)))
	}
	return b.String()
}

// GradientLines applies a color gradient across multiple lines of text,
// treating all lines as one continuous sequence for smooth color flow.
func GradientLines(lines []string, from, to colorful.Color, bold bool) string {
	total := 0
	for _, l := range lines {
		total += len([]rune(l))
	}
	if total == 0 {
		return ""
	}
	var b strings.Builder
	pos := 0
	for _, line := range lines {
		for _, r := range line {
			if r == ' ' {
				b.WriteRune(r)
				pos++
				continue
			}
			t := float64(pos) / float64(max(total-1, 1))
			c := from.BlendLuv(to, t)
			s := lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex()))
			if bold {
				s = s.Bold(true)
			}
			b.WriteString(s.Render(string(r)))
			pos++
		}
		b.WriteRune('\n')
	}
	return b.String()
}
