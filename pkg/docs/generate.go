// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// ReferenceFileName is the machine-readable artifact pathfinding.cloud pulls.
const ReferenceFileName = "pathrunner-reference.json"

// Generate builds the documentation Reference from the given Cobra root command
// and writes all artifacts under outDir:
//
//	<outDir>/pathrunner-reference.json   — the machine-readable reference
//	<outDir>/commands/<name>.md          — one cloudfox-style page per command
//	<outDir>/modules/<id>.md             — one cloudfox-style page per module
//
// It returns the assembled Reference so callers can report counts.
func Generate(root *cobra.Command, outDir string) (Reference, error) {
	ref := BuildReference(root)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return ref, fmt.Errorf("create output dir: %w", err)
	}

	if err := writeJSON(filepath.Join(outDir, ReferenceFileName), ref); err != nil {
		return ref, err
	}

	commandsDir := filepath.Join(outDir, "commands")
	if err := os.MkdirAll(commandsDir, 0o755); err != nil {
		return ref, fmt.Errorf("create commands dir: %w", err)
	}
	for _, c := range ref.Commands {
		path := filepath.Join(commandsDir, c.Name+".md")
		if err := os.WriteFile(path, []byte(RenderCommandMarkdown(c)), 0o644); err != nil {
			return ref, fmt.Errorf("write command %s: %w", c.Name, err)
		}
	}

	modulesDir := filepath.Join(outDir, "modules")
	if err := os.MkdirAll(modulesDir, 0o755); err != nil {
		return ref, fmt.Errorf("create modules dir: %w", err)
	}
	for _, m := range ref.Modules {
		if m.ID == "" {
			continue
		}
		path := filepath.Join(modulesDir, m.ID+".md")
		if err := os.WriteFile(path, []byte(RenderModuleMarkdown(m)), 0o644); err != nil {
			return ref, fmt.Errorf("write module %s: %w", m.ID, err)
		}
	}

	return ref, nil
}

// writeJSON marshals v as indented JSON (with a trailing newline, so the file is
// stable under tools that expect one) and writes it to path.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
