package status

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// ModuleStatus represents the test status of a single module.
type ModuleStatus struct {
	Status       string  `json:"status"`
	LastTested   *string `json:"last_tested"`
	TestedAgainst *string `json:"tested_against"`
	Notes        string  `json:"notes"`
}

// StatusManifest holds the complete module status data.
type StatusManifest struct {
	Modules map[string]ModuleStatus `json:"modules"`
}

// ValidStatuses are the allowed values for status fields.
var ValidStatuses = []string{"tested", "untested", "failing", "needs-update"}

// LoadManifest reads the module status manifest from testdata/module-status.json.
// It searches relative to the source file location (for use from any working directory).
func LoadManifest() (*StatusManifest, error) {
	path, err := findManifestPath()
	if err != nil {
		return nil, err
	}
	return LoadManifestFromPath(path)
}

// LoadManifestFromPath reads the manifest from a specific file path.
func LoadManifestFromPath(path string) (*StatusManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read module status manifest: %v", err)
	}

	var manifest StatusManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse module status manifest: %v", err)
	}

	return &manifest, nil
}

// SaveManifest writes the manifest back to testdata/module-status.json.
func SaveManifest(manifest *StatusManifest) error {
	path, err := findManifestPath()
	if err != nil {
		return err
	}
	return SaveManifestToPath(manifest, path)
}

// SaveManifestToPath writes the manifest to a specific file path.
func SaveManifestToPath(manifest *StatusManifest, path string) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal module status manifest: %v", err)
	}
	// Ensure trailing newline
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write module status manifest: %v", err)
	}

	return nil
}

// MarkTested updates a module's status to "tested" with the current date.
func (m *StatusManifest) MarkTested(moduleID string, testedAgainst string) {
	now := time.Now().Format("2006-01-02")
	entry := m.Modules[moduleID]
	entry.Status = "tested"
	entry.LastTested = &now
	if testedAgainst != "" {
		entry.TestedAgainst = &testedAgainst
	}
	m.Modules[moduleID] = entry
}

// MarkStatus updates a module's status to the given value.
func (m *StatusManifest) MarkStatus(moduleID string, newStatus string) error {
	valid := false
	for _, s := range ValidStatuses {
		if s == newStatus {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid status '%s'. Valid values: %v", newStatus, ValidStatuses)
	}

	entry := m.Modules[moduleID]
	entry.Status = newStatus
	m.Modules[moduleID] = entry
	return nil
}

// Summary returns counts by status.
func (m *StatusManifest) Summary() map[string]int {
	counts := make(map[string]int)
	for _, entry := range m.Modules {
		counts[entry.Status]++
	}
	return counts
}

// SortedModuleIDs returns module IDs sorted alphabetically.
func (m *StatusManifest) SortedModuleIDs() []string {
	ids := make([]string, 0, len(m.Modules))
	for id := range m.Modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// findManifestPath locates testdata/module-status.json relative to this source file,
// then walks up to find the project root.
func findManifestPath() (string, error) {
	// First try: relative to the source file (works in tests and dev)
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		// Walk up from pkg/status/ to project root
		projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
		candidate := filepath.Join(projectRoot, "testdata", "module-status.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Second try: relative to current working directory
	cwd, err := os.Getwd()
	if err == nil {
		candidate := filepath.Join(cwd, "testdata", "module-status.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not find testdata/module-status.json")
}
