package pmapper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Manager handles PMapper graph loading, storage, and querying.
type Manager struct {
	mu     sync.RWMutex
	graphs map[string]*PrivescGraph // account_id -> graph
}

// NewManager creates a new PMapper manager.
func NewManager() *Manager {
	return &Manager{
		graphs: make(map[string]*PrivescGraph),
	}
}

// graphDir returns the directory for storing graph data.
func graphDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".pathrunner", "graphs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("could not create graphs directory: %w", err)
	}
	return dir, nil
}

// graphPath returns the file path for a specific account's graph data.
func graphPath(accountID string) (string, error) {
	dir, err := graphDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, accountID+".json"), nil
}

// Import imports PMapper data from a directory path, stores it, and returns the account IDs.
func (m *Manager) Import(dirPath string, accountIDs []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If dirPath points directly to a directory with graph data (nodes.json/edges.json),
	// import just that one
	if hasGraphData(dirPath) {
		g, err := ImportFromDir(dirPath)
		if err != nil {
			return nil, err
		}
		m.graphs[g.AccountID] = g
		if err := m.saveGraph(g); err != nil {
			return nil, fmt.Errorf("imported but failed to persist: %w", err)
		}
		return []string{g.AccountID}, nil
	}

	// Otherwise, scan for account subdirectories
	accountDirs, err := FindAccountDirs(dirPath, accountIDs)
	if err != nil {
		return nil, err
	}

	if len(accountDirs) == 0 {
		return nil, fmt.Errorf("no PMapper data found in %s", dirPath)
	}

	var imported []string
	for accountID, accountDir := range accountDirs {
		g, err := ImportFromDir(accountDir)
		if err != nil {
			return imported, fmt.Errorf("failed to import account %s: %w", accountID, err)
		}
		m.graphs[g.AccountID] = g
		if err := m.saveGraph(g); err != nil {
			return imported, fmt.Errorf("imported %s but failed to persist: %w", accountID, err)
		}
		imported = append(imported, g.AccountID)
	}

	return imported, nil
}

// IsLoaded returns whether a graph is loaded for the given account.
func (m *Manager) IsLoaded(accountID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.graphs[accountID]
	return exists
}

// GetGraph returns the graph for an account, loading from disk if needed.
func (m *Manager) GetGraph(accountID string) (*PrivescGraph, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if g, exists := m.graphs[accountID]; exists {
		return g, nil
	}

	// Try loading from disk
	g, err := m.loadGraph(accountID)
	if err != nil {
		return nil, err
	}
	m.graphs[accountID] = g
	return g, nil
}

// FindPathsToAdmin finds escalation paths for a principal in a specific account.
func (m *Manager) FindPathsToAdmin(accountID, principalARN string) []PrivescPath {
	g, err := m.GetGraph(accountID)
	if err != nil {
		return nil
	}
	return g.FindPathsToAdmin(principalARN)
}

// CountPathsToAdmin counts reachable admin nodes for a principal.
func (m *Manager) CountPathsToAdmin(accountID, principalARN string) int {
	g, err := m.GetGraph(accountID)
	if err != nil {
		return 0
	}
	return g.CountPathsToAdmin(principalARN)
}

// Status returns status for all loaded graphs.
func (m *Manager) Status() []GraphStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var statuses []GraphStatus
	for _, g := range m.graphs {
		statuses = append(statuses, g.GetStatus())
	}
	return statuses
}

// TryAutoLoad attempts to load a graph from disk for the given account ID.
// Returns true if a graph was loaded successfully.
func (m *Manager) TryAutoLoad(accountID string) bool {
	if accountID == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.graphs[accountID]; exists {
		return true
	}

	g, err := m.loadGraph(accountID)
	if err != nil {
		return false
	}
	m.graphs[accountID] = g
	return true
}

// saveGraph persists a graph to disk.
func (m *Manager) saveGraph(g *PrivescGraph) error {
	path, err := graphPath(g.AccountID)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal graph: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// loadGraph loads a graph from disk and rebuilds the in-memory graph.
func (m *Manager) loadGraph(accountID string) (*PrivescGraph, error) {
	path, err := graphPath(accountID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no graph data for account %s: %w", accountID, err)
	}

	var g PrivescGraph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("failed to parse graph data: %w", err)
	}

	// If policies are missing, try to load them from the PMapper source directory
	if len(g.Policies) == 0 {
		if policies := tryLoadPoliciesFromSource(accountID); len(policies) > 0 {
			g.Policies = policies
			// Re-persist so future loads don't need to re-discover
			_ = m.saveGraph(&g)
		}
	}

	// Rebuild in-memory graph
	g.Build()

	return &g, nil
}

// tryLoadPoliciesFromSource attempts to load policies.json from the PMapper source
// directory for graphs that were imported before policy support was added.
func tryLoadPoliciesFromSource(accountID string) []PMapperPolicy {
	basePath := DefaultPMapperDir()
	if basePath == "" {
		return nil
	}

	// Try standard PMapper layout: {basePath}/{accountID}/graph/policies.json
	candidates := []string{
		filepath.Join(basePath, accountID, "graph", "policies.json"),
		filepath.Join(basePath, accountID, "policies.json"),
	}

	for _, path := range candidates {
		policies, err := parsePolicies(path)
		if err == nil && len(policies) > 0 {
			return policies
		}
	}

	return nil
}

// hasGraphData checks if a directory contains PMapper graph data (nodes.json/edges.json).
func hasGraphData(dirPath string) bool {
	// Check for graph/nodes.json first (standard PMapper layout)
	graphDir := filepath.Join(dirPath, "graph")
	if _, err := os.Stat(filepath.Join(graphDir, "nodes.json")); err == nil {
		return true
	}
	// Check for nodes.json directly in the directory
	if _, err := os.Stat(filepath.Join(dirPath, "nodes.json")); err == nil {
		return true
	}
	return false
}
