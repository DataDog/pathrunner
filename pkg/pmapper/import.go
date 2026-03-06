package pmapper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultPMapperDir returns the default PMapper data directory.
// Checks platform-specific paths in order of priority:
//   - macOS: ~/Library/Application Support/com.nccgroup.principalmapper/
//   - Linux: ~/.local/share/pmapper/
func DefaultPMapperDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	// Check platform-specific paths in priority order
	candidates := []string{
		filepath.Join(home, "Library", "Application Support", "com.nccgroup.principalmapper"),
		filepath.Join(home, ".local", "share", "pmapper"),
	}

	// On non-macOS, check Linux path first
	if runtime.GOOS != "darwin" {
		candidates[0], candidates[1] = candidates[1], candidates[0]
	}

	for _, dir := range candidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
	}

	// Fallback: return platform default even if it doesn't exist yet
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "com.nccgroup.principalmapper")
	}
	return filepath.Join(home, ".local", "share", "pmapper")
}

// FindAccountDirs discovers PMapper account directories matching the given account IDs.
// If accountIDs is empty, returns all found account directories.
func FindAccountDirs(basePath string, accountIDs []string) (map[string]string, error) {
	if basePath == "" {
		basePath = DefaultPMapperDir()
	}
	if basePath == "" {
		return nil, fmt.Errorf("could not determine PMapper data directory")
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PMapper directory %s: %w", basePath, err)
	}

	wantAll := len(accountIDs) == 0
	wantSet := make(map[string]bool, len(accountIDs))
	for _, id := range accountIDs {
		wantSet[id] = true
	}

	result := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// PMapper account dirs are 12-digit account IDs
		if len(name) != 12 || !isDigits(name) {
			continue
		}
		if wantAll || wantSet[name] {
			result[name] = filepath.Join(basePath, name)
		}
	}

	return result, nil
}

// ImportFromDir imports PMapper graph data from a directory containing
// graph/{nodes,edges}.json files. This is the standard PMapper output structure.
func ImportFromDir(dirPath string) (*PrivescGraph, error) {
	graphDir := filepath.Join(dirPath, "graph")

	// Check if graph subdirectory exists; if not, try the directory itself
	if _, err := os.Stat(graphDir); os.IsNotExist(err) {
		graphDir = dirPath
	}

	nodesPath := filepath.Join(graphDir, "nodes.json")
	edgesPath := filepath.Join(graphDir, "edges.json")

	nodes, err := parseNodes(nodesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nodes: %w", err)
	}

	edges, err := parseEdges(edgesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse edges: %w", err)
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes found in %s", nodesPath)
	}

	// Extract account ID from first node ARN
	accountID := extractAccountID(nodes[0].Arn)

	// Load policies.json (optional — don't fail if missing)
	policiesPath := filepath.Join(graphDir, "policies.json")
	policies, _ := parsePolicies(policiesPath)

	g := &PrivescGraph{
		AccountID:  accountID,
		ImportedAt: time.Now(),
		Nodes:      nodes,
		Edges:      edges,
		Policies:   policies,
	}

	// Build the in-memory graph
	g.Build()

	return g, nil
}

// parseNodes reads and parses a PMapper nodes.json file.
func parseNodes(path string) ([]PMapperNode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var nodes []PMapperNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return nodes, nil
}

// parsePolicies reads and parses a PMapper policies.json file.
// Returns nil, nil if the file does not exist (policies are optional).
func parsePolicies(path string) ([]PMapperPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// PMapper policies.json is an array of objects with arn, name, and policy_doc fields.
	// policy_doc may be a JSON string or already-parsed object depending on PMapper version.
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	var policies []PMapperPolicy
	for _, entry := range raw {
		var p struct {
			Arn       string          `json:"arn"`
			Name      string          `json:"name"`
			PolicyDoc json.RawMessage `json:"policy_doc"`
		}
		if err := json.Unmarshal(entry, &p); err != nil {
			continue
		}

		policy := PMapperPolicy{
			Arn:  p.Arn,
			Name: p.Name,
		}

		// policy_doc can be a JSON string (escaped) or an inline object
		if len(p.PolicyDoc) > 0 {
			var doc any
			if p.PolicyDoc[0] == '"' {
				// It's a JSON-encoded string — decode the string first, then parse it
				var docStr string
				if err := json.Unmarshal(p.PolicyDoc, &docStr); err == nil {
					_ = json.Unmarshal([]byte(docStr), &doc)
				}
			} else {
				_ = json.Unmarshal(p.PolicyDoc, &doc)
			}
			policy.PolicyDoc = doc
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// parseEdges reads and parses a PMapper edges.json file.
func parseEdges(path string) ([]PMapperEdge, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var edges []PMapperEdge
	if err := json.Unmarshal(data, &edges); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	return edges, nil
}

// extractAccountID extracts the AWS account ID from an ARN.
// e.g., "arn:aws:iam::123456789012:user/Alice" -> "123456789012"
func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// NormalizeARN converts assumed-role ARNs to their IAM role equivalent
// to match PMapper graph node ARNs.
// arn:aws:sts::ACCT:assumed-role/ROLE/SESSION -> arn:aws:iam::ACCT:role/ROLE
func NormalizeARN(arn string) string {
	if strings.Contains(arn, ":assumed-role/") {
		parts := strings.Split(arn, ":")
		if len(parts) >= 6 {
			resource := parts[5] // "assumed-role/ROLE/SESSION"
			resourceParts := strings.Split(resource, "/")
			if len(resourceParts) >= 2 {
				roleName := resourceParts[1]
				// Reconstruct as IAM role ARN
				parts[2] = "iam"            // sts -> iam
				parts[5] = "role/" + roleName // assumed-role/ROLE/SESSION -> role/ROLE
				return strings.Join(parts, ":")
			}
		}
	}
	return arn
}

// ExtractAccountIDFromARN extracts the AWS account ID from a caller ARN.
func ExtractAccountIDFromARN(arn string) string {
	return extractAccountID(arn)
}

// isDigits returns true if the string contains only digit characters.
func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
