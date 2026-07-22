// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package pmapper

import (
	"slices"
	"strings"

	"github.com/dominikbraun/graph"
)

// Build constructs the in-memory directed graph from nodes and edges.
// Must be called after importing or loading from disk.
func (g *PrivescGraph) Build() {
	g.dirGraph = graph.New(graph.StringHash, graph.Directed())

	// Add all nodes as vertices
	for _, node := range g.Nodes {
		_ = g.dirGraph.AddVertex(node.Arn)
	}

	// Track admin nodes
	g.adminARNs = nil
	for _, node := range g.Nodes {
		if node.IsAdmin {
			g.adminARNs = append(g.adminARNs, node.Arn)
		}
	}

	// Add edges with deduplication (merge multiple reasons for same src->dst)
	for _, edge := range g.Edges {
		attrKey := edge.ShortReason
		attrVal := edge.Reason

		err := g.dirGraph.AddEdge(edge.Source, edge.Destination,
			graph.EdgeAttribute(attrKey, attrVal))
		if err != nil {
			// Edge already exists — merge attributes
			existing, getErr := g.dirGraph.Edge(edge.Source, edge.Destination)
			if getErr == nil {
				attrs := existing.Properties.Attributes
				if attrs == nil {
					attrs = make(map[string]string)
				}
				attrs[attrKey] = attrVal
				_ = g.dirGraph.UpdateEdge(edge.Source, edge.Destination,
					graph.EdgeAttributes(attrs))
			}
		}
	}
}

// FindPathsToAdmin finds all escalation paths from a principal ARN to any admin node.
// Returns paths sorted by hop count (shortest first).
func (g *PrivescGraph) FindPathsToAdmin(principalARN string) []PrivescPath {
	if g.dirGraph == nil {
		return nil
	}

	// Normalize the principal ARN
	normalizedARN := NormalizeARN(principalARN)

	// Check if the principal is already admin (self-escalation capable)
	if slices.Contains(g.adminARNs, normalizedARN) {
		return g.buildSelfEscalationPaths(normalizedARN)
	}

	var paths []PrivescPath

	for _, adminARN := range g.adminARNs {
		path, err := graph.ShortestPath(g.dirGraph, normalizedARN, adminARN)
		if err != nil {
			continue // No path to this admin
		}

		if len(path) < 2 {
			continue // Need at least source + destination
		}

		privescPath := g.buildPrivescPath(normalizedARN, adminARN, path)

		// Append self-escalation steps for the target node so callers can see
		// why that node is privileged (e.g., it holds iam:CreatePolicyVersion on itself).
		for _, result := range g.analyzeSelfEscalation(adminARN) {
			r := result
			privescPath.Steps = append(privescPath.Steps, PrivescStep{
				Source:         adminARN,
				Destination:    adminARN,
				ShortReason:    "Self-Escalation",
				Reason:         result.Description,
				ModuleIDs:      []string{result.ModuleID},
				SelfEscalation: &r,
			})
		}

		paths = append(paths, privescPath)
	}

	// Sort by number of steps (shortest first)
	sortPathsByLength(paths)

	return paths
}

// CountPathsToAdmin returns the number of admin nodes reachable from the principal.
func (g *PrivescGraph) CountPathsToAdmin(principalARN string) int {
	if g.dirGraph == nil {
		return 0
	}

	normalizedARN := NormalizeARN(principalARN)
	count := 0

	// Self-escalation counts as a path
	if slices.Contains(g.adminARNs, normalizedARN) {
		results := g.analyzeSelfEscalation(normalizedARN)
		if len(results) > 0 {
			return 1 // self-escalation path
		}
		return 0
	}

	for _, adminARN := range g.adminARNs {
		if normalizedARN == adminARN {
			continue
		}
		_, err := graph.ShortestPath(g.dirGraph, normalizedARN, adminARN)
		if err == nil {
			count++
		}
	}

	return count
}

// HasNode checks if a principal ARN exists in the graph.
func (g *PrivescGraph) HasNode(principalARN string) bool {
	if g.dirGraph == nil {
		return false
	}
	normalizedARN := NormalizeARN(principalARN)
	_, err := g.dirGraph.Vertex(normalizedARN)
	return err == nil
}

// AdminARNs returns the list of admin node ARNs.
func (g *PrivescGraph) AdminARNs() []string {
	return g.adminARNs
}

// buildPrivescPath reconstructs the hop-by-hop details from a shortest path.
func (g *PrivescGraph) buildPrivescPath(source, target string, nodePath []string) PrivescPath {
	pp := PrivescPath{
		Source: source,
		Target: target,
	}

	for i := 0; i < len(nodePath)-1; i++ {
		src := nodePath[i]
		dst := nodePath[i+1]

		step := PrivescStep{
			Source:      src,
			Destination: dst,
		}

		// Get edge attributes for this hop
		edge, err := g.dirGraph.Edge(src, dst)
		if err == nil && edge.Properties.Attributes != nil {
			// Pick the first attribute as the primary reason
			for shortReason, reason := range edge.Properties.Attributes {
				step.ShortReason = shortReason
				step.Reason = reason
				break
			}
		}

		// Also check all raw edges for this src->dst to find all reasons
		// and resolve modules from all matching edges
		step.ModuleIDs = g.resolveModulesForHop(src, dst)

		pp.Steps = append(pp.Steps, step)
	}

	return pp
}

// resolveModulesForHop finds all module IDs for a specific source->destination hop
// by checking all raw edges between those nodes.
func (g *PrivescGraph) resolveModulesForHop(src, dst string) []string {
	seen := make(map[string]bool)
	var moduleIDs []string

	for _, edge := range g.Edges {
		if edge.Source == src && edge.Destination == dst {
			for _, id := range ResolveModules(edge) {
				if !seen[id] {
					seen[id] = true
					moduleIDs = append(moduleIDs, id)
				}
			}
		}
	}

	return moduleIDs
}

// GetEdgesBetween returns all raw PMapper edges between two nodes.
func (g *PrivescGraph) GetEdgesBetween(src, dst string) []PMapperEdge {
	var edges []PMapperEdge
	for _, edge := range g.Edges {
		if edge.Source == src && edge.Destination == dst {
			edges = append(edges, edge)
		}
	}
	return edges
}

// GetStatus returns metadata about the graph for status display.
func (g *PrivescGraph) GetStatus() GraphStatus {
	status := GraphStatus{
		AccountID:  g.AccountID,
		ImportedAt: g.ImportedAt,
		NodeCount:  len(g.Nodes),
		EdgeCount:  len(g.Edges),
	}

	for _, node := range g.Nodes {
		if node.IsAdmin {
			status.AdminCount++
		}
	}

	// Build edge pattern summary
	patternMap := make(map[string]*EdgePatternStatus)
	for _, edge := range g.Edges {
		key := edge.ShortReason
		if _, exists := patternMap[key]; !exists {
			mods := ResolveModulesAll(edge)
			patternMap[key] = &EdgePatternStatus{
				ShortReason: edge.ShortReason,
				Count:       0,
				ModuleIDs:   mods,
				HasModule:   len(ResolveModules(edge)) > 0,
			}
		}
		patternMap[key].Count++
	}

	for _, ps := range patternMap {
		status.EdgePatterns = append(status.EdgePatterns, *ps)
	}

	return status
}

// ShortARN extracts the short form of an ARN (e.g., "user/Alice" or "role/Admin").
func ShortARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		return parts[5]
	}
	return arn
}

// FindAllReachable discovers all nodes reachable from the principal via BFS,
// then builds shortest-path PrivescPath entries for each. Returns paths sorted
// by hop count (shortest first).
func (g *PrivescGraph) FindAllReachable(principalARN string) []PrivescPath {
	if g.dirGraph == nil {
		return nil
	}

	normalizedARN := NormalizeARN(principalARN)

	// BFS to find all reachable nodes
	reachable := make(map[string]bool)
	_ = graph.BFS(g.dirGraph, normalizedARN, func(vertex string) bool {
		if vertex != normalizedARN {
			reachable[vertex] = true
		}
		return false
	})

	if len(reachable) == 0 {
		return nil
	}

	var paths []PrivescPath
	for target := range reachable {
		path, err := graph.ShortestPath(g.dirGraph, normalizedARN, target)
		if err != nil || len(path) < 2 {
			continue
		}
		privescPath := g.buildPrivescPath(normalizedARN, target, path)
		paths = append(paths, privescPath)
	}

	sortPathsByLength(paths)
	return paths
}

// IsAdmin returns true if the given ARN corresponds to an admin node in the graph.
func (g *PrivescGraph) IsAdmin(arn string) bool {
	return slices.Contains(g.adminARNs, NormalizeARN(arn))
}

// buildSelfEscalationPaths creates synthetic paths for a node that is admin due to
// self-escalation capabilities. Returns one path per self-escalation result.
func (g *PrivescGraph) buildSelfEscalationPaths(principalARN string) []PrivescPath {
	results := g.analyzeSelfEscalation(principalARN)
	if len(results) == 0 {
		return nil
	}

	// Group all self-escalation results into a single path
	path := PrivescPath{
		Source: principalARN,
		Target: principalARN,
	}
	for _, result := range results {
		r := result // capture for pointer
		step := PrivescStep{
			Source:         principalARN,
			Destination:    principalARN,
			ShortReason:    "Self-Escalation",
			Reason:         result.Description,
			ModuleIDs:      []string{result.ModuleID},
			SelfEscalation: &r,
		}
		path.Steps = append(path.Steps, step)
	}

	return []PrivescPath{path}
}

// analyzeSelfEscalation runs self-escalation analysis for a node in this graph.
func (g *PrivescGraph) analyzeSelfEscalation(principalARN string) []SelfEscalationResult {
	if len(g.Policies) == 0 {
		return nil
	}

	// Find the node
	var node *PMapperNode
	for i := range g.Nodes {
		if g.Nodes[i].Arn == principalARN {
			node = &g.Nodes[i]
			break
		}
	}
	if node == nil {
		return nil
	}

	return AnalyzeSelfEscalation(*node, g.Policies)
}

// sortPathsByLength sorts paths by step count (shortest first).
func sortPathsByLength(paths []PrivescPath) {
	for i := 1; i < len(paths); i++ {
		key := paths[i]
		j := i - 1
		for j >= 0 && len(paths[j].Steps) > len(key.Steps) {
			paths[j+1] = paths[j]
			j--
		}
		paths[j+1] = key
	}
}
