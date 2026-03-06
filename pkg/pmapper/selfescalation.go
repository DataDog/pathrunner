package pmapper

import (
	"fmt"
	"strings"
)

// selfEscalationCheck defines one check from PMapper's gathering.py:update_admin_status().
type selfEscalationCheck struct {
	Action      string // IAM action (e.g. "iam:CreatePolicyVersion")
	NodeType    string // "user", "role", or "" for either
	ModuleID    string // pathrunner module ID
	TargetSelf  bool   // resource must match the node's own ARN
	TargetGroup bool   // resource must match one of the node's group ARNs
	TargetPolicy bool  // resource must match an attached customer-managed policy ARN
}

// selfEscalationChecks mirrors PMapper's admin status checks.
var selfEscalationChecks = []selfEscalationCheck{
	{Action: "iam:PutUserPolicy", NodeType: "user", ModuleID: "iam-007", TargetSelf: true},
	{Action: "iam:PutRolePolicy", NodeType: "role", ModuleID: "iam-005", TargetSelf: true},
	{Action: "iam:AttachUserPolicy", NodeType: "user", ModuleID: "iam-008", TargetSelf: true},
	{Action: "iam:AttachRolePolicy", NodeType: "role", ModuleID: "iam-009", TargetSelf: true},
	{Action: "iam:CreatePolicyVersion", NodeType: "", ModuleID: "iam-001", TargetPolicy: true},
	{Action: "iam:PutGroupPolicy", NodeType: "user", ModuleID: "iam-011", TargetGroup: true},
	{Action: "iam:AttachGroupPolicy", NodeType: "user", ModuleID: "iam-010", TargetGroup: true},
}

// AnalyzeSelfEscalation checks what self-escalation actions a node can perform.
// This mirrors PMapper's gathering.py:update_admin_status() logic, which determines
// if a principal can grant itself admin by modifying its own policies.
func AnalyzeSelfEscalation(node PMapperNode, policies []PMapperPolicy) []SelfEscalationResult {
	nodeType := nodeTypeFromARN(node.Arn) // "user" or "role"
	if nodeType == "" {
		return nil
	}

	// Build policy document lookup: policy ARN -> parsed statements
	policyDocs := buildPolicyLookup(policies)

	// Collect all policy statements that apply to this node
	statements := collectNodeStatements(node, policyDocs)
	if len(statements) == 0 {
		return nil
	}

	// Gather target resources for each check type
	groupARNs := extractGroupARNs(node)
	customerPolicyARNs := extractCustomerPolicyARNs(node)

	var results []SelfEscalationResult
	seen := make(map[string]bool) // deduplicate by moduleID+resource

	for _, check := range selfEscalationChecks {
		if check.NodeType != "" && check.NodeType != nodeType {
			continue
		}

		var targetResources []string
		switch {
		case check.TargetSelf:
			targetResources = []string{node.Arn}
		case check.TargetGroup:
			targetResources = groupARNs
		case check.TargetPolicy:
			targetResources = customerPolicyARNs
		}

		for _, targetARN := range targetResources {
			if statementsAllow(statements, check.Action, targetARN) {
				key := check.ModuleID + ":" + targetARN
				if seen[key] {
					continue
				}
				seen[key] = true
				results = append(results, SelfEscalationResult{
					ModuleID:    check.ModuleID,
					Action:      check.Action,
					Resource:    targetARN,
					Description: describeSelfEscalation(check, node.Arn, targetARN),
				})
			}
		}
	}

	return results
}

// policyStatement is a simplified IAM policy statement for matching.
type policyStatement struct {
	Effect    string
	Actions   []string
	Resources []string
}

// buildPolicyLookup creates a map from policy ARN to parsed statements.
func buildPolicyLookup(policies []PMapperPolicy) map[string][]policyStatement {
	lookup := make(map[string][]policyStatement)
	for _, p := range policies {
		stmts := parsePolicyStatements(p.PolicyDoc)
		if len(stmts) > 0 {
			lookup[p.Arn] = stmts
		}
	}
	return lookup
}

// collectNodeStatements gathers all Allow statements from policies attached to a node.
func collectNodeStatements(node PMapperNode, policyDocs map[string][]policyStatement) []policyStatement {
	var all []policyStatement
	for _, ap := range node.AttachedPolicies {
		if stmts, ok := policyDocs[ap.Arn]; ok {
			all = append(all, stmts...)
		}
	}
	return all
}

// parsePolicyStatements extracts statements from a parsed IAM policy document.
func parsePolicyStatements(doc any) []policyStatement {
	docMap, ok := doc.(map[string]any)
	if !ok {
		return nil
	}

	statementsRaw, ok := docMap["Statement"]
	if !ok {
		return nil
	}

	// Statement can be a single object or an array
	var stmtList []any
	switch v := statementsRaw.(type) {
	case []any:
		stmtList = v
	case map[string]any:
		stmtList = []any{v}
	default:
		return nil
	}

	var result []policyStatement
	for _, raw := range stmtList {
		stmtMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		effect, _ := stmtMap["Effect"].(string)
		if !strings.EqualFold(effect, "Allow") {
			continue
		}

		stmt := policyStatement{
			Effect:    "Allow",
			Actions:   toStringSlice(stmtMap["Action"]),
			Resources: toStringSlice(stmtMap["Resource"]),
		}
		if len(stmt.Actions) > 0 && len(stmt.Resources) > 0 {
			result = append(result, stmt)
		}
	}

	return result
}

// toStringSlice converts a JSON value (string or []string) to a string slice.
func toStringSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// statementsAllow checks if any Allow statement grants the action on the resource.
func statementsAllow(stmts []policyStatement, action, resource string) bool {
	for _, stmt := range stmts {
		if actionMatches(stmt.Actions, action) && resourceMatches(stmt.Resources, resource) {
			return true
		}
	}
	return false
}

// actionMatches checks if an IAM action is matched by any pattern in the list.
// Supports: "*", "iam:*", "iam:CreatePolicyVersion", "iam:Create*"
func actionMatches(patterns []string, action string) bool {
	actionLower := strings.ToLower(action)
	for _, pattern := range patterns {
		patternLower := strings.ToLower(pattern)
		if patternLower == "*" {
			return true
		}
		if patternLower == actionLower {
			return true
		}
		// Wildcard suffix: "iam:*" or "iam:Create*"
		if strings.HasSuffix(patternLower, "*") {
			prefix := patternLower[:len(patternLower)-1]
			if strings.HasPrefix(actionLower, prefix) {
				return true
			}
		}
	}
	return false
}

// resourceMatches checks if a resource ARN is matched by any pattern in the list.
// Supports: "*", exact match, and simple glob with trailing wildcard.
func resourceMatches(patterns []string, resource string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if pattern == resource {
			return true
		}
		// Simple glob: "arn:aws:iam::123:user/*" matches "arn:aws:iam::123:user/Alice"
		if strings.HasSuffix(pattern, "*") {
			prefix := pattern[:len(pattern)-1]
			if strings.HasPrefix(resource, prefix) {
				return true
			}
		}
	}
	return false
}

// nodeTypeFromARN returns "user" or "role" based on the ARN resource type.
func nodeTypeFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	resource := parts[5]
	if strings.HasPrefix(resource, "user/") {
		return "user"
	}
	if strings.HasPrefix(resource, "role/") {
		return "role"
	}
	return ""
}

// extractGroupARNs extracts group ARNs from a node's GroupMemberships.
// PMapper stores these as strings or objects with an "arn" field.
func extractGroupARNs(node PMapperNode) []string {
	var arns []string
	for _, gm := range node.GroupMemberships {
		switch v := gm.(type) {
		case string:
			arns = append(arns, v)
		case map[string]any:
			if arn, ok := v["arn"].(string); ok {
				arns = append(arns, arn)
			}
		}
	}
	return arns
}

// extractCustomerPolicyARNs returns ARNs of customer-managed policies attached to a node.
// Skips AWS-managed policies (containing ":aws:policy/").
func extractCustomerPolicyARNs(node PMapperNode) []string {
	var arns []string
	for _, p := range node.AttachedPolicies {
		if !strings.Contains(p.Arn, ":aws:policy/") {
			arns = append(arns, p.Arn)
		}
	}
	return arns
}

// describeSelfEscalation generates a human-readable description of a self-escalation action.
func describeSelfEscalation(check selfEscalationCheck, nodeARN, targetARN string) string {
	short := ShortARN(nodeARN)
	switch {
	case check.TargetSelf:
		return fmt.Sprintf("%s can %s on itself", short, check.Action)
	case check.TargetGroup:
		return fmt.Sprintf("%s can %s on group %s", short, check.Action, ShortARN(targetARN))
	case check.TargetPolicy:
		return fmt.Sprintf("%s can %s on attached policy %s", short, check.Action, ShortARN(targetARN))
	default:
		return fmt.Sprintf("%s can %s on %s", short, check.Action, ShortARN(targetARN))
	}
}
