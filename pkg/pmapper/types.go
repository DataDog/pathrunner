// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package pmapper

import (
	"time"

	"github.com/dominikbraun/graph"
)

// PMapperNode represents a principal node from PMapper's nodes.json.
type PMapperNode struct {
	Arn              string           `json:"arn"`
	IDValue          string           `json:"id_value"`
	AttachedPolicies []AttachedPolicy `json:"attached_policies"`
	GroupMemberships []any            `json:"group_memberships"`
	TrustPolicy      any             `json:"trust_policy"`
	InstanceProfile  any             `json:"instance_profile"`
	ActivePassword   bool            `json:"active_password"`
	AccessKeys       int             `json:"access_keys"`
	IsAdmin          bool            `json:"is_admin"`
	PermissionBoundary any           `json:"permissions_boundary"`
	HasMfa           bool            `json:"has_mfa"`
	Tags             map[string]string `json:"tags"`
}

// AttachedPolicy represents an IAM policy attached to a node.
type AttachedPolicy struct {
	Arn  string `json:"arn"`
	Name string `json:"name"`
}

// PMapperEdge represents a privilege escalation edge from PMapper's edges.json.
type PMapperEdge struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	ShortReason string `json:"short_reason"`
}

// PMapperPolicy represents a customer-managed IAM policy from PMapper's policies.json.
type PMapperPolicy struct {
	Arn        string `json:"arn"`
	Name       string `json:"name"`
	PolicyDoc  any    `json:"policy_doc"` // parsed policy document
}

// SelfEscalationResult describes one self-escalation action available to a node.
type SelfEscalationResult struct {
	ModuleID    string // pathrunner module ID (e.g. "iam-001")
	Action      string // IAM action (e.g. "iam:CreatePolicyVersion")
	Resource    string // ARN the action targets
	Description string // human-readable explanation
}

// PrivescGraph holds the imported PMapper graph data and in-memory directed graph.
type PrivescGraph struct {
	AccountID  string          `json:"account_id"`
	ImportedAt time.Time       `json:"imported_at"`
	Nodes      []PMapperNode   `json:"nodes"`
	Edges      []PMapperEdge   `json:"edges"`
	Policies   []PMapperPolicy `json:"policies,omitempty"`

	// In-memory only (not persisted)
	dirGraph  graph.Graph[string, string] `json:"-"`
	adminARNs []string                    `json:"-"`
}

// PrivescPath represents a complete escalation path from source to an admin target.
type PrivescPath struct {
	Source string
	Target string
	Steps  []PrivescStep
}

// PrivescStep represents one hop in an escalation chain.
type PrivescStep struct {
	Source         string
	Destination    string
	ShortReason    string
	Reason         string
	ModuleIDs      []string              // pathrunner modules that can exploit this step
	SelfEscalation *SelfEscalationResult // non-nil for self-escalation steps (Source == Destination)
}

// GraphStatus contains metadata about an imported graph for status display.
type GraphStatus struct {
	AccountID    string
	ImportedAt   time.Time
	NodeCount    int
	AdminCount   int
	EdgeCount    int
	EdgePatterns []EdgePatternStatus
}

// EdgePatternStatus shows coverage for a specific edge pattern.
type EdgePatternStatus struct {
	ShortReason    string
	ReasonFragment string
	Count          int
	ModuleIDs      []string
	HasModule      bool
}
