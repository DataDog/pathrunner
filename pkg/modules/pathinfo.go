// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package modules

import "fmt"

// PathInfo contains structured metadata for an attack path, aligned with
// the pathfinding.cloud schema. Modules populate this via Go struct literals.
type PathInfo struct {
	// Cross-project identifier (e.g., "ec2-001", "lambda-001")
	ID string
	// Permission-based name (e.g., "iam:PassRole + ec2:RunInstances")
	Name string
	// Category: "self-escalation", "principal-access", "new-passrole", "existing-passrole", "credential-access"
	Category string
	// AWS services involved, lowercase (e.g., ["iam", "ec2"])
	Services []string
	// Human-readable description of the attack path
	Description string
	// IAM permissions required and optional
	Permissions PermissionSet
	// Prerequisites for the attack path
	Prerequisites Prerequisites
	// External references (blog posts, docs, etc.)
	References []Reference
	// Related path IDs (e.g., ["ec2-002", "lambda-002"])
	RelatedPaths []string
	// MITRE ATT&CK mappings
	MITRE *MITREMapping
	// Pathrunner-specific fields
	Author  string
	Aliases []string // Alternative names (e.g., ["lambda-passrole", "exploit/lambda_passrole"])
}

// PermissionSet groups required and additional IAM permissions.
type PermissionSet struct {
	Required   []Permission
	Additional []Permission
}

// Permission represents a single IAM action with optional description.
type Permission struct {
	Permission  string // IAM action (e.g., "iam:PassRole")
	Description string // Resource constraints or notes
}

// Prerequisites describes what an administrator or lateral mover needs
// to have set up before this path is exploitable.
type Prerequisites struct {
	Admin   []string
	Lateral []string
}

// Reference is an external link (blog post, documentation, etc.).
type Reference struct {
	Title string
	URL   string
}

// MITREMapping holds MITRE ATT&CK tactic and technique references.
type MITREMapping struct {
	Tactics    []string
	Techniques []string
}

// PathfindingCloudURL returns the pathfinding.cloud URL for this path.
func (p PathInfo) PathfindingCloudURL() string {
	if p.ID == "" {
		return ""
	}
	return fmt.Sprintf("https://pathfinding.cloud/paths/%s", p.ID)
}
