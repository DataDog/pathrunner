// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package resources

import "time"

// Resource is the normalized representation of any AWS resource.
// Resources come from cloudfox imports or live module discovery API calls.
type Resource struct {
	AccountID    string            `json:"account_id"`
	Name         string            `json:"name"`
	ARN          string            `json:"arn,omitempty"`
	Service      string            `json:"service"`
	ResourceType string            `json:"resource_type"`
	Region       string            `json:"region,omitempty"`
	Role         string            `json:"role,omitempty"`
	IsAdmin      string            `json:"is_admin,omitempty"`
	CanPrivEsc   string            `json:"can_privesc,omitempty"`
	Public       string            `json:"public,omitempty"`
	Source       string            `json:"source,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// ImportRecord tracks a single import event (cloudfox import or discovery API call).
type ImportRecord struct {
	SourceType  string    `json:"source_type"`
	SourceDir   string    `json:"source_dir,omitempty"`
	SourceInfo  string    `json:"source_info,omitempty"`
	Profile     string    `json:"profile,omitempty"`
	ImportedAt  time.Time `json:"imported_at"`
	FilesParsed []string  `json:"files_parsed,omitempty"`
}

// AccountResources holds all resources for one AWS account, merged across multiple imports.
type AccountResources struct {
	AccountID string         `json:"account_id"`
	Imports   []ImportRecord `json:"imports"`
	Resources []Resource     `json:"resources"`
}

// ResourceSummary is a service+region count for summary display.
type ResourceSummary struct {
	Service string
	Region  string
	Count   int
}

// ImportStatus contains metadata for status display.
type ImportStatus struct {
	AccountID     string
	Imports       []ImportRecord
	ResourceCount int
	ServiceCounts map[string]int
}

// DiscoverySuggestion is a resource-store suggestion for a module option value.
type DiscoverySuggestion struct {
	Value  string
	Label  string
	Source string
}

// OptionResourceMapping defines how a module option name maps to resource queries.
type OptionResourceMapping struct {
	Service      string
	ResourceType string
	ReturnField  string // "arn" or "name"
}
