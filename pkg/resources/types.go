package resources

import "time"

// Resource is the normalized representation of any AWS resource from cloudfox output.
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
	Properties   map[string]string `json:"properties,omitempty"`
}

// ImportRecord tracks a single cloudfox import (one run, one identity, one source dir).
type ImportRecord struct {
	SourceDir   string    `json:"source_dir"`
	Profile     string    `json:"profile,omitempty"`
	ImportedAt  time.Time `json:"imported_at"`
	FilesParsed []string  `json:"files_parsed"`
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
