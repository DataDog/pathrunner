// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

// Package report renders workspace reports in different file formats (HTML, Markdown).
package report

import "time"

// ReportData holds all information needed to render a workspace report in any format.
type ReportData struct {
	WorkspaceName string
	GeneratedAt   time.Time
	ModuleFilter  string // empty when no filter is applied
	Created       []Resource
	Modified      []Resource
	Events        []Event
}

// Resource represents a created or modified AWS resource tracked during exploitation.
type Resource struct {
	Type          string
	Name          string
	ARN           string
	Region        string
	ModuleID      string
	CleanupMethod string
	Created       string
	Metadata      map[string]string
}

// Event represents a recorded CloudTrail API call for blue team detection reference.
type Event struct {
	Timestamp   string
	ModuleID    string
	Service     string
	Operation   string
	Region      string
	Principal   string
	Description string
}
