// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package pmapper

import (
	"github.com/DataDog/pathrunner/pkg/modules"
	"strings"
)

// EdgeMapping maps a PMapper edge pattern to pathrunner module IDs.
type EdgeMapping struct {
	ShortReason    string   // PMapper short_reason to match exactly
	ReasonContains string   // substring to match in PMapper reason field
	PathIDs        []string // pathfinding.cloud path IDs (= pathrunner module IDs)
}

// EdgeMappings defines the static mapping from PMapper edge patterns to pathrunner modules.
// Each mapping is derived from pathfinding.cloud's detectionTools.pmapper URLs which point
// to exact PMapper source code lines.
var EdgeMappings = []EdgeMapping{
	// Lambda edges (lambda_edges.py)
	{ShortReason: "Lambda", ReasonContains: "create a new function", PathIDs: []string{"lambda-001", "lambda-002", "lambda-005"}},
	{ShortReason: "Lambda", ReasonContains: "edit an existing function", PathIDs: []string{"lambda-003", "lambda-004"}},
	{ShortReason: "Lambda", ReasonContains: "use an existing function and modify", PathIDs: []string{"lambda-003", "lambda-004"}},

	// EC2 edges (ec2_edges.py)
	{ShortReason: "EC2", ReasonContains: "run an instance", PathIDs: []string{"ec2-001"}},

	// STS edges (sts_edges.py)
	{ShortReason: "AssumeRole", ReasonContains: "sts:AssumeRole", PathIDs: []string{"sts-001"}},

	// IAM edges (iam_edges.py)
	{ShortReason: "IAM", ReasonContains: "create access keys", PathIDs: []string{"iam-002", "iam-003"}},
	{ShortReason: "IAM", ReasonContains: "set the password", PathIDs: []string{"iam-004", "iam-006"}},
	{ShortReason: "IAM", ReasonContains: "update the trust document", PathIDs: []string{"iam-012"}},

	// CloudFormation edges (cloudformation_edges.py)
	{ShortReason: "Cloudformation", ReasonContains: "create a stack", PathIDs: []string{"cloudformation-001"}},
	{ShortReason: "Cloudformation", ReasonContains: "update the CloudFormation stack", PathIDs: []string{"cloudformation-002", "cloudformation-005"}},
	{ShortReason: "Cloudformation", ReasonContains: "create and execute a changeset", PathIDs: []string{"cloudformation-005"}},

	// CodeBuild edges (codebuild_edges.py)
	{ShortReason: "CodeBuild", ReasonContains: "existing project", PathIDs: []string{"codebuild-001", "codebuild-002"}},
	{ShortReason: "CodeBuild", ReasonContains: "create a project", PathIDs: []string{"codebuild-002", "codebuild-003"}},
	{ShortReason: "CodeBuild", ReasonContains: "update a project", PathIDs: []string{"codebuild-001", "codebuild-003", "codebuild-004"}},

	// SageMaker edges (sagemaker_edges.py)
	{ShortReason: "SageMaker", ReasonContains: "launch a notebook", PathIDs: []string{"sagemaker-001", "sagemaker-002", "sagemaker-003"}},
	{ShortReason: "SageMaker", ReasonContains: "create a training job", PathIDs: []string{"sagemaker-001", "sagemaker-002", "sagemaker-003"}},
	{ShortReason: "SageMaker", ReasonContains: "create a processing job", PathIDs: []string{"sagemaker-001", "sagemaker-002", "sagemaker-003"}},

	// SSM edges (ssm_edges.py)
	{ShortReason: "SSM", ReasonContains: "SendCommand", PathIDs: []string{"ssm-001"}},
	{ShortReason: "SSM", ReasonContains: "StartSession", PathIDs: []string{"ssm-001", "ssm-002"}},
}

// ResolveModules finds pathrunner module IDs that can exploit a given PMapper edge.
// Matches short_reason exactly and reason as a case-insensitive substring,
// then filters against the live module registry to only return registered modules.
func ResolveModules(edge PMapperEdge) []string {
	var allMatched []string
	seen := make(map[string]bool)

	for _, mapping := range EdgeMappings {
		if edge.ShortReason != mapping.ShortReason {
			continue
		}
		if !strings.Contains(strings.ToLower(edge.Reason), strings.ToLower(mapping.ReasonContains)) {
			continue
		}
		for _, pathID := range mapping.PathIDs {
			if !seen[pathID] {
				seen[pathID] = true
				allMatched = append(allMatched, pathID)
			}
		}
	}

	// Filter to only registered modules
	var registered []string
	for _, id := range allMatched {
		if _, err := modules.LoadModule(id); err == nil {
			registered = append(registered, id)
		}
	}

	return registered
}

// ResolveModulesAll finds all pathrunner module IDs (registered or not) for an edge.
func ResolveModulesAll(edge PMapperEdge) []string {
	var allMatched []string
	seen := make(map[string]bool)

	for _, mapping := range EdgeMappings {
		if edge.ShortReason != mapping.ShortReason {
			continue
		}
		if !strings.Contains(strings.ToLower(edge.Reason), strings.ToLower(mapping.ReasonContains)) {
			continue
		}
		for _, pathID := range mapping.PathIDs {
			if !seen[pathID] {
				seen[pathID] = true
				allMatched = append(allMatched, pathID)
			}
		}
	}

	return allMatched
}
