// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"strings"
	"testing"
	"time"

	"github.com/DataDog/pathrunner/pkg/report"
)

func sampleReportData() report.ReportData {
	return report.ReportData{
		WorkspaceName: "test-workspace",
		GeneratedAt:   time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Created: []report.Resource{
			{
				Type:          "lambda:function",
				Name:          "pathrunner-test-fn",
				ARN:           "arn:aws:lambda:us-east-1:123456789012:function:pathrunner-test-fn",
				Region:        "us-east-1",
				ModuleID:      "lambda-001",
				CleanupMethod: "delete the Lambda function",
				Created:       "2026-01-15 10:00:00",
				Metadata:      map[string]string{},
			},
		},
		Modified: []report.Resource{
			{
				Type:          "iam:attached-policy",
				Name:          "test-user",
				Region:        "us-east-1",
				ModuleID:      "iam-001",
				CleanupMethod: "detach the policy",
				Metadata: map[string]string{
					"principal_type": "user",
					"principal_name": "test-user",
					"policy_arn":     "arn:aws:iam::123456789012:policy/AdminPolicy",
				},
			},
		},
		Events: []report.Event{
			{
				Timestamp:   "2026-01-15 10:00:01",
				ModuleID:    "lambda-001",
				Service:     "lambda",
				Operation:   "CreateFunction",
				Region:      "us-east-1",
				Principal:   "arn:aws:iam::123456789012:user/attacker",
				Description: "created exploit Lambda function",
			},
		},
	}
}

// --- Markdown tests ---

func TestRenderMarkdown_basicReport(t *testing.T) {
	data := sampleReportData()
	md := report.RenderMarkdown(data)

	checks := []string{
		"# Pathrunner Workspace Report",
		"test-workspace",
		"2026-01-15",
		"## Summary",
		"## Created Resources",
		"pathrunner-test-fn",
		"lambda:function",
		"arn:aws:lambda:us-east-1:123456789012:function:pathrunner-test-fn",
		// cleanup command now paired inline with the resource, not in a separate section
		"aws lambda delete-function",
		"## Modified Resources",
		"iam:attached-policy",
		"test-user (user)",
		"arn:aws:iam::123456789012:policy/AdminPolicy",
		"aws iam detach-user-policy",
		"## CloudTrail Events",
		"CreateFunction",
		"| Timestamp | Module | Service | Operation | Principal | Description |",
	}

	if strings.Contains(md, "## Manual Cleanup Commands") {
		t.Error("standalone Manual Cleanup Commands section should no longer exist; commands are paired with resources")
	}

	for _, want := range checks {
		if !strings.Contains(md, want) {
			t.Errorf("expected Markdown to contain %q", want)
		}
	}
}

func TestRenderMarkdown_emptyEvents(t *testing.T) {
	data := sampleReportData()
	data.Events = nil
	md := report.RenderMarkdown(data)

	if strings.Contains(md, "## CloudTrail Events") {
		t.Error("CloudTrail section should be absent when there are no events")
	}
}

func TestRenderMarkdown_moduleFilter(t *testing.T) {
	data := sampleReportData()
	data.ModuleFilter = "lambda-001"
	md := report.RenderMarkdown(data)

	if !strings.Contains(md, "module_filter") {
		t.Error("expected frontmatter to include module_filter when set")
	}
	if !strings.Contains(md, "lambda-001") {
		t.Error("expected module filter value to appear in Markdown")
	}
}

func TestRenderMarkdown_emptyCreated(t *testing.T) {
	data := sampleReportData()
	data.Created = nil
	md := report.RenderMarkdown(data)

	if strings.Contains(md, "## Created Resources") {
		t.Error("Created Resources section should be absent when no created resources")
	}
	// Modified section should still appear
	if !strings.Contains(md, "## Modified Resources") {
		t.Error("Modified Resources section should still appear")
	}
}

func TestRenderMarkdown_pipeEscaping(t *testing.T) {
	data := sampleReportData()
	// Pipe character in a description would break the Markdown table if unescaped.
	data.Events[0].Description = "foo | bar | baz"
	md := report.RenderMarkdown(data)

	if strings.Contains(md, "foo | bar | baz") {
		t.Error("raw pipe in table cell must be escaped as \\|")
	}
	if !strings.Contains(md, "foo \\| bar \\| baz") {
		t.Error("expected escaped pipe characters in CloudTrail table")
	}
}

// --- HTML tests ---

func TestRenderHTML_basicReport(t *testing.T) {
	data := sampleReportData()
	html, err := report.RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	checks := []string{
		"<!DOCTYPE html>",
		"test-workspace",
		"pathrunner-test-fn",
		"lambda:function",
		"arn:aws:lambda:us-east-1:123456789012:function:pathrunner-test-fn",
		"iam:attached-policy",
		"CreateFunction",
		"aws lambda delete-function",
	}

	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Errorf("expected HTML to contain %q", want)
		}
	}
}

func TestRenderHTML_escaping(t *testing.T) {
	data := sampleReportData()
	// Inject a script tag — html/template must escape it.
	data.Created[0].Name = "<script>alert('xss')</script>"
	data.Events[0].Description = "<img src=x onerror=alert(1)>"

	html, err := report.RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	// Raw tags must not appear in the output.
	if strings.Contains(html, "<script>alert") {
		t.Error("HTML must escape <script> in resource names")
	}
	if strings.Contains(html, "<img src=x") {
		t.Error("HTML must escape <img> in event descriptions")
	}
	// Escaped versions should appear.
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected HTML-escaped &lt;script&gt; in output")
	}
}

func TestRenderHTML_noEvents(t *testing.T) {
	data := sampleReportData()
	data.Events = nil
	html, err := report.RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML returned error: %v", err)
	}

	// The events table should not appear when there are no events.
	// (The stat tile still says "CloudTrail Events" with a count of 0.)
	if strings.Contains(html, `<table class="events"`) {
		t.Error("events table should be absent when there are no events")
	}
	if strings.Contains(html, "blue team detection reference") {
		t.Error("events section heading should be absent when there are no events")
	}
}

// --- CleanupCommand tests ---

func TestCleanupCommand_lambdaFunction(t *testing.T) {
	res := report.Resource{
		Type:   "lambda:function",
		Name:   "my-fn",
		Region: "us-west-2",
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws lambda delete-function") {
		t.Errorf("unexpected cleanup command: %s", cmd)
	}
	if !strings.Contains(cmd, "us-west-2") {
		t.Errorf("expected region in command: %s", cmd)
	}
}

func TestCleanupCommand_iamDetachUserPolicy(t *testing.T) {
	res := report.Resource{
		Type: "iam:attached-policy",
		Metadata: map[string]string{
			"principal_type": "user",
			"principal_name": "alice",
			"policy_arn":     "arn:aws:iam::123:policy/Foo",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "detach-user-policy") {
		t.Errorf("expected detach-user-policy, got: %s", cmd)
	}
	if !strings.Contains(cmd, "alice") {
		t.Errorf("expected principal name, got: %s", cmd)
	}
}

func TestCleanupCommand_batchJobDefinition(t *testing.T) {
	res := report.Resource{
		Type:   "batch:job-definition",
		Name:   "pathrunner-batch001-1790215595",
		ARN:    "arn:aws:batch:us-east-1:123456789012:job-definition/pathrunner-batch001-1790215595:1",
		Region: "us-east-1",
		Metadata: map[string]string{
			"job_definition_arn": "arn:aws:batch:us-east-1:123456789012:job-definition/pathrunner-batch001-1790215595:1",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws batch deregister-job-definition") {
		t.Errorf("expected deregister-job-definition, got: %s", cmd)
	}
	if strings.Contains(cmd, "manual cleanup required") {
		t.Errorf("batch:job-definition should not fall through to default, got: %s", cmd)
	}
}

func TestCleanupCommand_batchJobQueue(t *testing.T) {
	res := report.Resource{
		Type:   "batch:job-queue",
		Name:   "pathrunner-batch003-jq",
		Region: "us-east-1",
		Metadata: map[string]string{
			"job_queue_name": "pathrunner-batch003-jq",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "update-job-queue") || !strings.Contains(cmd, "DISABLED") {
		t.Errorf("expected disable step in job queue cleanup, got: %s", cmd)
	}
	if !strings.Contains(cmd, "delete-job-queue") {
		t.Errorf("expected delete-job-queue, got: %s", cmd)
	}
}

func TestCleanupCommand_batchComputeEnvironment(t *testing.T) {
	res := report.Resource{
		Type:   "batch:compute-environment",
		Name:   "pathrunner-batch003-ce",
		Region: "us-east-1",
		Metadata: map[string]string{
			"compute_environment_name": "pathrunner-batch003-ce",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "update-compute-environment") || !strings.Contains(cmd, "DISABLED") {
		t.Errorf("expected disable step in compute environment cleanup, got: %s", cmd)
	}
	if !strings.Contains(cmd, "delete-compute-environment") {
		t.Errorf("expected delete-compute-environment, got: %s", cmd)
	}
}

func TestCleanupCommand_unknownType(t *testing.T) {
	res := report.Resource{
		Type: "unknown:thing",
		Name: "foo",
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "manual cleanup required") {
		t.Errorf("expected fallback comment for unknown type, got: %s", cmd)
	}
}

func TestCleanupCommand_apprunnerService(t *testing.T) {
	res := report.Resource{
		Type:   "apprunner:service",
		Name:   "pathrunner-svc",
		ARN:    "arn:aws:apprunner:us-east-1:123:service/pathrunner-svc/abc",
		Region: "us-east-1",
		Metadata: map[string]string{
			"service_arn": "arn:aws:apprunner:us-east-1:123:service/pathrunner-svc/abc",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws apprunner delete-service") {
		t.Errorf("expected apprunner delete-service, got: %s", cmd)
	}
	if !strings.Contains(cmd, "arn:aws:apprunner") {
		t.Errorf("expected service ARN in command, got: %s", cmd)
	}
}

func TestCleanupCommand_bedrockAgentRuntime(t *testing.T) {
	res := report.Resource{
		Type:   "bedrock-agentcore:agent-runtime",
		Name:   "pathrunner-runtime",
		Region: "us-east-1",
		Metadata: map[string]string{
			"runtime_id": "rt-12345",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "delete-agent-runtime") {
		t.Errorf("expected delete-agent-runtime, got: %s", cmd)
	}
	if !strings.Contains(cmd, "rt-12345") {
		t.Errorf("expected runtime_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_cloudformationStack(t *testing.T) {
	res := report.Resource{
		Type:   "cloudformation:stack",
		Name:   "pathrunner-cfn-stack",
		Region: "us-east-1",
		Metadata: map[string]string{
			"stack_name": "pathrunner-cfn-stack",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws cloudformation delete-stack") {
		t.Errorf("expected cloudformation delete-stack, got: %s", cmd)
	}
	if !strings.Contains(cmd, "pathrunner-cfn-stack") {
		t.Errorf("expected stack name in command, got: %s", cmd)
	}
}

func TestCleanupCommand_cloudformationStackset(t *testing.T) {
	res := report.Resource{
		Type:   "cloudformation:stackset",
		Name:   "pathrunner-stackset",
		Region: "us-east-1",
		Metadata: map[string]string{
			"stackset_name": "pathrunner-stackset",
			"account_id":    "123456789012",
			"target_region": "us-east-1",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "delete-stack-instances") {
		t.Errorf("expected delete-stack-instances, got: %s", cmd)
	}
	if !strings.Contains(cmd, "delete-stack-set") {
		t.Errorf("expected delete-stack-set, got: %s", cmd)
	}
}

func TestCleanupCommand_codebuildProject(t *testing.T) {
	res := report.Resource{
		Type:   "codebuild:project",
		Name:   "pathrunner-build",
		Region: "us-east-1",
		Metadata: map[string]string{
			"project_name": "pathrunner-build",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws codebuild delete-project") {
		t.Errorf("expected codebuild delete-project, got: %s", cmd)
	}
	if !strings.Contains(cmd, "pathrunner-build") {
		t.Errorf("expected project name in command, got: %s", cmd)
	}
}

func TestCleanupCommand_ec2LaunchTemplateVersion(t *testing.T) {
	res := report.Resource{
		Type:   "ec2:launch-template-version",
		Name:   "lt-12345/v3",
		Region: "us-east-1",
		Metadata: map[string]string{
			"template_id":    "lt-12345",
			"version_number": "3",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "delete-launch-template-versions") {
		t.Errorf("expected delete-launch-template-versions, got: %s", cmd)
	}
	if !strings.Contains(cmd, "lt-12345") {
		t.Errorf("expected template_id in command, got: %s", cmd)
	}
	if !strings.Contains(cmd, "3") {
		t.Errorf("expected version_number in command, got: %s", cmd)
	}
}

func TestCleanupCommand_ec2LaunchTemplateDefault(t *testing.T) {
	res := report.Resource{
		Type:   "ec2:launch-template-default",
		Name:   "lt-12345/default",
		Region: "us-east-1",
		Metadata: map[string]string{
			"template_id":      "lt-12345",
			"original_version": "1",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "modify-launch-template") {
		t.Errorf("expected modify-launch-template, got: %s", cmd)
	}
	if !strings.Contains(cmd, "--default-version 1") {
		t.Errorf("expected original version in command, got: %s", cmd)
	}
}

func TestCleanupCommand_ecsTaskDefinition(t *testing.T) {
	res := report.Resource{
		Type:   "ecs:task-definition",
		Name:   "pathrunner-task",
		ARN:    "arn:aws:ecs:us-east-1:123:task-definition/pathrunner-task:5",
		Region: "us-east-1",
		Metadata: map[string]string{
			"revision": "5",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "deregister-task-definition") {
		t.Errorf("expected deregister-task-definition, got: %s", cmd)
	}
	if !strings.Contains(cmd, "delete-task-definitions") {
		t.Errorf("expected delete-task-definitions, got: %s", cmd)
	}
}

func TestCleanupCommand_ecsTask(t *testing.T) {
	res := report.Resource{
		Type:   "ecs:task",
		Name:   "arn:aws:ecs:us-east-1:123:task/mycluster/abc123",
		ARN:    "arn:aws:ecs:us-east-1:123:task/mycluster/abc123",
		Region: "us-east-1",
		Metadata: map[string]string{
			"cluster": "mycluster",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws ecs stop-task") {
		t.Errorf("expected ecs stop-task, got: %s", cmd)
	}
	if !strings.Contains(cmd, "mycluster") {
		t.Errorf("expected cluster name in command, got: %s", cmd)
	}
}

func TestCleanupCommand_emrCluster(t *testing.T) {
	res := report.Resource{
		Type:   "emr:cluster",
		Name:   "pathrunner-emr",
		Region: "us-east-1",
		Metadata: map[string]string{
			"cluster_id": "j-ABC123",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws emr terminate-clusters") {
		t.Errorf("expected emr terminate-clusters, got: %s", cmd)
	}
	if !strings.Contains(cmd, "j-ABC123") {
		t.Errorf("expected cluster_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_emrServerlessApplication(t *testing.T) {
	res := report.Resource{
		Type:   "emrserverless:application",
		Name:   "pathrunner-app",
		Region: "us-east-1",
		Metadata: map[string]string{
			"application_id": "00app123",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws emr-serverless delete-application") {
		t.Errorf("expected emr-serverless delete-application, got: %s", cmd)
	}
	if !strings.Contains(cmd, "00app123") {
		t.Errorf("expected application_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_gameliftBuild(t *testing.T) {
	res := report.Resource{
		Type:   "gamelift:build",
		Name:   "pathrunner-build",
		Region: "us-east-1",
		Metadata: map[string]string{
			"build_id": "build-abc123",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws gamelift delete-build") {
		t.Errorf("expected gamelift delete-build, got: %s", cmd)
	}
	if !strings.Contains(cmd, "build-abc123") {
		t.Errorf("expected build_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_gameliftFleet(t *testing.T) {
	res := report.Resource{
		Type:   "gamelift:fleet",
		Name:   "pathrunner-fleet",
		Region: "us-east-1",
		Metadata: map[string]string{
			"fleet_id": "fleet-abc123",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws gamelift delete-fleet") {
		t.Errorf("expected gamelift delete-fleet, got: %s", cmd)
	}
	if !strings.Contains(cmd, "fleet-abc123") {
		t.Errorf("expected fleet_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_omicsWorkflow(t *testing.T) {
	res := report.Resource{
		Type:   "omics:workflow",
		Name:   "pathrunner-workflow",
		Region: "us-east-1",
		Metadata: map[string]string{
			"workflow_id": "1234567",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws omics delete-workflow") {
		t.Errorf("expected omics delete-workflow, got: %s", cmd)
	}
	if !strings.Contains(cmd, "1234567") {
		t.Errorf("expected workflow_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_omicsRun(t *testing.T) {
	res := report.Resource{
		Type:   "omics:run",
		Name:   "pathrunner-run",
		Region: "us-east-1",
		Metadata: map[string]string{
			"run_id": "7654321",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws omics cancel-run") {
		t.Errorf("expected omics cancel-run, got: %s", cmd)
	}
	if !strings.Contains(cmd, "aws omics delete-run") {
		t.Errorf("expected omics delete-run, got: %s", cmd)
	}
	if !strings.Contains(cmd, "7654321") {
		t.Errorf("expected run_id in command, got: %s", cmd)
	}
}

func TestCleanupCommand_ssmAutomationDocument(t *testing.T) {
	res := report.Resource{
		Type:   "ssm:automation-document",
		Name:   "pathrunner-doc",
		Region: "us-east-1",
		Metadata: map[string]string{
			"document_name": "pathrunner-ssm-001-doc",
		},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws ssm delete-document") {
		t.Errorf("expected ssm delete-document, got: %s", cmd)
	}
	if !strings.Contains(cmd, "pathrunner-ssm-001-doc") {
		t.Errorf("expected document_name in command, got: %s", cmd)
	}
}

func TestCleanupCommand_braketJob(t *testing.T) {
	res := report.Resource{
		Type:   "braket:job",
		Name:   "pathrunner-job",
		ARN:    "arn:aws:braket:us-east-1:123:job/pathrunner-job",
		Region: "us-east-1",
		Metadata: map[string]string{},
	}
	cmd := report.CleanupCommand(res)
	if !strings.Contains(cmd, "aws braket cancel-job") {
		t.Errorf("expected braket cancel-job, got: %s", cmd)
	}
	if !strings.Contains(cmd, "arn:aws:braket") {
		t.Errorf("expected job ARN in command, got: %s", cmd)
	}
}
