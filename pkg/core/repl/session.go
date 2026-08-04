// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package repl

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/ui"

	"github.com/DataDog/pathrunner/pkg/attacker"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/omics"
	omicstypes "github.com/aws/aws-sdk-go-v2/service/omics/types"
)

// cmdWorkspace handles workspace management commands
func (r *REPL) cmdWorkspace(repl *REPL, args []string) error {
	// Default to list if no subcommand provided
	if len(args) == 0 {
		return r.sessionList()
	}

	switch args[0] {
	case "create":
		return r.sessionCreate(args[1:])
	case "list":
		return r.sessionList()
	case "switch":
		return r.sessionSwitch(args[1:])
	case "save":
		return r.sessionSave()
	case "delete":
		return r.sessionDelete(args[1:])
	case "cleanup":
		return r.sessionCleanup(args[1:])
	case "report":
		return r.sessionReport(args[1:])
	case "history":
		return r.sessionHistory(args[1:])
	case "help":
		return r.showWorkspaceHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown workspace subcommand: %s. Use 'workspace help' for available commands", args[0]))
	}
}

// sessionCreate creates a new session
func (r *REPL) sessionCreate(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWorkspaceCreateHelp()
	}

	if len(args) == 0 {
		return NewInvalidArgumentsError("workspace create requires a workspace name")
	}

	// Save current workspace state before creating new one
	r.saveCurrentState()
	current := r.sessionManager.GetCurrentSession()
	if current != nil {
		_ = r.sessionManager.SaveSession(current)
	}

	sessionName := args[0]
	if err := r.sessionManager.CreateSession(sessionName); err != nil {
		return NewExecutionError("failed to create workspace", err)
	}

	// Automatically switch to the newly created workspace
	if err := r.sessionManager.SwitchSession(sessionName); err != nil {
		return NewExecutionError("failed to switch to new workspace", err)
	}

	// Load clean state from new session (no identities, no module)
	r.loadSessionState()
	r.updateCompletion()
	r.UpdatePrompt()

	fmt.Printf("Created and switched to workspace '%s'\n", sessionName)
	return nil
}

// sessionList lists all sessions
func (r *REPL) sessionList() error {
	sessions, err := r.sessionManager.ListSessions()
	if err != nil {
		return NewExecutionError("failed to list workspaces", err)
	}

	if len(sessions) == 0 {
		fmt.Println("No workspaces found.")
		return nil
	}

	currentName := r.sessionManager.GetCurrentSession().GetName()

	rows := make([][]string, 0, len(sessions))
	for _, session := range sessions {
		current := ""
		if session.GetName() == currentName {
			current = "●"
		}

		rows = append(rows, []string{
			session.GetName(),
			session.GetCreated(),
			session.GetLastAccessed(),
			strconv.Itoa(session.GetCommandCount()),
			strconv.Itoa(session.GetResourceCount()),
			current,
		})
	}

	fmt.Println("Available workspaces:")
	fmt.Println()
	ui.Table([]string{"Name", "Created", "Last Accessed", "Commands", "Resources", "Current"}, rows)
	fmt.Println()

	return nil
}

// sessionSwitch switches to a different session
func (r *REPL) sessionSwitch(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWorkspaceSwitchHelp()
	}

	if len(args) == 0 {
		return NewInvalidArgumentsError("workspace switch requires workspace name")
	}

	sessionName := args[0]
	if err := r.sessionManager.SwitchSession(sessionName); err != nil {
		return NewExecutionError("failed to switch workspace", err)
	}

	// Reload state from new session
	r.loadSessionState()
	r.updateCompletion()
	r.UpdatePrompt()

	fmt.Printf("Switched to workspace: %s\n", sessionName)
	return nil
}

// sessionSave saves the current session
func (r *REPL) sessionSave() error {
	r.saveCurrentState()

	current := r.sessionManager.GetCurrentSession()
	if err := r.sessionManager.SaveSession(current); err != nil {
		return NewExecutionError("failed to save workspace", err)
	}

	fmt.Printf("Saved workspace: %s\n", current.GetName())
	return nil
}

// sessionDelete deletes a session
func (r *REPL) sessionDelete(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWorkspaceDeleteHelp()
	}

	if len(args) == 0 {
		return NewInvalidArgumentsError("workspace delete requires workspace name")
	}

	sessionName := args[0]
	if err := r.sessionManager.DeleteSession(sessionName); err != nil {
		return NewExecutionError("failed to delete workspace", err)
	}

	fmt.Printf("Deleted workspace: %s\n", sessionName)
	return nil
}

// sessionCleanup cleans up AWS resources created in the current session
func (r *REPL) sessionCleanup(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWorkspaceCleanupHelp()
	}

	// Parse flags
	cleanAll := false
	autoYes := false
	moduleFilter := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all":
			cleanAll = true
		case "--yes", "-y":
			autoYes = true
		case "--module":
			if i+1 < len(args) {
				i++
				moduleFilter = args[i]
			} else {
				return NewInvalidArgumentsError("--module requires a module ID")
			}
		default:
			return NewInvalidArgumentsError(fmt.Sprintf("unknown flag: %s", args[i]))
		}
	}

	resources := r.sessionManager.GetCreatedResources()

	// Filter by module ID if specified
	if moduleFilter != "" {
		var filtered []CreatedResource
		for _, res := range resources {
			if res.ModuleID == moduleFilter {
				filtered = append(filtered, res)
			}
		}
		resources = filtered
	}

	if len(resources) == 0 {
		if moduleFilter != "" {
			fmt.Printf("No resources to clean up for module '%s' in current workspace.\n", moduleFilter)
		} else {
			fmt.Println("No resources to clean up in current workspace.")
		}
		return nil
	}

	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	var resourcesToCleanup []CreatedResource

	if cleanAll {
		// Non-interactive: clean up all (optionally filtered) resources
		resourcesToCleanup = resources
	} else {
		// Interactive: show multi-select prompt
		options := make([]string, 0, len(resources)+1)
		resourceMap := make(map[int]CreatedResource)

		// Add "All resources" option
		allOption := fmt.Sprintf("All resources (%d)", len(resources))
		options = append(options, allOption)

		// Add individual resources
		for i, resource := range resources {
			regionInfo := ""
			if resource.Region != "" {
				regionInfo = fmt.Sprintf(" [%s]", resource.Region)
			}
			moduleInfo := ""
			if resource.ModuleID != "" {
				moduleInfo = fmt.Sprintf(" (%s)", resource.ModuleID)
			}
			option := fmt.Sprintf("%s: %s%s%s", resource.Type, resource.Name, regionInfo, moduleInfo)
			options = append(options, option)
			resourceMap[i+1] = resource // +1 because index 0 is "All resources"
		}

		// Show multi-select prompt
		selectedIndices, err := ui.MultiSelect("Select resources to clean up:", options)
		if err != nil {
			return fmt.Errorf("selection cancelled")
		}

		if len(selectedIndices) == 0 {
			fmt.Println("No resources selected for cleanup.")
			return nil
		}

		// Check if "All resources" was selected (index 0)
		selectAll := false
		for _, idx := range selectedIndices {
			if idx == 0 {
				selectAll = true
				break
			}
		}

		if selectAll {
			resourcesToCleanup = resources
		} else {
			for _, idx := range selectedIndices {
				if resource, exists := resourceMap[idx]; exists {
					resourcesToCleanup = append(resourcesToCleanup, resource)
				}
			}
		}
	}

	// Separate resources by account context so we use the right identity for each
	attackerIdentity := r.identityManager.GetAttackerIdentity()

	// Clean up selected resources
	fmt.Printf("\nCleaning up %d resources...\n", len(resourcesToCleanup))
	fmt.Println()

	var cleaned, gone, failed int
	permissionFailures := 0
	quit := false
	for _, resource := range resourcesToCleanup {
		if quit {
			break
		}

		regionInfo := ""
		if resource.Region != "" {
			regionInfo = fmt.Sprintf(" [%s]", resource.Region)
		}
		fmt.Printf("Cleaning up %s: %s%s...", resource.Type, resource.Name, regionInfo)

		// Use the attacker identity for attacker-side resources (e.g., S3 code buckets)
		cleanupIdentity := identity
		if resource.AccountContext == "attacker" {
			if attackerIdentity == nil {
				fmt.Printf(" FAILED (attacker identity required — use 'attacker set profile <name>' first)\n")
				failed++
				continue
			}
			cleanupIdentity = attackerIdentity
		}

		if err := r.cleanupResource(resource, cleanupIdentity); err != nil {
			if isNotFoundError(err) {
				// Resource no longer exists in AWS. Remove it from tracking rather
				// than leaving it as a permanent failure in the workspace state.
				fmt.Printf(" NOT FOUND\n")
				fmt.Printf("    AWS error: %v\n", err)
				removeIt := autoYes
				if !autoYes && ui.IsTTY() {
					choice, promptErr := ui.Select("Remove from workspace tracking?", []string{
						"Yes — remove this entry",
						"Yes to all — remove all not-found resources without asking",
						"No — keep in workspace",
						"Quit — stop cleanup",
					})
					if promptErr == nil {
						switch choice {
						case 0:
							removeIt = true
						case 1:
							removeIt = true
							autoYes = true
						case 2:
							removeIt = false
						case 3:
							quit = true
						}
					}
				}
				if removeIt {
					r.sessionManager.RemoveCreatedResource(resource.Name)
					gone++
				} else if !quit {
					failed++
				}
			} else {
				fmt.Printf(" FAILED (%v)\n", err)
				failed++
				if isPermissionError(err) {
					permissionFailures++
				}
			}
		} else {
			fmt.Printf(" OK\n")
			cleaned++
			r.sessionManager.RemoveCreatedResource(resource.Name)
		}
	}

	fmt.Println()
	summary := fmt.Sprintf("Cleanup complete: %d cleaned", cleaned)
	if gone > 0 {
		summary += fmt.Sprintf(", %d removed from tracking (already gone)", gone)
	}
	if failed > 0 {
		summary += fmt.Sprintf(", %d failed", failed)
	}
	fmt.Println(summary)

	if permissionFailures > 0 {
		fmt.Println()
		fmt.Printf("Note: %d failure(s) appear to be permission-related.\n", permissionFailures)
		fmt.Println("The current identity may lack delete/detach permissions.")
		fmt.Println("Try switching to an identity with higher privileges:")
		fmt.Println("  identity add --profile <admin-profile>")
		fmt.Println("  identity switch <admin-identity>")
		fmt.Println("  workspace cleanup --all")
		fmt.Println()
		fmt.Println("Use 'workspace report' to generate a cleanup report you can hand off.")
	}

	if cleaned > 0 || gone > 0 {
		_ = r.sessionSave()
	}

	return nil
}

// isPermissionError checks if an error is likely an AWS permissions issue.
func isPermissionError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "AccessDenied") ||
		strings.Contains(msg, "UnauthorizedAccess") ||
		strings.Contains(msg, "is not authorized to perform") ||
		strings.Contains(msg, "AccessDeniedException")
}

// isNotFoundError checks if an error indicates the resource no longer exists in AWS.
// These are safe to remove from tracking — the resource was deleted outside pathrunner.
func isNotFoundError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "NotFound") ||
		strings.Contains(msg, "NoSuchEntity") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "ResourceNotFoundException") ||
		strings.Contains(msg, "InvalidInstanceID.NotFound") ||
		strings.Contains(msg, "NoSuchBucket") ||
		strings.Contains(msg, "ResourceNotFound")
}

// sessionReport generates a cleanup report for handoff to a client or admin.
func (r *REPL) sessionReport(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWorkspaceReportHelp()
	}

	resources := r.sessionManager.GetCreatedResources()
	if len(resources) == 0 {
		fmt.Println("No tracked resources in current workspace. Nothing to report.")
		return nil
	}

	// Parse optional --module filter
	moduleFilter := ""
	for i, arg := range args {
		if arg == "--module" && i+1 < len(args) {
			moduleFilter = args[i+1]
		}
	}

	if moduleFilter != "" {
		var filtered []CreatedResource
		for _, res := range resources {
			if res.ModuleID == moduleFilter {
				filtered = append(filtered, res)
			}
		}
		resources = filtered
		if len(resources) == 0 {
			fmt.Printf("No tracked resources for module '%s'.\n", moduleFilter)
			return nil
		}
	}

	current := r.sessionManager.GetCurrentSession()
	workspaceName := "unknown"
	if current != nil {
		workspaceName = current.GetName()
	}

	// Separate created vs modified resources
	var created, modified []CreatedResource
	for _, res := range resources {
		if isModificationResource(res) {
			modified = append(modified, res)
		} else {
			created = append(created, res)
		}
	}

	// Header
	ui.ReportHeader(workspaceName, time.Now().Format("2006-01-02 15:04:05 MST"), len(resources), len(created), len(modified))

	// Created resources
	if len(created) > 0 {
		ui.ReportSection("CREATED RESOURCES (delete to clean up)")
		for _, res := range created {
			fmt.Println()
			fmt.Printf("    Type:     %s\n", res.Type)
			fmt.Printf("    Name:     %s\n", res.Name)
			if res.ARN != "" {
				fmt.Printf("    ARN:      %s\n", res.ARN)
			}
			if res.Region != "" {
				fmt.Printf("    Region:   %s\n", res.Region)
			}
			if res.ModuleID != "" {
				fmt.Printf("    Module:   %s\n", res.ModuleID)
			}
			fmt.Printf("    Cleanup:  %s\n", res.CleanupMethod)
			if res.Created != "" {
				fmt.Printf("    Created:  %s\n", res.Created)
			}
		}
		fmt.Println()
	}

	// Modified resources
	if len(modified) > 0 {
		ui.ReportSection("MODIFIED RESOURCES (revert to clean up)")
		for _, res := range modified {
			fmt.Println()
			fmt.Printf("    Type:       %s\n", res.Type)
			if principalName, ok := res.Metadata["principal_name"]; ok {
				fmt.Printf("    Principal:  %s (%s)\n", principalName, res.Metadata["principal_type"])
			} else {
				fmt.Printf("    Name:       %s\n", res.Name)
			}
			if policyArn, ok := res.Metadata["policy_arn"]; ok {
				fmt.Printf("    Policy:     %s\n", policyArn)
			}
			if res.Region != "" {
				fmt.Printf("    Region:     %s\n", res.Region)
			}
			if res.ModuleID != "" {
				fmt.Printf("    Module:     %s\n", res.ModuleID)
			}
			fmt.Printf("    Reversal:   %s\n", res.CleanupMethod)
		}
		fmt.Println()
	}

	// Manual cleanup instructions
	ui.ReportSection("MANUAL CLEANUP COMMANDS")
	fmt.Println()
	for _, res := range created {
		printManualCleanupCommand(res)
	}
	for _, res := range modified {
		printManualCleanupCommand(res)
	}

	ui.ReportFooter()

	return nil
}

// isModificationResource returns true for resources that represent modifications
// to existing AWS resources (e.g., policy attachments) rather than new creations.
func isModificationResource(res CreatedResource) bool {
	return res.Type == "iam:attached-policy" || res.Type == "iam:policy-version" ||
		res.Type == "iam:inline-policy" || res.Type == "iam:group-membership" ||
		res.Type == "iam:trust-policy"
}

// printManualCleanupCommand prints the AWS CLI command to clean up a resource.
func printManualCleanupCommand(res CreatedResource) {
	region := res.Region
	if region == "" {
		region = "us-east-1"
	}

	switch res.Type {
	case "lambda:function":
		fmt.Printf("    aws lambda delete-function --function-name %s --region %s\n", res.Name, region)
	case "lambda:event-source-mapping":
		uuid := res.Metadata["uuid"]
		if uuid == "" {
			uuid = res.Name
		}
		fmt.Printf("    aws lambda delete-event-source-mapping --uuid %s --region %s\n", uuid, region)
	case "lambda:permission":
		funcName := res.Metadata["function_name"]
		stmtID := res.Metadata["statement_id"]
		fmt.Printf("    aws lambda remove-permission --function-name %s --statement-id %s --region %s\n", funcName, stmtID, region)
	case "ec2:instance":
		instanceID := res.Metadata["instance_id"]
		if instanceID == "" {
			instanceID = res.Name
		}
		fmt.Printf("    aws ec2 terminate-instances --instance-ids %s --region %s\n", instanceID, region)
	case "ec2:spot-instance-request":
		spotRequestID := res.Metadata["spot_request_id"]
		if spotRequestID == "" {
			spotRequestID = res.Name
		}
		fmt.Printf("    aws ec2 cancel-spot-instance-requests --spot-instance-request-ids %s --region %s\n", spotRequestID, region)
	case "iam:attached-policy":
		principalType := res.Metadata["principal_type"]
		principalName := res.Metadata["principal_name"]
		policyArn := res.Metadata["policy_arn"]
		switch principalType {
		case "role":
			fmt.Printf("    aws iam detach-role-policy --role-name %s --policy-arn %s\n", principalName, policyArn)
		case "group":
			fmt.Printf("    aws iam detach-group-policy --group-name %s --policy-arn %s\n", principalName, policyArn)
		default:
			fmt.Printf("    aws iam detach-user-policy --user-name %s --policy-arn %s\n", principalName, policyArn)
		}
	case "iam:inline-policy":
		principalType := res.Metadata["principal_type"]
		principalName := res.Metadata["principal_name"]
		policyName := res.Metadata["policy_name"]
		switch principalType {
		case "role":
			fmt.Printf("    aws iam delete-role-policy --role-name %s --policy-name %s\n", principalName, policyName)
		case "group":
			fmt.Printf("    aws iam delete-group-policy --group-name %s --policy-name %s\n", principalName, policyName)
		default:
			fmt.Printf("    aws iam delete-user-policy --user-name %s --policy-name %s\n", principalName, policyName)
		}
	case "iam:group-membership":
		userName := res.Metadata["user_name"]
		groupName := res.Metadata["group_name"]
		fmt.Printf("    aws iam remove-user-from-group --user-name %s --group-name %s\n", userName, groupName)
	case "iam:trust-policy":
		roleName := res.Metadata["role_name"]
		fmt.Printf("    aws iam update-assume-role-policy --role-name %s --policy-document '<original-trust-policy>'\n", roleName)
	case "iam:policy-version":
		policyArn := res.Metadata["policy_arn"]
		versionID := res.Metadata["version_id"]
		fmt.Printf("    aws iam delete-policy-version --policy-arn %s --version-id %s\n", policyArn, versionID)
	case "iam:access-key":
		username := res.Metadata["username"]
		accessKeyID := res.Metadata["access_key_id"]
		if accessKeyID == "" {
			accessKeyID = res.Name
		}
		fmt.Printf("    aws iam delete-access-key --user-name %s --access-key-id %s\n", username, accessKeyID)
	case "iam:login-profile":
		username := res.Metadata["username"]
		if username == "" {
			username = res.Name
		}
		fmt.Printf("    aws iam delete-login-profile --user-name %s\n", username)
	case "iam:role":
		fmt.Printf("    aws iam delete-role --role-name %s\n", res.Name)
	case "iam:user":
		fmt.Printf("    aws iam delete-user --user-name %s\n", res.Name)
	case "ecs:service":
		cluster := res.Metadata["cluster"]
		fmt.Printf("    aws ecs delete-service --cluster %s --service %s --force --region %s\n", cluster, res.Name, region)
	case "ecs:cluster":
		fmt.Printf("    aws ecs delete-cluster --cluster %s --region %s\n", res.Name, region)
	case "s3_bucket":
		fmt.Printf("    aws s3 rm s3://%s --recursive --region %s\n", res.Name, region)
		fmt.Printf("    aws s3api delete-bucket --bucket %s --region %s\n", res.Name, region)
	case "glue:dev-endpoint":
		fmt.Printf("    aws glue delete-dev-endpoint --endpoint-name %s --region %s\n", res.Name, region)
	case "glue:job":
		fmt.Printf("    aws glue delete-job --job-name %s --region %s\n", res.Name, region)
	case "glue:session":
		fmt.Printf("    aws glue stop-session --id %s --region %s\n", res.Name, region)
		fmt.Printf("    aws glue delete-session --id %s --region %s\n", res.Name, region)
	case "glue:trigger":
		fmt.Printf("    aws glue stop-trigger --name %s --region %s\n", res.Name, region)
		fmt.Printf("    aws glue delete-trigger --name %s --region %s\n", res.Name, region)
	case "imagebuilder:component":
		componentArn := res.Metadata["component_arn"]
		if componentArn == "" {
			componentArn = res.ARN
		}
		fmt.Printf("    aws imagebuilder delete-component --component-build-version-arn %s --region %s\n", componentArn, region)
	case "imagebuilder:recipe":
		recipeArn := res.Metadata["recipe_arn"]
		if recipeArn == "" {
			recipeArn = res.ARN
		}
		fmt.Printf("    aws imagebuilder delete-image-recipe --image-recipe-arn %s --region %s\n", recipeArn, region)
	case "imagebuilder:infra-config":
		infraArn := res.Metadata["infra_config_arn"]
		if infraArn == "" {
			infraArn = res.ARN
		}
		fmt.Printf("    aws imagebuilder delete-infrastructure-configuration --infrastructure-configuration-arn %s --region %s\n", infraArn, region)
	case "imagebuilder:image":
		imageArn := res.Metadata["image_build_arn"]
		if imageArn == "" {
			imageArn = res.ARN
		}
		fmt.Printf("    aws imagebuilder cancel-image-creation --image-build-version-arn %s --region %s 2>/dev/null || true\n", imageArn, region)
		fmt.Printf("    aws imagebuilder delete-image --image-build-version-arn %s --region %s\n", imageArn, region)
	case "kinesisanalyticsv2:application":
		createTimestamp := res.Metadata["create_timestamp"]
		fmt.Printf("    # First stop the application, then delete it using its original CreateTimestamp\n")
		fmt.Printf("    aws kinesisanalyticsv2 stop-application --application-name %s --force --region %s 2>/dev/null || true\n", res.Name, region)
		fmt.Printf("    aws kinesisanalyticsv2 delete-application --application-name %s --create-timestamp %s --region %s\n", res.Name, createTimestamp, region)
	case "local:file":
		path := res.Metadata["path"]
		if path == "" {
			path = res.Name
		}
		fmt.Printf("    rm -f %s\n", path)
	default:
		fmt.Printf("    # %s: %s (manual cleanup required)\n", res.Type, res.Name)
	}
}

// sessionHistory shows command history
func (r *REPL) sessionHistory(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWorkspaceHistoryHelp()
	}

	current := r.sessionManager.GetCurrentSession()

	limit := 20 // Default limit
	if len(args) > 0 {
		if l, err := strconv.Atoi(args[0]); err == nil && l > 0 {
			limit = l
		}
	}

	commandLog := current.GetCommandLog()
	totalCommands := len(commandLog)

	fmt.Printf("Command history for session '%s' (last %d commands):\n", current.GetName(), limit)
	fmt.Println()

	if totalCommands == 0 {
		fmt.Println("No commands in history.")
		return nil
	}

	// Show the last N commands
	start := 0
	if totalCommands > limit {
		start = totalCommands - limit
	}

	rows := make([][]string, 0, limit)
	for i := start; i < totalCommands; i++ {
		entry := commandLog[i]
		status := "✓"
		if !entry.Success {
			status = "✗"
			if entry.Error != "" {
				status += " " + entry.Error
			}
		}

		rows = append(rows, []string{entry.Timestamp, entry.Command, status})
	}

	ui.Table([]string{"Timestamp", "Command", "Status"}, rows)
	fmt.Println()
	fmt.Printf("Total commands: %d\n", totalCommands)

	return nil
}

// loadSessionState loads state from the current session
func (r *REPL) loadSessionState() {
	session := r.sessionManager.GetCurrentSession()

	// Load identities - always set to replace previous workspace's identities
	identities := session.GetIdentities()
	if identities == nil {
		identities = make(map[string]*modules.Identity)
	}
	r.identityManager.SetIdentities(identities)

	// Load current identity
	currentIdentityName := session.GetCurrentIdentity()
	if currentIdentityName != "" && len(identities) > 0 {
		if identity, exists := identities[currentIdentityName]; exists {
			r.identityManager.SetCurrent(identity)
		} else {
			r.identityManager.SetCurrent(nil)
		}
	} else {
		r.identityManager.SetCurrent(nil)
	}

	// Load current module
	if moduleName := session.GetCurrentModule(); moduleName != "" {
		if module, err := modules.LoadModule(moduleName); err == nil {
			r.currentModule = module
		}
	} else {
		r.currentModule = nil
	}

	// Load options
	r.options = make(map[string]string)
	for k, v := range session.GetOptions() {
		r.options[k] = v
	}
}

// saveCurrentState saves current state to the session
func (r *REPL) saveCurrentState() {
	session := r.sessionManager.GetCurrentSession()

	// Save all identities
	identities := r.identityManager.GetIdentities()
	if len(identities) > 0 {
		session.SetIdentities(identities)
	}

	// Save current identity
	if identity := r.identityManager.GetCurrent(); identity != nil {
		session.SetCurrentIdentity(identity.Name)
	}

	// Save current module
	if r.currentModule != nil {
		session.SetCurrentModule(r.currentModule.Name())
	}

	// Save options
	session.SetOptions(r.options)
}

// cleanupResource cleans up a specific resource
func (r *REPL) cleanupResource(resource CreatedResource, identity *modules.Identity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config := identity.GetConfig()

	switch resource.Type {
	case "lambda:function":
		return r.cleanupLambdaFunction(ctx, config, resource)
	case "ec2:instance":
		return r.cleanupEC2Instance(ctx, config, resource)
	case "ec2:spot-instance-request":
		return r.cleanupEC2SpotInstanceRequest(ctx, config, resource)
	case "iam:role":
		return r.cleanupIAMRole(ctx, config, resource)
	case "iam:user":
		return r.cleanupIAMUser(ctx, config, resource)
	case "iam:attached-policy":
		return r.cleanupIAMAttachedPolicy(ctx, config, resource)
	case "iam:inline-policy":
		return r.cleanupIAMInlinePolicy(ctx, config, resource)
	case "iam:group-membership":
		return r.cleanupIAMGroupMembership(ctx, config, resource)
	case "iam:trust-policy":
		return r.cleanupIAMTrustPolicy(ctx, config, resource)
	case "iam:policy-version":
		return r.cleanupIAMPolicyVersion(ctx, config, resource)
	case "iam:access-key":
		return r.cleanupIAMAccessKey(ctx, config, resource)
	case "iam:login-profile":
		return r.cleanupIAMLoginProfile(ctx, config, resource)
	case "ecs:service":
		return r.cleanupECSService(ctx, config, resource)
	case "ecs:cluster":
		return r.cleanupECSCluster(ctx, config, resource)
	case "lambda:event-source-mapping":
		return r.cleanupLambdaEventSourceMapping(ctx, config, resource)
	case "lambda:permission":
		return r.cleanupLambdaPermission(ctx, config, resource)
	case "ecs:task-definition":
		return r.cleanupECSTaskDefinition(ctx, config, resource)
	case "s3_bucket":
		return r.cleanupS3Bucket(ctx, config, resource)
	case "glue:job":
		return r.cleanupGlueJob(ctx, config, resource)
	case "glue:dev-endpoint":
		return r.cleanupGlueDevEndpoint(ctx, config, resource)
	case "glue:session":
		return r.cleanupGlueSession(ctx, config, resource)
	case "glue:trigger":
		return r.cleanupGlueTrigger(ctx, config, resource)
	case "emrserverless:application":
		return r.cleanupEMRServerlessApplication(ctx, config, resource)
	case "cloudformation:stack":
		return r.cleanupCloudFormationStack(ctx, config, resource)
	case "cloudformation:stack-update":
		return r.cleanupCloudFormationStackUpdate(ctx, config, resource)
	case "cloudformation:stackset":
		return r.cleanupCloudFormationStackSet(ctx, config, resource)
	case "cloudformation:stackset-update":
		return r.cleanupCloudFormationStackSetUpdate(ctx, config, resource)
	case "bedrock-agentcore:browser":
		return r.cleanupBedrockAgentCoreBrowser(ctx, config, resource)
	case "bedrock-agentcore:harness":
		return r.cleanupBedrockAgentCoreHarness(ctx, config, resource)
	case "bedrock-agentcore:code-interpreter":
		return r.cleanupBedrockCodeInterpreter(ctx, config, resource)
	case "bedrock-agentcore:agent-runtime":
		return r.cleanupBedrockAgentCoreAgentRuntime(ctx, config, resource)
	case "ecs:task":
		return r.cleanupECSTask(ctx, config, resource)
	case "ec2:userdata":
		return r.cleanupEC2UserData(ctx, config, resource)
	case "apprunner:service":
		return r.cleanupAppRunnerService(ctx, config, resource)
	case "braket:job":
		return r.cleanupBraketJob(ctx, config, resource)
	case "ec2:launch-template-version":
		return r.cleanupEC2LaunchTemplateVersion(ctx, config, resource)
	case "ec2:launch-template-default":
		return r.cleanupEC2LaunchTemplateDefault(ctx, config, resource)
	case "batch:job-definition":
		return r.cleanupBatchJobDefinition(ctx, config, resource)
	case "batch:job-queue":
		return r.cleanupBatchJobQueue(ctx, config, resource)
	case "batch:compute-environment":
		return r.cleanupBatchComputeEnvironment(ctx, config, resource)
	case "imagebuilder:component":
		return r.cleanupImageBuilderComponent(ctx, config, resource)
	case "imagebuilder:recipe":
		return r.cleanupImageBuilderRecipe(ctx, config, resource)
	case "imagebuilder:infra-config":
		return r.cleanupImageBuilderInfraConfig(ctx, config, resource)
	case "imagebuilder:image":
		return r.cleanupImageBuilderImage(ctx, config, resource)
	case "emr:cluster":
		return r.cleanupEMRCluster(ctx, config, resource)
	case "omics:workflow":
		return r.cleanupOmicsWorkflow(ctx, config, resource)
	case "omics:run":
		return r.cleanupOmicsRun(ctx, config, resource)
	case "ssm:automation-document":
		return r.cleanupSSMAutomationDocument(ctx, config, resource)
	case "kinesisanalyticsv2:application":
		return r.cleanupKinesisAnalyticsApplication(ctx, config, resource)
	case "gamelift:fleet":
		return r.cleanupGameLiftFleet(ctx, config, resource)
	case "gamelift:build":
		return r.cleanupGameLiftBuild(ctx, config, resource)
	case "local:file":
		path := resource.Metadata["path"]
		if path == "" {
			return fmt.Errorf("local:file resource missing 'path' metadata")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported resource type: %s", resource.Type)
	}
}

// cleanupLambdaFunction deletes a Lambda function
func (r *REPL) cleanupLambdaFunction(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := lambda.NewFromConfig(config)
	_, err := client.DeleteFunction(ctx, &lambda.DeleteFunctionInput{
		FunctionName: aws.String(resource.Name),
	})
	return err
}

// cleanupLambdaEventSourceMapping deletes a Lambda event source mapping
func (r *REPL) cleanupLambdaEventSourceMapping(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := lambda.NewFromConfig(config)

	uuid := resource.Metadata["uuid"]
	if uuid == "" {
		uuid = resource.Name
	}

	_, err := client.DeleteEventSourceMapping(ctx, &lambda.DeleteEventSourceMappingInput{
		UUID: aws.String(uuid),
	})
	return err
}

// cleanupLambdaPermission removes a resource-based policy statement from a Lambda function.
func (r *REPL) cleanupLambdaPermission(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := lambda.NewFromConfig(config)

	funcName := resource.Metadata["function_name"]
	stmtID := resource.Metadata["statement_id"]
	if funcName == "" || stmtID == "" {
		return fmt.Errorf("missing function_name or statement_id metadata for lambda:permission resource")
	}

	_, err := client.RemovePermission(ctx, &lambda.RemovePermissionInput{
		FunctionName: aws.String(funcName),
		StatementId:  aws.String(stmtID),
	})
	return err
}

// cleanupEC2Instance terminates an EC2 instance
func (r *REPL) cleanupEC2Instance(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := ec2.NewFromConfig(config)

	instanceID, exists := resource.Metadata["instance_id"]
	if !exists {
		instanceID = resource.Name
	}

	_, err := client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	})
	return err
}

// cleanupEC2SpotInstanceRequest cancels an EC2 spot instance request.
func (r *REPL) cleanupEC2SpotInstanceRequest(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := ec2.NewFromConfig(config)

	spotRequestID, exists := resource.Metadata["spot_request_id"]
	if !exists {
		spotRequestID = resource.Name
	}

	_, err := client.CancelSpotInstanceRequests(ctx, &ec2.CancelSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []string{spotRequestID},
	})
	return err
}

// cleanupIAMRole deletes an IAM role and its policies
func (r *REPL) cleanupIAMRole(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	// Detach managed policies
	if policies, exists := resource.Metadata["attached_policies"]; exists {
		policyList := strings.Split(policies, ",")
		for _, policyArn := range policyList {
			if policyArn != "" {
				_, _ = client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
					RoleName:  aws.String(resource.Name),
					PolicyArn: aws.String(policyArn),
				})
			}
		}
	}

	// Delete inline policies
	if policies, exists := resource.Metadata["inline_policies"]; exists {
		policyList := strings.Split(policies, ",")
		for _, policyName := range policyList {
			if policyName != "" {
				_, _ = client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
					RoleName:   aws.String(resource.Name),
					PolicyName: aws.String(policyName),
				})
			}
		}
	}

	// Delete the role
	_, err := client.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(resource.Name),
	})
	return err
}

// cleanupIAMAttachedPolicy detaches a managed policy from a role or user
func (r *REPL) cleanupIAMAttachedPolicy(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	principalType := resource.Metadata["principal_type"]
	principalName := resource.Metadata["principal_name"]
	policyArn := resource.Metadata["policy_arn"]

	if policyArn == "" {
		policyArn = resource.ARN
	}
	if principalName == "" {
		principalName = resource.Name
	}

	// Normalize ARNs to friendly names — IAM APIs require names, not ARNs
	if strings.HasPrefix(principalName, "arn:") {
		if idx := strings.LastIndex(principalName, "/"); idx != -1 {
			principalName = principalName[idx+1:]
		}
	}

	switch principalType {
	case "user":
		_, err := client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			UserName:  aws.String(principalName),
			PolicyArn: aws.String(policyArn),
		})
		return err
	case "group":
		_, err := client.DetachGroupPolicy(ctx, &iam.DetachGroupPolicyInput{
			GroupName: aws.String(principalName),
			PolicyArn: aws.String(policyArn),
		})
		return err
	case "role", "":
		_, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  aws.String(principalName),
			PolicyArn: aws.String(policyArn),
		})
		return err
	default:
		return fmt.Errorf("unsupported principal type: %s", principalType)
	}
}

// cleanupIAMPolicyVersion deletes a specific policy version
func (r *REPL) cleanupIAMPolicyVersion(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	policyArn := resource.Metadata["policy_arn"]
	if policyArn == "" {
		policyArn = resource.ARN
	}

	versionID := resource.Metadata["version_id"]
	if versionID == "" {
		return fmt.Errorf("no version_id in resource metadata")
	}

	_, err := client.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: aws.String(versionID),
	})
	return err
}

// cleanupIAMAccessKey deletes an IAM access key
func (r *REPL) cleanupIAMAccessKey(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	username := resource.Metadata["username"]
	accessKeyID := resource.Metadata["access_key_id"]
	if accessKeyID == "" {
		accessKeyID = resource.Name
	}

	_, err := client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName:    aws.String(username),
		AccessKeyId: aws.String(accessKeyID),
	})
	return err
}

// cleanupIAMLoginProfile deletes an IAM login profile
func (r *REPL) cleanupIAMLoginProfile(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	username := resource.Metadata["username"]
	if username == "" {
		username = resource.Name
	}

	_, err := client.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{
		UserName: aws.String(username),
	})
	return err
}

// cleanupECSService updates desired count to 0 and deletes the service
func (r *REPL) cleanupECSService(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := ecs.NewFromConfig(config)

	cluster := resource.Metadata["cluster"]
	serviceName := resource.Name

	// Scale down to 0 first
	_, _ = client.UpdateService(ctx, &ecs.UpdateServiceInput{
		Cluster:      aws.String(cluster),
		Service:      aws.String(serviceName),
		DesiredCount: aws.Int32(0),
	})

	// Delete the service
	_, err := client.DeleteService(ctx, &ecs.DeleteServiceInput{
		Cluster: aws.String(cluster),
		Service: aws.String(serviceName),
		Force:   aws.Bool(true),
	})
	return err
}

// cleanupECSCluster deletes an ECS cluster
func (r *REPL) cleanupECSCluster(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := ecs.NewFromConfig(config)

	_, err := client.DeleteCluster(ctx, &ecs.DeleteClusterInput{
		Cluster: aws.String(resource.Name),
	})
	return err
}

// cleanupECSTaskDefinition deregisters an ECS task definition
func (r *REPL) cleanupECSTaskDefinition(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := ecs.NewFromConfig(config)

	taskDefArn := resource.ARN
	if taskDefArn == "" {
		taskDefArn = resource.Name
	}

	_, err := client.DeregisterTaskDefinition(ctx, &ecs.DeregisterTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefArn),
	})
	if err != nil {
		return err
	}

	// Also delete the deregistered task definition
	_, _ = client.DeleteTaskDefinitions(ctx, &ecs.DeleteTaskDefinitionsInput{
		TaskDefinitions: []string{taskDefArn},
	})
	return nil
}

// cleanupIAMUser deletes an IAM user and its policies
func (r *REPL) cleanupIAMUser(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	// Delete access keys
	listKeysResult, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(resource.Name),
	})
	if err == nil {
		for _, key := range listKeysResult.AccessKeyMetadata {
			_, _ = client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
				UserName:    aws.String(resource.Name),
				AccessKeyId: key.AccessKeyId,
			})
		}
	}

	// Detach managed policies
	if policies, exists := resource.Metadata["attached_policies"]; exists {
		policyList := strings.Split(policies, ",")
		for _, policyArn := range policyList {
			if policyArn != "" {
				_, _ = client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
					UserName:  aws.String(resource.Name),
					PolicyArn: aws.String(policyArn),
				})
			}
		}
	}

	// Delete inline policies
	if policies, exists := resource.Metadata["inline_policies"]; exists {
		policyList := strings.Split(policies, ",")
		for _, policyName := range policyList {
			if policyName != "" {
				_, _ = client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
					UserName:   aws.String(resource.Name),
					PolicyName: aws.String(policyName),
				})
			}
		}
	}

	// Delete the user
	_, err = client.DeleteUser(ctx, &iam.DeleteUserInput{
		UserName: aws.String(resource.Name),
	})
	return err
}

// cleanupIAMInlinePolicy deletes an inline policy from a role, group, or user
func (r *REPL) cleanupIAMInlinePolicy(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	principalType := resource.Metadata["principal_type"]
	principalName := resource.Metadata["principal_name"]
	policyName := resource.Metadata["policy_name"]

	if policyName == "" {
		policyName = resource.Name
	}

	switch principalType {
	case "user":
		_, err := client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			UserName:   aws.String(principalName),
			PolicyName: aws.String(policyName),
		})
		return err
	case "group":
		_, err := client.DeleteGroupPolicy(ctx, &iam.DeleteGroupPolicyInput{
			GroupName:  aws.String(principalName),
			PolicyName: aws.String(policyName),
		})
		return err
	case "role", "":
		_, err := client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(principalName),
			PolicyName: aws.String(policyName),
		})
		return err
	default:
		return fmt.Errorf("unsupported principal type for inline policy: %s", principalType)
	}
}

// cleanupIAMGroupMembership removes a user from a group
func (r *REPL) cleanupIAMGroupMembership(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	userName := resource.Metadata["user_name"]
	groupName := resource.Metadata["group_name"]

	if userName == "" || groupName == "" {
		return fmt.Errorf("missing user_name or group_name in resource metadata")
	}

	_, err := client.RemoveUserFromGroup(ctx, &iam.RemoveUserFromGroupInput{
		UserName:  aws.String(userName),
		GroupName: aws.String(groupName),
	})
	return err
}

// cleanupIAMTrustPolicy restores the original trust policy on a role
func (r *REPL) cleanupIAMTrustPolicy(ctx context.Context, config aws.Config, resource CreatedResource) error {
	client := iam.NewFromConfig(config)

	roleName := resource.Metadata["role_name"]
	originalPolicy := resource.Metadata["original_policy"]

	if roleName == "" {
		roleName = resource.Name
	}
	if originalPolicy == "" {
		return fmt.Errorf("no original_policy in resource metadata; cannot restore trust policy")
	}

	_, err := client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyDocument: aws.String(originalPolicy),
	})
	return err
}

// cleanupS3Bucket empties and deletes an S3 bucket
func (r *REPL) cleanupS3Bucket(_ context.Context, config aws.Config, resource CreatedResource) error {
	region := resource.Region
	if region == "" {
		region = config.Region
	}
	return attacker.DeleteBucket(config, resource.Name, region)
}

// cleanupGlueJob deletes a Glue job
func (r *REPL) cleanupGlueJob(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	client := glue.NewFromConfig(config)
	_, err := client.DeleteJob(ctx, &glue.DeleteJobInput{
		JobName: aws.String(resource.Name),
	})
	return err
}

// cleanupGlueSession stops (if still running) and deletes a Glue Interactive Session.
func (r *REPL) cleanupGlueSession(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	client := glue.NewFromConfig(config)

	// Retrieve current status; stop the session before deleting if it is still running.
	statusResult, err := client.GetSession(ctx, &glue.GetSessionInput{
		Id: aws.String(resource.Name),
	})
	if err == nil {
		status := statusResult.Session.Status
		if status == gluetypes.SessionStatusReady || status == gluetypes.SessionStatusProvisioning {
			_, _ = client.StopSession(ctx, &glue.StopSessionInput{
				Id: aws.String(resource.Name),
			})
			time.Sleep(5 * time.Second)
		}
	}

	_, err = client.DeleteSession(ctx, &glue.DeleteSessionInput{
		Id: aws.String(resource.Name),
	})
	return err
}

// cleanupGlueDevEndpoint deletes a Glue development endpoint.
// AWS processes the deletion asynchronously; billing stops as soon as the
// delete request is accepted.
func (r *REPL) cleanupGlueDevEndpoint(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	client := glue.NewFromConfig(config)
	endpointName := resource.Name
	if n := resource.Metadata["endpoint_name"]; n != "" {
		endpointName = n
	}
	_, err := client.DeleteDevEndpoint(ctx, &glue.DeleteDevEndpointInput{
		EndpointName: aws.String(endpointName),
	})
	return err
}

// cleanupGlueTrigger stops (if active) then deletes a Glue trigger.
// The trigger must be stopped before it can be deleted when in ACTIVATED state.
func (r *REPL) cleanupGlueTrigger(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	client := glue.NewFromConfig(config)
	// Stop the trigger first; ignore errors if it is already stopped or deactivated.
	_, _ = client.StopTrigger(ctx, &glue.StopTriggerInput{
		Name: aws.String(resource.Name),
	})
	_, err := client.DeleteTrigger(ctx, &glue.DeleteTriggerInput{
		Name: aws.String(resource.Name),
	})
	return err
}

// cleanupEC2UserData, cleanupEC2LaunchTemplateVersion, cleanupEC2LaunchTemplateDefault,
// cleanupEMRServerlessApplication, and cleanupEMRCluster are implemented in cleanup_extra.go.

// cleanupOmicsWorkflow deletes a HealthOmics workflow.
func (r *REPL) cleanupOmicsWorkflow(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := omics.NewFromConfig(config)

	// Prefer the workflow_id metadata field; fall back to the resource Name.
	workflowID := resource.Metadata["workflow_id"]
	if workflowID == "" {
		workflowID = resource.Name
	}

	_, err := client.DeleteWorkflow(ctx, &omics.DeleteWorkflowInput{
		Id: aws.String(workflowID),
	})
	return err
}

// cleanupOmicsRun deletes a HealthOmics workflow run.
// If the run is still active (PENDING, STARTING, RUNNING), it is cancelled first.
func (r *REPL) cleanupOmicsRun(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := omics.NewFromConfig(config)

	// Prefer the run_id metadata field; fall back to the resource Name.
	runID := resource.Metadata["run_id"]
	if runID == "" {
		runID = resource.Name
	}

	// Check current run state before attempting deletion.
	getResult, err := client.GetRun(ctx, &omics.GetRunInput{
		Id: aws.String(runID),
	})
	if err == nil {
		switch getResult.Status {
		case omicstypes.RunStatusPending, omicstypes.RunStatusStarting, omicstypes.RunStatusRunning:
			// Cancel the run first; deletion of an active run is not permitted.
			_, _ = client.CancelRun(ctx, &omics.CancelRunInput{
				Id: aws.String(runID),
			})
			time.Sleep(15 * time.Second)
		}
	}

	_, err = client.DeleteRun(ctx, &omics.DeleteRunInput{
		Id: aws.String(runID),
	})
	return err
}

