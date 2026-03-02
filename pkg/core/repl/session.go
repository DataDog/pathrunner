package repl

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"pathrunner/pkg/modules"

	"github.com/AlecAivazis/survey/v2"
	"github.com/aquasecurity/table"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
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
		r.sessionManager.SaveSession(current)
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

	// Create table
	t := table.New(os.Stdout)
	t.SetHeaders("Name", "Created", "Last Accessed", "Commands", "Resources", "Current")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	currentName := r.sessionManager.GetCurrentSession().GetName()

	for _, session := range sessions {
		current := ""
		if session.GetName() == currentName {
			current = "●"
		}

		t.AddRow(
			session.GetName(),
			session.GetCreated(),
			session.GetLastAccessed(),
			strconv.Itoa(session.GetCommandCount()),
			strconv.Itoa(session.GetResourceCount()),
			current,
		)
	}

	fmt.Println("Available workspaces:")
	fmt.Println()
	t.Render()
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
	moduleFilter := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all":
			cleanAll = true
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
		resourceMap := make(map[string]CreatedResource)

		// Add "All resources" option
		allOption := fmt.Sprintf("All resources (%d)", len(resources))
		options = append(options, allOption)

		// Add individual resources
		for _, resource := range resources {
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
			resourceMap[option] = resource
		}

		// Show multi-select prompt
		var selected []string
		prompt := &survey.MultiSelect{
			Message: "Select resources to clean up (space to select, enter to confirm):",
			Options: options,
			Description: func(value string, index int) string {
				if index == 0 {
					return "Clean up all tracked resources"
				}
				return ""
			},
		}

		err := survey.AskOne(prompt, &selected, survey.WithPageSize(10))
		if err != nil {
			return fmt.Errorf("selection cancelled")
		}

		if len(selected) == 0 {
			fmt.Println("No resources selected for cleanup.")
			return nil
		}

		// Check if "All resources" was selected
		selectAll := false
		for _, sel := range selected {
			if sel == allOption {
				selectAll = true
				break
			}
		}

		if selectAll {
			resourcesToCleanup = resources
		} else {
			for _, sel := range selected {
				if resource, exists := resourceMap[sel]; exists {
					resourcesToCleanup = append(resourcesToCleanup, resource)
				}
			}
		}
	}

	// Clean up selected resources
	fmt.Printf("\nCleaning up %d resources...\n", len(resourcesToCleanup))
	fmt.Println()

	var cleaned, failed int
	for _, resource := range resourcesToCleanup {
		regionInfo := ""
		if resource.Region != "" {
			regionInfo = fmt.Sprintf(" [%s]", resource.Region)
		}
		fmt.Printf("Cleaning up %s: %s%s...", resource.Type, resource.Name, regionInfo)

		if err := r.cleanupResource(resource, identity); err != nil {
			fmt.Printf(" FAILED (%v)\n", err)
			failed++
		} else {
			fmt.Printf(" OK\n")
			cleaned++
			r.sessionManager.RemoveCreatedResource(resource.Name)
		}
	}

	fmt.Println()
	fmt.Printf("Cleanup complete: %d cleaned, %d failed\n", cleaned, failed)

	if cleaned > 0 {
		r.sessionSave()
	}

	return nil
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

	// Create table
	t := table.New(os.Stdout)
	t.SetHeaders("Timestamp", "Command", "Status")
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(false)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.SetAlignment(table.AlignLeft)

	for i := start; i < totalCommands; i++ {
		entry := commandLog[i]
		status := "✓"
		if !entry.Success {
			status = "✗"
			if entry.Error != "" {
				status += " " + entry.Error
			}
		}

		t.AddRow(entry.Timestamp, entry.Command, status)
	}

	t.Render()
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
	case "iam:role":
		return r.cleanupIAMRole(ctx, config, resource)
	case "iam:user":
		return r.cleanupIAMUser(ctx, config, resource)
	case "iam:attached-policy":
		return r.cleanupIAMAttachedPolicy(ctx, config, resource)
	case "iam:policy-version":
		return r.cleanupIAMPolicyVersion(ctx, config, resource)
	case "ecs:service":
		return r.cleanupECSService(ctx, config, resource)
	case "ecs:cluster":
		return r.cleanupECSCluster(ctx, config, resource)
	case "ecs:task-definition":
		return r.cleanupECSTaskDefinition(ctx, config, resource)
	default:
		return fmt.Errorf("unsupported resource type: %s", resource.Type)
	}
}

// cleanupLambdaFunction deletes a Lambda function
func (r *REPL) cleanupLambdaFunction(ctx context.Context, config aws.Config, resource CreatedResource) error {
	// Override region with the resource's region if it was tracked
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := lambda.NewFromConfig(config)
	_, err := client.DeleteFunction(ctx, &lambda.DeleteFunctionInput{
		FunctionName: aws.String(resource.Name),
	})
	return err
}

// cleanupEC2Instance terminates an EC2 instance
func (r *REPL) cleanupEC2Instance(ctx context.Context, config aws.Config, resource CreatedResource) error {
	// Override region with the resource's region if it was tracked
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := ec2.NewFromConfig(config)

	// Get instance ID from metadata
	instanceID, exists := resource.Metadata["instance_id"]
	if !exists {
		// Fallback to using resource name as instance ID
		instanceID = resource.Name
	}

	_, err := client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
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
				client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
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
				client.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
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

	switch principalType {
	case "user":
		_, err := client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
			UserName:  aws.String(principalName),
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
			client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
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
				client.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{
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
				client.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
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
