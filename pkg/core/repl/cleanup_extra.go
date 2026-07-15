package repl

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/braket"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/gamelift"
	"github.com/aws/aws-sdk-go-v2/service/emrserverless"
	"github.com/aws/aws-sdk-go-v2/service/imagebuilder"
	"github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2"
	katypes "github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// cleanupCloudFormationStack deletes a CloudFormation stack created by an exploit module.
// Resources provisioned inside the stack (e.g., the escalated IAM role in cloudformation-001)
// are automatically deleted by CloudFormation as part of stack deletion.
func (r *REPL) cleanupCloudFormationStack(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	stackName := resource.Metadata["stack_name"]
	if stackName == "" {
		stackName = resource.Name
	}
	cfnClient := cloudformation.NewFromConfig(config)
	_, err := cfnClient.DeleteStack(ctx, &cloudformation.DeleteStackInput{
		StackName: aws.String(stackName),
	})
	return err
}

// cleanupCloudFormationStackUpdate reverts a CloudFormation stack to its original template.
// The original template body must be stored in resource.Metadata["original_template"].
// Used for cloudformation stack update exploitation (e.g., cloudformation-002).
func (r *REPL) cleanupCloudFormationStackUpdate(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	stackName := resource.Metadata["stack_name"]
	if stackName == "" {
		stackName = resource.Name
	}
	originalTemplate := resource.Metadata["original_template"]
	if originalTemplate == "" {
		return fmt.Errorf("no original_template in metadata for cloudformation:stack-update '%s'; revert manually", stackName)
	}
	cfnClient := cloudformation.NewFromConfig(config)
	changeSetName := "pathrunner-cleanup-revert"
	_, err := cfnClient.CreateChangeSet(ctx, &cloudformation.CreateChangeSetInput{
		StackName:     aws.String(stackName),
		ChangeSetName: aws.String(changeSetName),
		TemplateBody:  aws.String(originalTemplate),
		Capabilities:  []cftypes.Capability{cftypes.CapabilityCapabilityIam},
	})
	if err != nil {
		return fmt.Errorf("failed to create revert change set for stack '%s': %w", stackName, err)
	}
	_, err = cfnClient.ExecuteChangeSet(ctx, &cloudformation.ExecuteChangeSetInput{
		StackName:     aws.String(stackName),
		ChangeSetName: aws.String(changeSetName),
	})
	if err != nil {
		return fmt.Errorf("failed to execute revert change set for stack '%s': %w", stackName, err)
	}
	return nil
}

// cleanupCloudFormationStackSet removes all stack instances and then deletes the StackSet.
// CloudFormation requires instances to be fully deleted before the StackSet itself can be removed.
// This is used for cloudformation-003 (CreateStackSet + CreateStackInstances) resources.
func (r *REPL) cleanupCloudFormationStackSet(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	stackSetName := resource.Metadata["stackset_name"]
	if stackSetName == "" {
		stackSetName = resource.Name
	}

	accountID := resource.Metadata["account_id"]
	targetRegion := resource.Metadata["target_region"]
	if targetRegion == "" {
		targetRegion = config.Region
	}

	cfnClient := cloudformation.NewFromConfig(config)

	// Check whether the StackSet still exists before attempting deletion.
	descCtx, descCancel := context.WithTimeout(ctx, 30*time.Second)
	_, descErr := cfnClient.DescribeStackSet(descCtx, &cloudformation.DescribeStackSetInput{
		StackSetName: aws.String(stackSetName),
	})
	descCancel()
	if descErr != nil {
		// StackSet already deleted — treat as success.
		return nil
	}

	// Step 1: delete stack instances if accountID is known.
	if accountID != "" {
		delInstCtx, delInstCancel := context.WithTimeout(ctx, 60*time.Second)
		delResult, delErr := cfnClient.DeleteStackInstances(delInstCtx, &cloudformation.DeleteStackInstancesInput{
			StackSetName: aws.String(stackSetName),
			Accounts:     []string{accountID},
			Regions:      []string{targetRegion},
			RetainStacks: aws.Bool(false),
		})
		delInstCancel()
		if delErr != nil {
			return fmt.Errorf("failed to delete stack instances for StackSet '%s': %v", stackSetName, delErr)
		}
		operationID := aws.ToString(delResult.OperationId)
		// Poll for the deletion to complete (max 5 minutes, 30 attempts x 10s each).
		for attempt := 1; attempt <= 30; attempt++ {
			time.Sleep(10 * time.Second)
			pollCtx, pollCancel := context.WithTimeout(ctx, 30*time.Second)
			opResult, pollErr := cfnClient.DescribeStackSetOperation(pollCtx, &cloudformation.DescribeStackSetOperationInput{
				StackSetName: aws.String(stackSetName),
				OperationId:  aws.String(operationID),
			})
			pollCancel()
			if pollErr != nil {
				return fmt.Errorf("failed to poll stack instance deletion for StackSet '%s': %v", stackSetName, pollErr)
			}
			switch opResult.StackSetOperation.Status {
			case cftypes.StackSetOperationStatusSucceeded:
				// Instance deletion complete; proceed to delete the StackSet.
				goto deleteStackSet
			case cftypes.StackSetOperationStatusFailed, cftypes.StackSetOperationStatusStopped:
				return fmt.Errorf("stack instance deletion operation failed for StackSet '%s'", stackSetName)
			}
		}
		return fmt.Errorf("stack instance deletion for StackSet '%s' did not complete within 5 minutes", stackSetName)
	}

deleteStackSet:
	delStackCtx, delStackCancel := context.WithTimeout(ctx, 30*time.Second)
	defer delStackCancel()
	_, err := cfnClient.DeleteStackSet(delStackCtx, &cloudformation.DeleteStackSetInput{
		StackSetName: aws.String(stackSetName),
	})
	return err
}

// cleanupCloudFormationStackSetUpdate reverts a CloudFormation StackSet to its original
// template by calling UpdateStackSet with the saved template body.
// Used for cloudformation-004 (UpdateStackSet exploitation) resources.
// The original_template, admin_role_arn, and execution_role_name must be present in Metadata.
func (r *REPL) cleanupCloudFormationStackSetUpdate(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	stackSetName := resource.Metadata["stackset_name"]
	if stackSetName == "" {
		stackSetName = resource.Name
	}

	originalTemplate := resource.Metadata["original_template"]
	if originalTemplate == "" {
		return fmt.Errorf("no original_template in metadata for cloudformation:stackset-update '%s'; revert manually", stackSetName)
	}

	adminRoleArn := resource.Metadata["admin_role_arn"]
	if adminRoleArn == "" {
		return fmt.Errorf("no admin_role_arn in metadata for cloudformation:stackset-update '%s'; revert manually", stackSetName)
	}

	executionRoleName := resource.Metadata["execution_role_name"]
	if executionRoleName == "" {
		executionRoleName = "AWSCloudFormationStackSetExecutionRole"
	}

	cfnClient := cloudformation.NewFromConfig(config)
	updateCtx, updateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer updateCancel()

	updateResult, err := cfnClient.UpdateStackSet(updateCtx, &cloudformation.UpdateStackSetInput{
		StackSetName:          aws.String(stackSetName),
		TemplateBody:          aws.String(originalTemplate),
		AdministrationRoleARN: aws.String(adminRoleArn),
		ExecutionRoleName:     aws.String(executionRoleName),
		Capabilities:          []cftypes.Capability{cftypes.CapabilityCapabilityNamedIam},
	})
	if err != nil {
		return fmt.Errorf("failed to revert StackSet '%s' to original template: %v", stackSetName, err)
	}

	operationID := aws.ToString(updateResult.OperationId)
	fmt.Printf("Cleanup: Reverting StackSet '%s' (operation: %s)...\n", stackSetName, operationID)

	// Poll every 5 seconds for up to 10 minutes (120 attempts).
	for attempt := 1; attempt <= 120; attempt++ {
		time.Sleep(5 * time.Second)
		pollCtx, pollCancel := context.WithTimeout(ctx, 30*time.Second)
		result, pollErr := cfnClient.DescribeStackSetOperation(pollCtx, &cloudformation.DescribeStackSetOperationInput{
			StackSetName: aws.String(stackSetName),
			OperationId:  aws.String(operationID),
		})
		pollCancel()
		if pollErr != nil {
			return fmt.Errorf("failed to poll StackSet operation status during cleanup: %v", pollErr)
		}
		switch result.StackSetOperation.Status {
		case cftypes.StackSetOperationStatusSucceeded:
			fmt.Printf("StackSet '%s' successfully reverted to original template.\n", stackSetName)
			return nil
		case cftypes.StackSetOperationStatusFailed:
			return fmt.Errorf("cleanup StackSet operation failed for '%s'", stackSetName)
		case cftypes.StackSetOperationStatusStopped:
			return fmt.Errorf("cleanup StackSet operation was stopped for '%s'", stackSetName)
		}
	}

	return fmt.Errorf("StackSet '%s' cleanup did not complete within 10 minutes", stackSetName)
}

// cleanupBedrockAgentCoreBrowser deletes a Bedrock AgentCore browser.
// The starting user may lack bedrock-agentcore-control:DeleteBrowser; run workspace
// cleanup with the extracted identity if this fails.
func (r *REPL) cleanupBedrockAgentCoreBrowser(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	browserID := resource.Metadata["browser_id"]
	if browserID == "" {
		browserID = resource.Name
	}
	client := bedrockagentcorecontrol.NewFromConfig(config)
	_, err := client.DeleteBrowser(ctx, &bedrockagentcorecontrol.DeleteBrowserInput{
		BrowserId: aws.String(browserID),
	})
	return err
}

// cleanupBedrockAgentCoreHarness deletes a Bedrock AgentCore harness.
// The starting user may lack bedrock-agentcore-control:DeleteHarness; run workspace
// cleanup with the extracted identity if this fails.
func (r *REPL) cleanupBedrockAgentCoreHarness(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	harnessID := resource.Metadata["harness_id"]
	if harnessID == "" {
		harnessID = resource.Name
	}
	client := bedrockagentcorecontrol.NewFromConfig(config)
	_, err := client.DeleteHarness(ctx, &bedrockagentcorecontrol.DeleteHarnessInput{
		HarnessId: aws.String(harnessID),
	})
	return err
}

// cleanupBedrockCodeInterpreter deletes a Bedrock AgentCore code interpreter.
// The starting user typically lacks bedrock-agentcore-control:DeleteCodeInterpreter;
// run workspace cleanup with the extracted identity if this fails.
func (r *REPL) cleanupBedrockCodeInterpreter(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	interpreterID := resource.Metadata["interpreter_id"]
	if interpreterID == "" {
		interpreterID = resource.Name
	}
	client := bedrockagentcorecontrol.NewFromConfig(config)
	_, err := client.DeleteCodeInterpreter(ctx, &bedrockagentcorecontrol.DeleteCodeInterpreterInput{
		CodeInterpreterId: aws.String(interpreterID),
	})
	return err
}

// cleanupBedrockAgentCoreAgentRuntime deletes a Bedrock AgentCore agent runtime.
// The starting user may lack bedrock-agentcore-control:DeleteAgentRuntime; run workspace
// cleanup with the extracted identity if this fails.
func (r *REPL) cleanupBedrockAgentCoreAgentRuntime(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	agentRuntimeID := resource.Metadata["agent_runtime_id"]
	if agentRuntimeID == "" {
		agentRuntimeID = resource.Name
	}
	client := bedrockagentcorecontrol.NewFromConfig(config)
	_, err := client.DeleteAgentRuntime(ctx, &bedrockagentcorecontrol.DeleteAgentRuntimeInput{
		AgentRuntimeId: aws.String(agentRuntimeID),
	})
	return err
}

// cleanupECSTask stops a running ECS task. The cluster name is stored in
// resource.Metadata["cluster"] by the exploit module that started the task.
func (r *REPL) cleanupECSTask(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	taskArn := resource.ARN
	if taskArn == "" {
		taskArn = resource.Name
	}
	client := ecs.NewFromConfig(config)
	_, err := client.StopTask(ctx, &ecs.StopTaskInput{
		Cluster: aws.String(resource.Metadata["cluster"]),
		Task:    aws.String(taskArn),
	})
	return err
}

// cleanupAppRunnerService deletes an App Runner service.
func (r *REPL) cleanupAppRunnerService(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	serviceArn := resource.ARN
	if serviceArn == "" {
		serviceArn = resource.Metadata["service_arn"]
	}
	client := apprunner.NewFromConfig(config)
	_, err := client.DeleteService(ctx, &apprunner.DeleteServiceInput{
		ServiceArn: aws.String(serviceArn),
	})
	return err
}

// cleanupBraketJob cancels a Braket hybrid job.
func (r *REPL) cleanupBraketJob(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	jobArn := resource.ARN
	if jobArn == "" {
		jobArn = resource.Name
	}
	client := braket.NewFromConfig(config)
	_, err := client.CancelJob(ctx, &braket.CancelJobInput{
		JobArn: aws.String(jobArn),
	})
	return err
}

// cleanupEC2UserData restores the original user-data on an EC2 instance modified by ec2-002.
// The original base64-encoded user-data is stored in resource.Metadata["original_userdata"].
// If the instance was running when modified, it is stopped before the restore and started again afterwards.
func (r *REPL) cleanupEC2UserData(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	instanceID := resource.Metadata["instance_id"]
	if instanceID == "" {
		instanceID = resource.Name
	}
	originalUserData := resource.Metadata["original_userdata"]

	// Use a long context for stop/start cycle (each can take ~60s).
	longCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client := ec2.NewFromConfig(config)

	// Stop the instance — user-data can only be modified while stopped.
	fmt.Printf("Stopping instance '%s' to restore original user-data...\n", instanceID)
	_, err := client.StopInstances(longCtx, &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return fmt.Errorf("failed to stop instance %s: %v", instanceID, err)
	}

	// Wait for stopped state (up to 5 minutes).
	waiter := ec2.NewInstanceStoppedWaiter(client)
	if err := waiter.Wait(longCtx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}, 5*time.Minute); err != nil {
		return fmt.Errorf("instance %s did not stop in time: %v", instanceID, err)
	}

	// Restore original user-data. The stored value is base64-encoded (as returned by the API).
	// BlobAttributeValue.Value takes raw bytes; the SDK re-encodes them automatically.
	var rawUserData []byte
	if originalUserData != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(originalUserData)
		if decErr != nil {
			rawUserData = []byte(originalUserData)
		} else {
			rawUserData = decoded
		}
	}

	_, err = client.ModifyInstanceAttribute(longCtx, &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		UserData: &ec2types.BlobAttributeValue{
			Value: rawUserData,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to restore user-data on instance %s: %v", instanceID, err)
	}

	// Restart if the instance was running before modification.
	if wasRunning := resource.Metadata["was_running"]; wasRunning == "true" {
		fmt.Printf("Restarting instance '%s'...\n", instanceID)
		if _, startErr := client.StartInstances(longCtx, &ec2.StartInstancesInput{
			InstanceIds: []string{instanceID},
		}); startErr != nil {
			fmt.Printf("Warning: failed to restart instance %s: %v\n", instanceID, startErr)
		}
	}

	return nil
}

// cleanupEC2LaunchTemplateVersion deletes a specific EC2 launch template version created by ec2-005.
// The template itself is not deleted — only the malicious version added during exploitation.
func (r *REPL) cleanupEC2LaunchTemplateVersion(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	templateID := resource.Metadata["template_id"]
	if templateID == "" {
		return fmt.Errorf("no template_id in metadata for ec2:launch-template-version '%s'", resource.Name)
	}
	versionNumber := resource.Metadata["version_number"]
	if versionNumber == "" {
		return fmt.Errorf("no version_number in metadata for ec2:launch-template-version '%s'", resource.Name)
	}

	client := ec2.NewFromConfig(config)
	_, err := client.DeleteLaunchTemplateVersions(ctx, &ec2.DeleteLaunchTemplateVersionsInput{
		LaunchTemplateId: aws.String(templateID),
		Versions:         []string{versionNumber},
	})
	return err
}

// cleanupBatchJobDefinition deregisters an AWS Batch job definition created by an exploit module.
// The job definition ARN must be stored in resource.ARN or resource.Metadata["job_definition_arn"].
// Note: the starting user for batch-001 typically lacks batch:DeregisterJobDefinition;
// use 'workspace cleanup' with an elevated identity if this fails.
func (r *REPL) cleanupBatchJobDefinition(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	jobDefArn := resource.ARN
	if jobDefArn == "" {
		jobDefArn = resource.Metadata["job_definition_arn"]
	}
	if jobDefArn == "" {
		return fmt.Errorf("no ARN in metadata for batch:job-definition '%s'; deregister manually", resource.Name)
	}
	client := batch.NewFromConfig(config)
	_, err := client.DeregisterJobDefinition(ctx, &batch.DeregisterJobDefinitionInput{
		JobDefinition: aws.String(jobDefArn),
	})
	return err
}

// cleanupImageBuilderComponent deletes a specific Image Builder component build version.
func (r *REPL) cleanupImageBuilderComponent(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	componentArn := resource.Metadata["component_arn"]
	if componentArn == "" {
		componentArn = resource.ARN
	}
	if componentArn == "" {
		return fmt.Errorf("no component ARN for imagebuilder:component '%s'", resource.Name)
	}
	client := imagebuilder.NewFromConfig(config)
	_, err := client.DeleteComponent(ctx, &imagebuilder.DeleteComponentInput{
		ComponentBuildVersionArn: aws.String(componentArn),
	})
	return err
}

// cleanupImageBuilderRecipe deletes an Image Builder image recipe.
func (r *REPL) cleanupImageBuilderRecipe(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	recipeArn := resource.Metadata["recipe_arn"]
	if recipeArn == "" {
		recipeArn = resource.ARN
	}
	if recipeArn == "" {
		return fmt.Errorf("no recipe ARN for imagebuilder:recipe '%s'", resource.Name)
	}
	client := imagebuilder.NewFromConfig(config)
	_, err := client.DeleteImageRecipe(ctx, &imagebuilder.DeleteImageRecipeInput{
		ImageRecipeArn: aws.String(recipeArn),
	})
	return err
}

// cleanupImageBuilderInfraConfig deletes an Image Builder infrastructure configuration.
func (r *REPL) cleanupImageBuilderInfraConfig(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	infraArn := resource.Metadata["infra_config_arn"]
	if infraArn == "" {
		infraArn = resource.ARN
	}
	if infraArn == "" {
		return fmt.Errorf("no ARN for imagebuilder:infra-config '%s'", resource.Name)
	}
	client := imagebuilder.NewFromConfig(config)
	_, err := client.DeleteInfrastructureConfiguration(ctx, &imagebuilder.DeleteInfrastructureConfigurationInput{
		InfrastructureConfigurationArn: aws.String(infraArn),
	})
	return err
}

// cleanupImageBuilderImage cancels an in-progress image build and then deletes the image.
// Image Builder builds can take 10-30 minutes; the cancel call is best-effort and
// ignored if the build is already in a terminal state.
func (r *REPL) cleanupImageBuilderImage(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	imageBuildArn := resource.Metadata["image_build_arn"]
	if imageBuildArn == "" {
		imageBuildArn = resource.ARN
	}
	if imageBuildArn == "" {
		return fmt.Errorf("no ARN for imagebuilder:image '%s'", resource.Name)
	}
	client := imagebuilder.NewFromConfig(config)

	// Attempt to cancel first (no-op if already in terminal state)
	_, _ = client.CancelImageCreation(ctx, &imagebuilder.CancelImageCreationInput{
		ImageBuildVersionArn: aws.String(imageBuildArn),
	})

	_, err := client.DeleteImage(ctx, &imagebuilder.DeleteImageInput{
		ImageBuildVersionArn: aws.String(imageBuildArn),
	})
	return err
}

// cleanupEMRServerlessApplication deletes an EMR Serverless application created by an exploit module.
// The application ID must be stored in resource.Metadata["application_id"] or resource.Name.
func (r *REPL) cleanupEMRServerlessApplication(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	applicationID := resource.Metadata["application_id"]
	if applicationID == "" {
		applicationID = resource.Name
	}
	if applicationID == "" {
		return fmt.Errorf("no application_id in metadata for emrserverless:application '%s'", resource.Name)
	}
	client := emrserverless.NewFromConfig(config)
	_, err := client.DeleteApplication(ctx, &emrserverless.DeleteApplicationInput{
		ApplicationId: aws.String(applicationID),
	})
	return err
}

// cleanupEC2LaunchTemplateDefault restores an EC2 launch template's default version to its
// pre-exploitation value. Used to undo the ec2:ModifyLaunchTemplate call in ec2-005.
func (r *REPL) cleanupEC2LaunchTemplateDefault(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	templateID := resource.Metadata["template_id"]
	if templateID == "" {
		return fmt.Errorf("no template_id in metadata for ec2:launch-template-default '%s'", resource.Name)
	}
	originalVersion := resource.Metadata["original_version"]
	if originalVersion == "" {
		return fmt.Errorf("no original_version in metadata for ec2:launch-template-default '%s'", resource.Name)
	}

	client := ec2.NewFromConfig(config)
	_, err := client.ModifyLaunchTemplate(ctx, &ec2.ModifyLaunchTemplateInput{
		LaunchTemplateId: aws.String(templateID),
		DefaultVersion:   aws.String(originalVersion),
	})
	return err
}

// cleanupSSMAutomationDocument deletes an SSM Automation document created by ssm-003.
// The starting user for ssm-003 typically lacks ssm:DeleteDocument, so this cleanup
// handler is most useful when run with elevated credentials via 'workspace cleanup'.
func (r *REPL) cleanupSSMAutomationDocument(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	documentName := resource.Metadata["document_name"]
	if documentName == "" {
		documentName = resource.Name
	}
	if documentName == "" {
		return fmt.Errorf("no document_name in metadata for ssm:automation-document resource")
	}
	client := ssm.NewFromConfig(config)
	_, err := client.DeleteDocument(ctx, &ssm.DeleteDocumentInput{
		Name: aws.String(documentName),
	})
	return err
}

// cleanupKinesisAnalyticsApplication stops (if running) and deletes a Managed Apache Flink application.
// The DeleteApplication API requires the original CreateTimestamp, which is stored in resource Metadata.
func (r *REPL) cleanupKinesisAnalyticsApplication(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	client := kinesisanalyticsv2.NewFromConfig(config)

	// Attempt to stop the application first (best-effort — may already be stopped).
	_, stopErr := client.StopApplication(ctx, &kinesisanalyticsv2.StopApplicationInput{
		ApplicationName: aws.String(resource.Name),
		Force:           aws.Bool(true),
	})
	if stopErr != nil {
		fmt.Printf("Note: stop-application returned an error (may already be stopped): %v\n", stopErr)
	}

	// Wait briefly for the application to reach READY before deleting.
	stopDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(stopDeadline) {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 15*time.Second)
		descResult, descErr := client.DescribeApplication(waitCtx, &kinesisanalyticsv2.DescribeApplicationInput{
			ApplicationName: aws.String(resource.Name),
		})
		waitCancel()
		if descErr != nil || (descResult.ApplicationDetail != nil && descResult.ApplicationDetail.ApplicationStatus == katypes.ApplicationStatusReady) {
			break
		}
		time.Sleep(10 * time.Second)
	}

	// Re-fetch the CreateTimestamp (it may have incremented during stop).
	var createTimestamp *time.Time
	freshCtx, freshCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer freshCancel()
	descResult, descErr := client.DescribeApplication(freshCtx, &kinesisanalyticsv2.DescribeApplicationInput{
		ApplicationName: aws.String(resource.Name),
	})
	if descErr == nil && descResult.ApplicationDetail != nil {
		createTimestamp = descResult.ApplicationDetail.CreateTimestamp
	} else {
		ts, parseErr := time.Parse(time.RFC3339, resource.Metadata["create_timestamp"])
		if parseErr != nil {
			return fmt.Errorf("could not determine application CreateTimestamp for deletion: %v", parseErr)
		}
		createTimestamp = &ts
	}

	_, err := client.DeleteApplication(ctx, &kinesisanalyticsv2.DeleteApplicationInput{
		ApplicationName: aws.String(resource.Name),
		CreateTimestamp: createTimestamp,
	})
	return err
}

// cleanupEMRCluster terminates an EMR cluster created by an exploit module.
// The cluster ID must be stored in resource.Metadata["cluster_id"] or resource.Name.
func (r *REPL) cleanupEMRCluster(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}

	clusterID := resource.Metadata["cluster_id"]
	if clusterID == "" {
		clusterID = resource.Name
	}

	client := emr.NewFromConfig(config)
	_, err := client.TerminateJobFlows(ctx, &emr.TerminateJobFlowsInput{
		JobFlowIds: []string{clusterID},
	})
	return err
}

// cleanupGameLiftFleet deletes a GameLift fleet created by gamelift-001.
// The starting user for gamelift-001 typically lacks gamelift:DeleteFleet;
// run 'workspace cleanup' with admin credentials if this fails.
// GameLift fleets must be in a non-transitional state before they can be deleted.
func (r *REPL) cleanupGameLiftFleet(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	fleetID := resource.Metadata["fleet_id"]
	if fleetID == "" {
		fleetID = resource.ARN
	}
	if fleetID == "" {
		fleetID = resource.Name
	}
	client := gamelift.NewFromConfig(config)
	_, err := client.DeleteFleet(ctx, &gamelift.DeleteFleetInput{
		FleetId: aws.String(fleetID),
	})
	return err
}

// cleanupGameLiftBuild deletes a GameLift build created by gamelift-001.
// The starting user for gamelift-001 typically lacks gamelift:DeleteBuild;
// run 'workspace cleanup' with admin credentials if this fails.
// A build cannot be deleted while it is referenced by an active fleet.
func (r *REPL) cleanupGameLiftBuild(ctx context.Context, config aws.Config, resource CreatedResource) error {
	if resource.Region != "" {
		config.Region = resource.Region
	}
	buildID := resource.Metadata["build_id"]
	if buildID == "" {
		buildID = resource.ARN
	}
	if buildID == "" {
		buildID = resource.Name
	}
	client := gamelift.NewFromConfig(config)
	_, err := client.DeleteBuild(ctx, &gamelift.DeleteBuildInput{
		BuildId: aws.String(buildID),
	})
	return err
}

