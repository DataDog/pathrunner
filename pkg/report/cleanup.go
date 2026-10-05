// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package report

import "fmt"

// CleanupCommand returns the AWS CLI command(s) needed to clean up a resource.
// Returns an empty string for unknown types. Multiple commands are newline-separated.
func CleanupCommand(res Resource) string {
	region := res.Region
	if region == "" {
		region = "us-east-1"
	}

	switch res.Type {
	case "lambda:function":
		return fmt.Sprintf("aws lambda delete-function --function-name %s --region %s", res.Name, region)
	case "lambda:event-source-mapping":
		uuid := res.Metadata["uuid"]
		if uuid == "" {
			uuid = res.Name
		}
		return fmt.Sprintf("aws lambda delete-event-source-mapping --uuid %s --region %s", uuid, region)
	case "lambda:permission":
		funcName := res.Metadata["function_name"]
		stmtID := res.Metadata["statement_id"]
		return fmt.Sprintf("aws lambda remove-permission --function-name %s --statement-id %s --region %s", funcName, stmtID, region)
	case "ec2:instance":
		instanceID := res.Metadata["instance_id"]
		if instanceID == "" {
			instanceID = res.Name
		}
		return fmt.Sprintf("aws ec2 terminate-instances --instance-ids %s --region %s", instanceID, region)
	case "ec2:spot-instance-request":
		spotRequestID := res.Metadata["spot_request_id"]
		if spotRequestID == "" {
			spotRequestID = res.Name
		}
		return fmt.Sprintf("aws ec2 cancel-spot-instance-requests --spot-instance-request-ids %s --region %s", spotRequestID, region)
	case "iam:attached-policy":
		principalType := res.Metadata["principal_type"]
		principalName := res.Metadata["principal_name"]
		policyArn := res.Metadata["policy_arn"]
		switch principalType {
		case "role":
			return fmt.Sprintf("aws iam detach-role-policy --role-name %s --policy-arn %s", principalName, policyArn)
		case "group":
			return fmt.Sprintf("aws iam detach-group-policy --group-name %s --policy-arn %s", principalName, policyArn)
		default:
			return fmt.Sprintf("aws iam detach-user-policy --user-name %s --policy-arn %s", principalName, policyArn)
		}
	case "iam:inline-policy":
		principalType := res.Metadata["principal_type"]
		principalName := res.Metadata["principal_name"]
		policyName := res.Metadata["policy_name"]
		switch principalType {
		case "role":
			return fmt.Sprintf("aws iam delete-role-policy --role-name %s --policy-name %s", principalName, policyName)
		case "group":
			return fmt.Sprintf("aws iam delete-group-policy --group-name %s --policy-name %s", principalName, policyName)
		default:
			return fmt.Sprintf("aws iam delete-user-policy --user-name %s --policy-name %s", principalName, policyName)
		}
	case "iam:group-membership":
		userName := res.Metadata["user_name"]
		groupName := res.Metadata["group_name"]
		return fmt.Sprintf("aws iam remove-user-from-group --user-name %s --group-name %s", userName, groupName)
	case "iam:trust-policy":
		roleName := res.Metadata["role_name"]
		return fmt.Sprintf("aws iam update-assume-role-policy --role-name %s --policy-document '<original-trust-policy>'", roleName)
	case "iam:policy-version":
		policyArn := res.Metadata["policy_arn"]
		versionID := res.Metadata["version_id"]
		return fmt.Sprintf("aws iam delete-policy-version --policy-arn %s --version-id %s", policyArn, versionID)
	case "iam:access-key":
		username := res.Metadata["username"]
		accessKeyID := res.Metadata["access_key_id"]
		if accessKeyID == "" {
			accessKeyID = res.Name
		}
		return fmt.Sprintf("aws iam delete-access-key --user-name %s --access-key-id %s", username, accessKeyID)
	case "iam:login-profile":
		username := res.Metadata["username"]
		if username == "" {
			username = res.Name
		}
		return fmt.Sprintf("aws iam delete-login-profile --user-name %s", username)
	case "iam:role":
		return fmt.Sprintf("aws iam delete-role --role-name %s", res.Name)
	case "iam:user":
		return fmt.Sprintf("aws iam delete-user --user-name %s", res.Name)
	case "ecs:service":
		cluster := res.Metadata["cluster"]
		return fmt.Sprintf("aws ecs delete-service --cluster %s --service %s --force --region %s", cluster, res.Name, region)
	case "ecs:cluster":
		return fmt.Sprintf("aws ecs delete-cluster --cluster %s --region %s", res.Name, region)
	case "s3_bucket":
		return fmt.Sprintf("aws s3 rm s3://%s --recursive --region %s\naws s3api delete-bucket --bucket %s --region %s", res.Name, region, res.Name, region)
	case "glue:dev-endpoint":
		return fmt.Sprintf("aws glue delete-dev-endpoint --endpoint-name %s --region %s", res.Name, region)
	case "glue:job":
		return fmt.Sprintf("aws glue delete-job --job-name %s --region %s", res.Name, region)
	case "glue:session":
		return fmt.Sprintf("aws glue stop-session --id %s --region %s\naws glue delete-session --id %s --region %s", res.Name, region, res.Name, region)
	case "glue:trigger":
		return fmt.Sprintf("aws glue stop-trigger --name %s --region %s\naws glue delete-trigger --name %s --region %s", res.Name, region, res.Name, region)
	case "imagebuilder:component":
		componentArn := res.Metadata["component_arn"]
		if componentArn == "" {
			componentArn = res.ARN
		}
		return fmt.Sprintf("aws imagebuilder delete-component --component-build-version-arn %s --region %s", componentArn, region)
	case "imagebuilder:recipe":
		recipeArn := res.Metadata["recipe_arn"]
		if recipeArn == "" {
			recipeArn = res.ARN
		}
		return fmt.Sprintf("aws imagebuilder delete-image-recipe --image-recipe-arn %s --region %s", recipeArn, region)
	case "imagebuilder:infra-config":
		infraArn := res.Metadata["infra_config_arn"]
		if infraArn == "" {
			infraArn = res.ARN
		}
		return fmt.Sprintf("aws imagebuilder delete-infrastructure-configuration --infrastructure-configuration-arn %s --region %s", infraArn, region)
	case "imagebuilder:image":
		imageArn := res.Metadata["image_build_arn"]
		if imageArn == "" {
			imageArn = res.ARN
		}
		return fmt.Sprintf("aws imagebuilder cancel-image-creation --image-build-version-arn %s --region %s 2>/dev/null || true\naws imagebuilder delete-image --image-build-version-arn %s --region %s", imageArn, region, imageArn, region)
	case "kinesisanalyticsv2:application":
		createTimestamp := res.Metadata["create_timestamp"]
		return fmt.Sprintf("# Stop the application first, then delete using its original CreateTimestamp\naws kinesisanalyticsv2 stop-application --application-name %s --force --region %s 2>/dev/null || true\naws kinesisanalyticsv2 delete-application --application-name %s --create-timestamp %s --region %s", res.Name, region, res.Name, createTimestamp, region)
	case "local:file":
		path := res.Metadata["path"]
		if path == "" {
			path = res.Name
		}
		return fmt.Sprintf("rm -f %s", path)
	case "batch:job-definition":
		jobDefArn := res.Metadata["job_definition_arn"]
		if jobDefArn == "" {
			jobDefArn = res.ARN
		}
		if jobDefArn == "" {
			jobDefArn = res.Name
		}
		return fmt.Sprintf("aws batch deregister-job-definition --job-definition %s --region %s", jobDefArn, region)
	case "batch:job-queue":
		queueName := res.Metadata["job_queue_name"]
		if queueName == "" {
			queueName = res.Name
		}
		return fmt.Sprintf("aws batch update-job-queue --job-queue %s --state DISABLED --region %s\naws batch delete-job-queue --job-queue %s --region %s", queueName, region, queueName, region)
	case "batch:compute-environment":
		ceName := res.Metadata["compute_environment_name"]
		if ceName == "" {
			ceName = res.Name
		}
		return fmt.Sprintf("aws batch update-compute-environment --compute-environment %s --state DISABLED --region %s\naws batch delete-compute-environment --compute-environment %s --region %s", ceName, region, ceName, region)
	case "bedrock-agentcore:code-interpreter":
		interpreterID := res.Metadata["interpreter_id"]
		if interpreterID == "" {
			interpreterID = res.Name
		}
		return fmt.Sprintf("aws bedrock-agentcore-control delete-code-interpreter --code-interpreter-id %s --region %s", interpreterID, region)
	case "bedrock-agentcore:agent-runtime":
		runtimeID := res.Metadata["runtime_id"]
		if runtimeID == "" {
			runtimeID = res.Name
		}
		return fmt.Sprintf("aws bedrock-agentcore-control delete-agent-runtime --agent-runtime-id %s --region %s", runtimeID, region)
	case "bedrock-agentcore:browser":
		browserID := res.Metadata["browser_id"]
		if browserID == "" {
			browserID = res.Name
		}
		return fmt.Sprintf("aws bedrock-agentcore-control delete-browser --browser-id %s --region %s", browserID, region)
	case "bedrock-agentcore:harness":
		harnessID := res.Metadata["harness_id"]
		if harnessID == "" {
			harnessID = res.Name
		}
		return fmt.Sprintf("aws bedrock-agentcore-control delete-harness --harness-id %s --region %s", harnessID, region)
	case "apprunner:service":
		serviceArn := res.Metadata["service_arn"]
		if serviceArn == "" {
			serviceArn = res.ARN
		}
		if serviceArn == "" {
			serviceArn = res.Name
		}
		return fmt.Sprintf("aws apprunner delete-service --service-arn %s --region %s", serviceArn, region)
	case "braket:job":
		jobArn := res.ARN
		if jobArn == "" {
			jobArn = res.Name
		}
		return fmt.Sprintf("aws braket cancel-job --job-arn %s --region %s", jobArn, region)
	case "cloudformation:stack":
		stackName := res.Metadata["stack_name"]
		if stackName == "" {
			stackName = res.Name
		}
		return fmt.Sprintf("aws cloudformation delete-stack --stack-name %s --region %s", stackName, region)
	case "cloudformation:stack-update":
		stackName := res.Metadata["stack_name"]
		if stackName == "" {
			stackName = res.Name
		}
		changeSetName := "pathrunner-revert-" + stackName
		return fmt.Sprintf("# Revert the stack to its original template via a change set\n"+
			"aws cloudformation create-change-set --stack-name %s --change-set-name %s --change-set-type UPDATE --template-body '<original-template-body>' --region %s\n"+
			"aws cloudformation execute-change-set --change-set-name %s --stack-name %s --region %s",
			stackName, changeSetName, region, changeSetName, stackName, region)
	case "cloudformation:stackset":
		stackSetName := res.Metadata["stackset_name"]
		if stackSetName == "" {
			stackSetName = res.Name
		}
		accountID := res.Metadata["account_id"]
		targetRegion := res.Metadata["target_region"]
		if targetRegion == "" {
			targetRegion = region
		}
		return fmt.Sprintf("# Delete stack instances first, then the stack set\n"+
			"aws cloudformation delete-stack-instances --stack-set-name %s --accounts %s --regions %s --no-retain-stacks --region %s\n"+
			"# Wait for the operation to complete, then:\n"+
			"aws cloudformation delete-stack-set --stack-set-name %s --region %s",
			stackSetName, accountID, targetRegion, region, stackSetName, region)
	case "cloudformation:stackset-update":
		stackSetName := res.Metadata["stackset_name"]
		if stackSetName == "" {
			stackSetName = res.Name
		}
		return fmt.Sprintf("# Revert the stack set to its original template\n"+
			"aws cloudformation update-stack-set --stack-set-name %s --template-body '<original-template-body>' --region %s",
			stackSetName, region)
	case "codebuild:project":
		projectName := res.Metadata["project_name"]
		if projectName == "" {
			projectName = res.Name
		}
		return fmt.Sprintf("aws codebuild delete-project --name %s --region %s", projectName, region)
	case "cognito-identity:identity-pool-roles":
		identityPoolID := res.Metadata["identity_pool_id"]
		if identityPoolID == "" {
			identityPoolID = res.Name
		}
		return fmt.Sprintf("# Remove the malicious unauthenticated role binding from the identity pool\n"+
			"# First check the current roles:\n"+
			"aws cognito-identity get-identity-pool-roles --identity-pool-id %s --region %s\n"+
			"# Then restore or clear the unauthenticated role:\n"+
			"aws cognito-identity set-identity-pool-roles --identity-pool-id %s --roles '{}' --region %s",
			identityPoolID, region, identityPoolID, region)
	case "ec2:launch-template-version":
		templateID := res.Metadata["template_id"]
		if templateID == "" {
			templateID = res.Name
		}
		versionNumber := res.Metadata["version_number"]
		if versionNumber == "" {
			versionNumber = "<version-number>"
		}
		return fmt.Sprintf("aws ec2 delete-launch-template-versions --launch-template-id %s --versions %s --region %s", templateID, versionNumber, region)
	case "ec2:launch-template-default":
		templateID := res.Metadata["template_id"]
		if templateID == "" {
			templateID = res.Name
		}
		originalVersion := res.Metadata["original_version"]
		if originalVersion == "" {
			originalVersion = "<original-version-number>"
		}
		return fmt.Sprintf("aws ec2 modify-launch-template --launch-template-id %s --default-version %s --region %s", templateID, originalVersion, region)
	case "ec2:userdata":
		instanceID := res.Metadata["instance_id"]
		if instanceID == "" {
			instanceID = res.Name
		}
		originalUserData := res.Metadata["original_userdata"]
		if originalUserData == "" {
			originalUserData = "<original-base64-userdata>"
		}
		return fmt.Sprintf("# Stop instance, restore original user-data, then restart\n"+
			"aws ec2 stop-instances --instance-ids %s --region %s\n"+
			"# Wait for stopped state:\n"+
			"aws ec2 wait instance-stopped --instance-ids %s --region %s\n"+
			"aws ec2 modify-instance-attribute --instance-id %s --user-data Value=%s --region %s\n"+
			"aws ec2 start-instances --instance-ids %s --region %s",
			instanceID, region, instanceID, region, instanceID, originalUserData, region, instanceID, region)
	case "ecs:task-definition":
		taskDefArn := res.ARN
		if taskDefArn == "" {
			revision := res.Metadata["revision"]
			if revision != "" {
				taskDefArn = res.Name + ":" + revision
			} else {
				taskDefArn = res.Name
			}
		}
		return fmt.Sprintf("aws ecs deregister-task-definition --task-definition %s --region %s\naws ecs delete-task-definitions --task-definitions %s --region %s",
			taskDefArn, region, taskDefArn, region)
	case "ecs:task":
		cluster := res.Metadata["cluster"]
		taskArn := res.ARN
		if taskArn == "" {
			taskArn = res.Name
		}
		return fmt.Sprintf("aws ecs stop-task --cluster %s --task %s --region %s", cluster, taskArn, region)
	case "emr:cluster":
		clusterID := res.Metadata["cluster_id"]
		if clusterID == "" {
			clusterID = res.Name
		}
		return fmt.Sprintf("aws emr terminate-clusters --cluster-ids %s --region %s", clusterID, region)
	case "emrserverless:application":
		applicationID := res.Metadata["application_id"]
		if applicationID == "" {
			applicationID = res.Name
		}
		return fmt.Sprintf("aws emr-serverless delete-application --application-id %s --region %s", applicationID, region)
	case "gamelift:build":
		buildID := res.Metadata["build_id"]
		if buildID == "" {
			buildID = res.ARN
		}
		if buildID == "" {
			buildID = res.Name
		}
		return fmt.Sprintf("aws gamelift delete-build --build-id %s --region %s", buildID, region)
	case "gamelift:fleet":
		fleetID := res.Metadata["fleet_id"]
		if fleetID == "" {
			fleetID = res.ARN
		}
		if fleetID == "" {
			fleetID = res.Name
		}
		return fmt.Sprintf("aws gamelift delete-fleet --fleet-id %s --region %s", fleetID, region)
	case "omics:workflow":
		workflowID := res.Metadata["workflow_id"]
		if workflowID == "" {
			workflowID = res.Name
		}
		return fmt.Sprintf("aws omics delete-workflow --id %s --region %s", workflowID, region)
	case "omics:run":
		runID := res.Metadata["run_id"]
		if runID == "" {
			runID = res.Name
		}
		return fmt.Sprintf("aws omics cancel-run --id %s --region %s 2>/dev/null || true\naws omics delete-run --id %s --region %s", runID, region, runID, region)
	case "ssm:automation-document":
		documentName := res.Metadata["document_name"]
		if documentName == "" {
			documentName = res.Name
		}
		return fmt.Sprintf("aws ssm delete-document --name %s --region %s", documentName, region)
	case "lambda:function-code":
		functionName := res.Metadata["function_name"]
		if functionName == "" {
			functionName = res.Name
		}
		return fmt.Sprintf(
			"# Lambda function '%s' code was modified and not restored. Restore via Terraform or:\n"+
				"# aws lambda update-function-code --function-name %s --zip-file fileb://<original-code.zip> --region %s",
			functionName, functionName, region)
	case "glue:job-update":
		jobName := res.Metadata["job_name"]
		if jobName == "" {
			jobName = res.Name
		}
		originalRoleArn := res.Metadata["original_role_arn"]
		if originalRoleArn == "" {
			originalRoleArn = "<original-role-arn>"
		}
		originalScript := res.Metadata["original_script"]
		if originalScript == "" {
			originalScript = "<original-script-s3-uri>"
		}
		return fmt.Sprintf(
			"aws glue update-job --job-name %s --job-update '{\"Role\":\"%s\",\"Command\":{\"Name\":\"pythonshell\",\"ScriptLocation\":\"%s\",\"PythonVersion\":\"3.9\"}}' --region %s",
			jobName, originalRoleArn, originalScript, region)
	case "apprunner:service-update":
		serviceArn := res.Metadata["service_arn"]
		if serviceArn == "" {
			serviceArn = res.ARN
		}
		if serviceArn == "" {
			serviceArn = res.Name
		}
		serviceName := res.Metadata["service_name"]
		if serviceName == "" {
			serviceName = res.Name
		}
		return fmt.Sprintf(
			"# App Runner service '%s' was updated with exploit config and not restored.\n"+
				"# Restore the original image/StartCommand via the console or:\n"+
				"aws apprunner update-service --service-arn %s --source-configuration '<original-source-config>' --region %s",
			serviceName, serviceArn, region)
	case "iam:login-profile-update":
		username := res.Metadata["username"]
		if username == "" {
			username = res.Name
		}
		return fmt.Sprintf(
			"# IAM user '%s' login profile password was changed. The original password cannot be recovered.\n"+
				"# Reset it to a new known value or have the user change it:\n"+
				"aws iam update-login-profile --user-name %s --password '<new-password>' --no-password-reset-required",
			username, username)
	default:
		return fmt.Sprintf("# %s: %s (manual cleanup required)", res.Type, res.Name)
	}
}
