package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// DiscoverBatchJobDefinitions lists active Batch job definitions and enriches each
// with the jobRoleArn so the operator can identify definitions with privileged roles.
// Returns choices with job definition names as values.
func DiscoverBatchJobDefinitions(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	batchClient := batch.NewFromConfig(config)

	listCtx, listCancel := context.WithTimeout(ctx, 30*time.Second)
	defer listCancel()

	output, err := batchClient.DescribeJobDefinitions(listCtx, &batch.DescribeJobDefinitionsInput{
		Status: aws.String("ACTIVE"),
	})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("JOB_DEFINITION", "batch:DescribeJobDefinitions", err))
		}
		return nil, fmt.Errorf("failed to describe Batch job definitions: %v", err)
	}

	var choices []modules.DiscoveryChoice
	for _, jd := range output.JobDefinitions {
		name := aws.ToString(jd.JobDefinitionName)

		// Extract jobRoleArn for display, preferring container properties.
		roleArn := extractJobRoleArn(jd)
		roleName := roleArn
		if parts := strings.Split(roleArn, "/"); len(parts) > 1 {
			roleName = parts[len(parts)-1]
		}

		var label string
		if roleArn != "" {
			label = fmt.Sprintf("%s (role: %s)", name, roleName)
		} else {
			label = fmt.Sprintf("%s (no jobRoleArn)", name)
		}

		choices = append(choices, modules.DiscoveryChoice{
			Value: name,
			Label: label,
			Metadata: map[string]string{
				"role_arn":  roleArn,
				"role_name": roleName,
			},
		})
	}

	return choices, nil
}

// DiscoverBatchJobQueues lists active Batch job queues.
// Returns choices with job queue names as values.
func DiscoverBatchJobQueues(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	batchClient := batch.NewFromConfig(config)

	listCtx, listCancel := context.WithTimeout(ctx, 30*time.Second)
	defer listCancel()

	output, err := batchClient.DescribeJobQueues(listCtx, &batch.DescribeJobQueuesInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("JOB_QUEUE", "batch:DescribeJobQueues", err))
		}
		return nil, fmt.Errorf("failed to describe Batch job queues: %v", err)
	}

	var choices []modules.DiscoveryChoice
	for _, jq := range output.JobQueues {
		name := aws.ToString(jq.JobQueueName)
		state := string(jq.State)
		label := fmt.Sprintf("%s (state: %s)", name, state)

		choices = append(choices, modules.DiscoveryChoice{
			Value: name,
			Label: label,
			Metadata: map[string]string{
				"state": state,
			},
		})
	}

	return choices, nil
}

// extractJobRoleArn pulls the jobRoleArn from a job definition, checking both
// container properties (EC2/Fargate) and EKS properties.
func extractJobRoleArn(jd batchtypes.JobDefinition) string {
	if jd.ContainerProperties != nil {
		return aws.ToString(jd.ContainerProperties.JobRoleArn)
	}
	if jd.EksProperties != nil && jd.EksProperties.PodProperties != nil {
		return aws.ToString(jd.EksProperties.PodProperties.ServiceAccountName)
	}
	return ""
}
