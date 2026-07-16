package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// DiscoverGlueJobs lists existing Glue jobs and returns them as discovery choices.
// Each choice includes the job name as the value and the current role as metadata.
func DiscoverGlueJobs(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	glueClient := glue.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := glueClient.ListJobs(listCtx, &glue.ListJobsInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("JOB_NAME", "glue:ListJobs", err))
		}
		return nil, fmt.Errorf("failed to list Glue jobs: %v", err)
	}

	var choices []modules.DiscoveryChoice
	for _, jobName := range result.JobNames {
		if jobName == "" {
			continue
		}

		// Try to get job details (role) — skip if we don't have glue:GetJob
		var roleLabel string
		getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
		jobDetail, err := glueClient.GetJob(getCtx, &glue.GetJobInput{
			JobName: aws.String(jobName),
		})
		getCancel()
		if err == nil && jobDetail.Job != nil {
			roleArn := aws.ToString(jobDetail.Job.Role)
			roleName := roleArn
			if parts := strings.Split(roleArn, "/"); len(parts) > 1 {
				roleName = parts[len(parts)-1]
			}
			roleLabel = fmt.Sprintf(" (role: %s)", roleName)
		}

		label := fmt.Sprintf("%s%s", jobName, roleLabel)
		choices = append(choices, modules.DiscoveryChoice{
			Value: jobName,
			Label: label,
			Metadata: map[string]string{
				"job_name": jobName,
			},
		})
	}

	return choices, nil
}
