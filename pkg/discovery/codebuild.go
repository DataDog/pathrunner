package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"pathrunner/pkg/modules"
)

// DiscoverCodeBuildProjects lists CodeBuild projects and enriches each with
// service role information so the operator can identify privileged projects.
// Returns choices with project names as values.
func DiscoverCodeBuildProjects(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	cbClient := codebuild.NewFromConfig(config)

	listCtx, listCancel := context.WithTimeout(ctx, 30*time.Second)
	defer listCancel()

	// ListProjects returns names only; batch-fetch details separately.
	listResult, err := cbClient.ListProjects(listCtx, &codebuild.ListProjectsInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("PROJECT_NAME", "codebuild:ListProjects", err))
		}
		return nil, fmt.Errorf("failed to list CodeBuild projects: %v", err)
	}

	if len(listResult.Projects) == 0 {
		return nil, nil
	}

	// Batch-get project details to surface service role ARNs.
	batchCtx, batchCancel := context.WithTimeout(ctx, 30*time.Second)
	defer batchCancel()

	batchResult, err := cbClient.BatchGetProjects(batchCtx, &codebuild.BatchGetProjectsInput{
		Names: listResult.Projects,
	})
	if err != nil {
		// Fall back to name-only choices if BatchGetProjects fails.
		var choices []modules.DiscoveryChoice
		for _, name := range listResult.Projects {
			choices = append(choices, modules.DiscoveryChoice{
				Value: name,
				Label: name,
			})
		}
		return choices, nil
	}

	var choices []modules.DiscoveryChoice
	for _, proj := range batchResult.Projects {
		projName := aws.ToString(proj.Name)
		roleArn := aws.ToString(proj.ServiceRole)

		// Extract the short role name for display.
		roleName := roleArn
		if parts := strings.Split(roleArn, "/"); len(parts) > 1 {
			roleName = parts[len(parts)-1]
		}

		label := fmt.Sprintf("%s (role: %s)", projName, roleName)

		choices = append(choices, modules.DiscoveryChoice{
			Value: projName,
			Label: label,
			Metadata: map[string]string{
				"role_arn":  roleArn,
				"role_name": roleName,
			},
		})
	}

	return choices, nil
}
