// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// DiscoverCodeDeployApps lists CodeDeploy applications.
// Returns choices with application names as values.
func DiscoverCodeDeployApps(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := codedeploy.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := client.ListApplications(listCtx, &codedeploy.ListApplicationsInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("APP_NAME", "codedeploy:ListApplications", err))
		}
		return nil, fmt.Errorf("failed to list CodeDeploy applications: %v", err)
	}

	if len(result.Applications) == 0 {
		return nil, nil
	}

	var choices []modules.DiscoveryChoice
	for _, appName := range result.Applications {
		choices = append(choices, modules.DiscoveryChoice{
			Value: appName,
			Label: appName,
		})
	}

	return choices, nil
}

// DiscoverCodeDeployGroups lists deployment groups for a given CodeDeploy application.
// Returns choices with deployment group names as values.
func DiscoverCodeDeployGroups(ctx context.Context, config aws.Config, appName string) ([]modules.DiscoveryChoice, error) {
	client := codedeploy.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := client.ListDeploymentGroups(listCtx, &codedeploy.ListDeploymentGroupsInput{
		ApplicationName: aws.String(appName),
	})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("DEPLOYMENT_GROUP", "codedeploy:ListDeploymentGroups", err))
		}
		return nil, fmt.Errorf("failed to list deployment groups for %s: %v", appName, err)
	}

	if len(result.DeploymentGroups) == 0 {
		return nil, nil
	}

	var choices []modules.DiscoveryChoice
	for _, groupName := range result.DeploymentGroups {
		choices = append(choices, modules.DiscoveryChoice{
			Value: groupName,
			Label: fmt.Sprintf("%s (app: %s)", groupName, appName),
		})
	}

	return choices, nil
}
