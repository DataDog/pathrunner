// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// DiscoverBedrockAgentRuntimes lists Bedrock AgentCore agent runtimes.
// Returns choices with runtime ARNs as values.
func DiscoverBedrockAgentRuntimes(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	client := bedrockagentcorecontrol.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := client.ListAgentRuntimes(listCtx, &bedrockagentcorecontrol.ListAgentRuntimesInput{
		MaxResults: aws.Int32(50),
	})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("TARGET_RUNTIME_ARN", "bedrock-agentcore:ListAgentRuntimes", err))
		}
		return nil, fmt.Errorf("failed to list Bedrock AgentCore runtimes: %v", err)
	}

	var choices []modules.DiscoveryChoice
	for _, runtime := range result.AgentRuntimes {
		arn := aws.ToString(runtime.AgentRuntimeArn)
		name := aws.ToString(runtime.AgentRuntimeName)
		status := string(runtime.Status)

		label := fmt.Sprintf("%s (%s)", name, status)

		choices = append(choices, modules.DiscoveryChoice{
			Value: arn,
			Label: label,
			Metadata: map[string]string{
				"name":   name,
				"status": status,
			},
		})
	}

	return choices, nil
}
