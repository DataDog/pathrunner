// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/DataDog/pathrunner/pkg/modules"
)

// LambdaFunctionInfo contains discovered Lambda function information.
type LambdaFunctionInfo struct {
	FunctionName string
	FunctionArn  string
	Runtime      string
	Handler      string
	RoleArn      string
	RoleName     string
	HasAdmin     bool
}

// DiscoverLambdaFunctions lists Lambda functions and enriches them with
// execution role information. Returns choices with function names as values.
func DiscoverLambdaFunctions(ctx context.Context, config aws.Config) ([]modules.DiscoveryChoice, error) {
	lambdaClient := lambda.NewFromConfig(config)

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result, err := lambdaClient.ListFunctions(listCtx, &lambda.ListFunctionsInput{})
	if err != nil {
		if IsAccessDenied(err) {
			return nil, fmt.Errorf("%s", FormatPermissionError("FUNCTION_NAME", "lambda:ListFunctions", err))
		}
		return nil, fmt.Errorf("failed to list Lambda functions: %v", err)
	}

	var choices []modules.DiscoveryChoice
	for _, fn := range result.Functions {
		funcName := aws.ToString(fn.FunctionName)
		roleArn := aws.ToString(fn.Role)
		runtime := string(fn.Runtime)
		handler := aws.ToString(fn.Handler)

		// Extract role name from ARN
		roleName := roleArn
		if parts := strings.Split(roleArn, "/"); len(parts) > 1 {
			roleName = parts[len(parts)-1]
		}

		label := fmt.Sprintf("%s (role: %s, runtime: %s)", funcName, roleName, runtime)

		choices = append(choices, modules.DiscoveryChoice{
			Value: funcName,
			Label: label,
			Metadata: map[string]string{
				"function_arn": aws.ToString(fn.FunctionArn),
				"role_arn":     roleArn,
				"role_name":    roleName,
				"runtime":      runtime,
				"handler":      handler,
			},
		})
	}

	return choices, nil
}
