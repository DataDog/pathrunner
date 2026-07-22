// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package utils

import (
	"fmt"
	"strings"
)

// ExtractAccountIDFromARN extracts the account ID from an AWS ARN.
// ARN format: arn:partition:service:region:account-id:resource
func ExtractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// ParseLambdaTimeout parses and validates a Lambda function timeout value (1-900 seconds).
func ParseLambdaTimeout(s string) (int32, error) {
	var timeout int
	if _, err := fmt.Sscanf(s, "%d", &timeout); err != nil {
		return 0, err
	}
	if timeout < 1 || timeout > 900 {
		return 0, fmt.Errorf("timeout must be between 1 and 900 seconds")
	}
	return int32(timeout), nil
}

// ParseLambdaMemorySize parses and validates a Lambda function memory size (128-10240 MB).
func ParseLambdaMemorySize(s string) (int32, error) {
	var memory int
	if _, err := fmt.Sscanf(s, "%d", &memory); err != nil {
		return 0, err
	}
	if memory < 128 || memory > 10240 {
		return 0, fmt.Errorf("memory size must be between 128 and 10240 MB")
	}
	return int32(memory), nil
}
