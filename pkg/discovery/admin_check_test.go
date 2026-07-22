// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package discovery

import "testing"

func TestNormalizeARNForSimulator(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "assumed role ARN",
			input:    "arn:aws:sts::697683661464:assumed-role/pl-prod-lambda-006-to-admin-target-role/pathrunner-1772570881",
			expected: "arn:aws:iam::697683661464:role/pl-prod-lambda-006-to-admin-target-role",
		},
		{
			name:     "IAM role ARN unchanged",
			input:    "arn:aws:iam::123456789012:role/MyRole",
			expected: "arn:aws:iam::123456789012:role/MyRole",
		},
		{
			name:     "IAM user ARN unchanged",
			input:    "arn:aws:iam::123456789012:user/MyUser",
			expected: "arn:aws:iam::123456789012:user/MyUser",
		},
		{
			name:     "assumed role with path",
			input:    "arn:aws:sts::111111111111:assumed-role/some-role/some-session",
			expected: "arn:aws:iam::111111111111:role/some-role",
		},
		{
			name:     "govcloud assumed role",
			input:    "arn:aws-us-gov:sts::222222222222:assumed-role/GovRole/session",
			expected: "arn:aws-us-gov:iam::222222222222:role/GovRole",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeARNForSimulator(tc.input)
			if result != tc.expected {
				t.Errorf("NormalizeARNForSimulator(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}
