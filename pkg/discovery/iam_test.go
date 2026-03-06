package discovery

import (
	"testing"
)

func TestTrustsAWSPrincipal(t *testing.T) {
	callerArn := "arn:aws:iam::123456789012:user/TestUser"
	callerAccount := "123456789012"

	testCases := []struct {
		name      string
		policyDoc string
		expected  bool
	}{
		{
			name: "wildcard principal",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": "*",
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: true,
		},
		{
			name: "account root matches any principal in account",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: true,
		},
		{
			name: "exact user ARN match",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:user/TestUser"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: true,
		},
		{
			name: "different user does not match",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:user/OtherUser"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: false,
		},
		{
			name: "different account does not match",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::999999999999:root"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: false,
		},
		{
			name: "principal array with matching entry",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": [
						"arn:aws:iam::999999999999:root",
						"arn:aws:iam::123456789012:user/TestUser"
					]},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: true,
		},
		{
			name: "principal array without matching entry",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": [
						"arn:aws:iam::999999999999:root",
						"arn:aws:iam::888888888888:user/Other"
					]},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: false,
		},
		{
			name: "deny statement is ignored",
			policyDoc: `{
				"Statement": [{
					"Effect": "Deny",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: false,
		},
		{
			name: "service principal only does not match",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"Service": "lambda.amazonaws.com"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: false,
		},
		{
			name: "action is sts:* matches",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:*"
				}]
			}`,
			expected: true,
		},
		{
			name: "action array includes sts:AssumeRole",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": ["sts:AssumeRole", "sts:TagSession"]
				}]
			}`,
			expected: true,
		},
		{
			name: "action does not include sts:AssumeRole",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:AssumeRoleWithSAML"
				}]
			}`,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := trustsAWSPrincipal(tc.policyDoc, callerArn, callerAccount)
			if result != tc.expected {
				t.Errorf("trustsAWSPrincipal() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestTrustsAWSPrincipalAssumedRole(t *testing.T) {
	// When the caller is an assumed role, the ARN looks different
	callerArn := "arn:aws:sts::123456789012:assumed-role/MyRole/session-name"
	callerAccount := "123456789012"

	testCases := []struct {
		name      string
		policyDoc string
		expected  bool
	}{
		{
			name: "trust policy references the role ARN",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/MyRole"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: true,
		},
		{
			name: "trust policy references a different role",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/OtherRole"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: false,
		},
		{
			name: "account root still matches",
			policyDoc: `{
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := trustsAWSPrincipal(tc.policyDoc, callerArn, callerAccount)
			if result != tc.expected {
				t.Errorf("trustsAWSPrincipal() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestNormalizeCallerArn(t *testing.T) {
	testCases := []struct {
		name     string
		arn      string
		account  string
		expected string
	}{
		{
			name:     "assumed-role ARN is normalized",
			arn:      "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
			account:  "123456789012",
			expected: "arn:aws:iam::123456789012:role/MyRole",
		},
		{
			name:     "user ARN is unchanged",
			arn:      "arn:aws:iam::123456789012:user/TestUser",
			account:  "123456789012",
			expected: "arn:aws:iam::123456789012:user/TestUser",
		},
		{
			name:     "role ARN is unchanged",
			arn:      "arn:aws:iam::123456789012:role/MyRole",
			account:  "123456789012",
			expected: "arn:aws:iam::123456789012:role/MyRole",
		},
		{
			name:     "assumed-role with path",
			arn:      "arn:aws:sts::123456789012:assumed-role/path/to/Role/session",
			account:  "123456789012",
			expected: "arn:aws:iam::123456789012:role/path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeCallerArn(tc.arn, tc.account)
			if result != tc.expected {
				t.Errorf("normalizeCallerArn(%q) = %q, want %q", tc.arn, result, tc.expected)
			}
		})
	}
}

func TestActionAllowsAssumeRole(t *testing.T) {
	testCases := []struct {
		name     string
		action   any
		expected bool
	}{
		{name: "exact match", action: "sts:AssumeRole", expected: true},
		{name: "sts wildcard", action: "sts:*", expected: true},
		{name: "full wildcard", action: "*", expected: true},
		{name: "different action", action: "sts:AssumeRoleWithSAML", expected: false},
		{name: "array with match", action: []any{"sts:TagSession", "sts:AssumeRole"}, expected: true},
		{name: "array without match", action: []any{"sts:TagSession", "sts:GetSessionToken"}, expected: false},
		{name: "nil action is permissive", action: nil, expected: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := actionAllowsAssumeRole(tc.action)
			if result != tc.expected {
				t.Errorf("actionAllowsAssumeRole(%v) = %v, want %v", tc.action, result, tc.expected)
			}
		})
	}
}
