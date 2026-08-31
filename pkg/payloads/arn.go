// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package payloads

import "strings"

// PrincipalFromARN parses an IAM ARN or plain name into a principal name and type.
// Supported ARN formats:
//
//	arn:aws:iam::ACCOUNT:user/USERNAME              → ("USERNAME", "user")
//	arn:aws:iam::ACCOUNT:role/ROLENAME              → ("ROLENAME", "role")
//	arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION  → ("ROLE", "role")
//
// Plain names (no ARN prefix) are treated as IAM users.
func PrincipalFromARN(input string) (name, principalType string) {
	switch {
	case strings.Contains(input, ":user/"):
		idx := strings.LastIndex(input, "/")
		return input[idx+1:], "user"
	case strings.Contains(input, ":assumed-role/"):
		// arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
		last := strings.LastIndex(input, "/")
		if last > 0 {
			prev := strings.LastIndex(input[:last], "/")
			if prev >= 0 {
				return input[prev+1 : last], "role"
			}
		}
	case strings.Contains(input, ":role/"):
		idx := strings.LastIndex(input, "/")
		return input[idx+1:], "role"
	}
	// Plain name — treat as IAM user.
	return input, "user"
}
