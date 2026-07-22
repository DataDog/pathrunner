// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package discovery

import (
	"fmt"
	"strings"
)

// IsAccessDenied checks if an AWS error is an access denied error.
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "AccessDenied") ||
		strings.Contains(msg, "UnauthorizedAccess") ||
		strings.Contains(msg, "AccessDeniedException") ||
		strings.Contains(msg, "is not authorized to perform")
}

// FormatPermissionError produces a user-friendly error message when
// discovery fails due to missing permissions.
func FormatPermissionError(optionName, permission string, err error) string {
	return fmt.Sprintf(
		"Cannot auto-discover %s: you need '%s' permission.\n  Set it manually: set %s <value>\n  Original error: %v",
		optionName, permission, optionName, err,
	)
}
