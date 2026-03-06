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
