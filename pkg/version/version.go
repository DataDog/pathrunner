// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package version

import (
	"fmt"
	"runtime"
	"strings"
)

var (
	Version   = "0.1.0"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Full returns the version string. For release builds (clean semver, no pre-release suffix),
// the git commit hash is omitted. For dev/pre-release builds, the hash is included.
func Full() string {
	if !strings.Contains(Version, "-") {
		return fmt.Sprintf("v%s", Version)
	}
	return fmt.Sprintf("v%s (%s)", Version, GitCommit)
}

func Info() string {
	return fmt.Sprintf("pathrunner v%s\ncommit: %s\nbuilt:  %s\ngo:     %s\nos:     %s/%s",
		Version, GitCommit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
