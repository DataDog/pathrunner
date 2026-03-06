package version

import (
	"fmt"
	"runtime"
)

var (
	Version   = "0.1.0"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func Full() string {
	return fmt.Sprintf("v%s (%s)", Version, GitCommit)
}

func Info() string {
	return fmt.Sprintf("pathrunner v%s\ncommit: %s\nbuilt:  %s\ngo:     %s\nos:     %s/%s",
		Version, GitCommit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
