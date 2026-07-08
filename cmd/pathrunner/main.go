package main

import (
	"os"
	"pathrunner/pkg/cli"

	// Auto-generated exploit module registrations.
	// Run 'go generate ./pkg/exploits/' to regenerate after adding new modules.
	_ "pathrunner/pkg/exploits"

	// Payload registrations (manual — payload sub-packages import the parent payloads package)
	_ "pathrunner/pkg/payloads/ec2"
	_ "pathrunner/pkg/payloads/glue"
	_ "pathrunner/pkg/payloads/ecs"
	_ "pathrunner/pkg/payloads/lambda"
)

func main() {
	cliApp := cli.NewCLI()
	rootCmd := cliApp.CreateRootCommand()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
