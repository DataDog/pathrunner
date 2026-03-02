package main

import (
	"os"
	"pathrunner/pkg/cli"

	// Import payloads to register them
	_ "pathrunner/pkg/payloads/ec2"
	_ "pathrunner/pkg/payloads/lambda"

	// Import modules to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/sts_assume_role"
)

func main() {
	cliApp := cli.NewCLI()
	rootCmd := cliApp.CreateRootCommand()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}