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
	_ "pathrunner/pkg/payloads/amplify"
	_ "pathrunner/pkg/payloads/apprunner"
	_ "pathrunner/pkg/payloads/batch"
	_ "pathrunner/pkg/payloads/bedrock"
	_ "pathrunner/pkg/payloads/braket"
	_ "pathrunner/pkg/payloads/cloudformation"
	_ "pathrunner/pkg/payloads/codebuild"
	_ "pathrunner/pkg/payloads/codedeploy"
	_ "pathrunner/pkg/payloads/ssm"
	_ "pathrunner/pkg/payloads/cognitoidentity"
	_ "pathrunner/pkg/payloads/emr"
	_ "pathrunner/pkg/payloads/emrserverless"
	_ "pathrunner/pkg/payloads/gamelift"
	_ "pathrunner/pkg/payloads/imagebuilder"
	_ "pathrunner/pkg/payloads/kinesisanalytics"
	_ "pathrunner/pkg/payloads/omics"
)

func main() {
	cliApp := cli.NewCLI()
	rootCmd := cliApp.CreateRootCommand()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if code := cli.ExitCode(); code != 0 {
		os.Exit(code)
	}
}
