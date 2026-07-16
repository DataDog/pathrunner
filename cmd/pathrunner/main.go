package main

import (
	"os"
	"github.com/DataDog/pathrunner/pkg/cli"

	// Auto-generated exploit module registrations.
	// Run 'go generate ./pkg/exploits/' to regenerate after adding new modules.
	_ "github.com/DataDog/pathrunner/pkg/exploits"

	// Payload registrations (manual — payload sub-packages import the parent payloads package)
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"
	_ "github.com/DataDog/pathrunner/pkg/payloads/glue"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ecs"
	_ "github.com/DataDog/pathrunner/pkg/payloads/lambda"
	_ "github.com/DataDog/pathrunner/pkg/payloads/amplify"
	_ "github.com/DataDog/pathrunner/pkg/payloads/apprunner"
	_ "github.com/DataDog/pathrunner/pkg/payloads/batch"
	_ "github.com/DataDog/pathrunner/pkg/payloads/bedrock"
	_ "github.com/DataDog/pathrunner/pkg/payloads/braket"
	_ "github.com/DataDog/pathrunner/pkg/payloads/cloudformation"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codedeploy"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ssm"
	_ "github.com/DataDog/pathrunner/pkg/payloads/cognitoidentity"
	_ "github.com/DataDog/pathrunner/pkg/payloads/emr"
	_ "github.com/DataDog/pathrunner/pkg/payloads/emrserverless"
	_ "github.com/DataDog/pathrunner/pkg/payloads/gamelift"
	_ "github.com/DataDog/pathrunner/pkg/payloads/imagebuilder"
	_ "github.com/DataDog/pathrunner/pkg/payloads/kinesisanalytics"
	_ "github.com/DataDog/pathrunner/pkg/payloads/omics"
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
