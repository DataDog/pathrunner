module github.com/DataDog/pathrunner

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.45.1
	github.com/aws/aws-sdk-go-v2/config v1.33.1
	github.com/aws/aws-sdk-go-v2/credentials v1.20.1
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.44.1
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.75.1
	github.com/aws/aws-sdk-go-v2/service/batch v1.72.1
	github.com/aws/aws-sdk-go-v2/service/bedrockagentcore v1.43.0
	github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol v1.61.1
	github.com/aws/aws-sdk-go-v2/service/braket v1.45.1
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.78.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.75.1
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.40.1
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.39.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.65.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.325.1
	github.com/aws/aws-sdk-go-v2/service/ecr v1.62.1
	github.com/aws/aws-sdk-go-v2/service/ecs v1.93.0
	github.com/aws/aws-sdk-go-v2/service/emr v1.66.1
	github.com/aws/aws-sdk-go-v2/service/emrserverless v1.46.1
	github.com/aws/aws-sdk-go-v2/service/gamelift v1.63.1
	github.com/aws/aws-sdk-go-v2/service/glue v1.155.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.61.1
	github.com/aws/aws-sdk-go-v2/service/imagebuilder v1.60.1
	github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2 v1.44.1
	github.com/aws/aws-sdk-go-v2/service/lambda v1.104.1
	github.com/aws/aws-sdk-go-v2/service/omics v1.51.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.109.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.46.1
	github.com/aws/aws-sdk-go-v2/service/ssm v1.75.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.47.1
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/huh v1.0.0
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/charmbracelet/x/term v0.2.2
	github.com/chzyer/readline v1.5.1
	github.com/dominikbraun/graph v0.23.0
	github.com/lucasb-eyer/go-colorful v1.4.1
	github.com/spf13/cobra v1.10.2
)

require github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.84.1

require (
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.1 // indirect
	// bedrockagentcore and bedrockagentcorecontrol moved to direct dependencies above (used by bedrock_startbrowsersession_cdp module)
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.35.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.40.1 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/catppuccin/go v0.3.0 // indirect
	github.com/charmbracelet/bubbles v1.0.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/x/ansi v0.11.8 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/exp/strings v0.1.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.28 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/xo/terminfo v1.0.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0
	golang.org/x/text v0.41.0 // indirect
)
