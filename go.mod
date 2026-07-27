module github.com/DataDog/pathrunner

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.43.0
	github.com/aws/aws-sdk-go-v2/config v1.32.30
	github.com/aws/aws-sdk-go-v2/credentials v1.19.29
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.41.1
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.69.1
	github.com/aws/aws-sdk-go-v2/service/batch v1.67.1
	github.com/aws/aws-sdk-go-v2/service/bedrockagentcore v1.33.1
	github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol v1.48.0
	github.com/aws/aws-sdk-go-v2/service/braket v1.42.1
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.74.1
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.71.1
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.37.1
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.35.1
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.60.1
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.316.1
	github.com/aws/aws-sdk-go-v2/service/ecr v1.59.1
	github.com/aws/aws-sdk-go-v2/service/ecs v1.88.1
	github.com/aws/aws-sdk-go-v2/service/emr v1.63.0
	github.com/aws/aws-sdk-go-v2/service/emrserverless v1.43.2
	github.com/aws/aws-sdk-go-v2/service/gamelift v1.58.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.148.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.55.1
	github.com/aws/aws-sdk-go-v2/service/imagebuilder v1.57.1
	github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2 v1.40.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.99.0
	github.com/aws/aws-sdk-go-v2/service/omics v1.48.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.105.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.72.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.44.1
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/huh v1.0.0
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/charmbracelet/x/term v0.2.2
	github.com/chzyer/readline v1.5.1
	github.com/dominikbraun/graph v0.23.0
	github.com/lucasb-eyer/go-colorful v1.4.0
	github.com/spf13/cobra v1.10.2
)

require github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.79.1

require (
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.14 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.31 // indirect
	// bedrockagentcore and bedrockagentcorecontrol moved to direct dependencies above (used by bedrock_startbrowsersession_cdp module)
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.12.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.4.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.32.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.37.1 // indirect
	github.com/aws/smithy-go v1.27.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/catppuccin/go v0.3.0 // indirect
	github.com/charmbracelet/bubbles v1.0.0 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/x/ansi v0.11.7 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/exp/strings v0.1.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.23 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0
	golang.org/x/text v0.40.0 // indirect
)
