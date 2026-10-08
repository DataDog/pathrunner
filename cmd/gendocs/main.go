// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

// Command gendocs generates the pathrunner documentation reference artifacts
// (pathrunner-reference.json + per-command/per-module markdown) by introspecting
// the live Cobra command tree and the module/payload registries.
//
// It is a SEPARATE binary from pathrunner on purpose: it reuses the exact same
// command tree (via cli.NewCLI().CreateRootCommand()) and the same blank imports
// that cmd/pathrunner/main.go uses so every module/payload init() registration
// fires, but it keeps the shipped pathrunner binary's command surface clean —
// operators never see a "docs" command. It makes no AWS calls and reads no
// ~/.pathrunner state; it is pure introspection.
//
// Usage:
//
//	go run ./cmd/gendocs --out docs/reference
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DataDog/pathrunner/pkg/cli"
	"github.com/DataDog/pathrunner/pkg/docs"

	// Auto-generated exploit module registrations (mirror cmd/pathrunner/main.go).
	_ "github.com/DataDog/pathrunner/pkg/exploits"

	// Payload registrations (mirror cmd/pathrunner/main.go).
	_ "github.com/DataDog/pathrunner/pkg/payloads/amplify"
	_ "github.com/DataDog/pathrunner/pkg/payloads/apprunner"
	_ "github.com/DataDog/pathrunner/pkg/payloads/batch"
	_ "github.com/DataDog/pathrunner/pkg/payloads/bedrock"
	_ "github.com/DataDog/pathrunner/pkg/payloads/braket"
	_ "github.com/DataDog/pathrunner/pkg/payloads/cloudformation"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codebuild"
	_ "github.com/DataDog/pathrunner/pkg/payloads/codedeploy"
	_ "github.com/DataDog/pathrunner/pkg/payloads/cognitoidentity"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ec2"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ecs"
	_ "github.com/DataDog/pathrunner/pkg/payloads/emr"
	_ "github.com/DataDog/pathrunner/pkg/payloads/emrserverless"
	_ "github.com/DataDog/pathrunner/pkg/payloads/gamelift"
	_ "github.com/DataDog/pathrunner/pkg/payloads/glue"
	_ "github.com/DataDog/pathrunner/pkg/payloads/imagebuilder"
	_ "github.com/DataDog/pathrunner/pkg/payloads/kinesisanalytics"
	_ "github.com/DataDog/pathrunner/pkg/payloads/lambda"
	_ "github.com/DataDog/pathrunner/pkg/payloads/omics"
	_ "github.com/DataDog/pathrunner/pkg/payloads/ssm"
)

func main() {
	outDir := flag.String("out", "docs/reference", "directory to write documentation artifacts into")
	flag.Parse()

	rootCmd := cli.NewCLI().CreateRootCommand()

	ref, err := docs.Generate(rootCmd, *outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gendocs: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote reference to %s/%s\n", *outDir, docs.ReferenceFileName)
	fmt.Printf("  commands: %d  modules: %d  payloads: %d  services: %d\n",
		ref.Counts.Commands, ref.Counts.Modules, ref.Counts.Payloads, ref.Counts.Services)
}
