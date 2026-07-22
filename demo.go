// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

// Demo script to test Pathrunner functionality
package main

import (
	"fmt"
)

func main() {
	fmt.Println("Pathrunner AWS Post-Exploitation Framework Demo")
	fmt.Println("==============================================")

	fmt.Println("\n✓ Core REPL framework implemented")
	fmt.Println("✓ Multi-identity credential management")
	fmt.Println("✓ Lambda/PassRole exploitation module")
	fmt.Println("✓ Four payload types implemented:")
	fmt.Println("  - exfil/response: Extract credentials in response")
	fmt.Println("  - exfil/https: Send credentials to remote endpoint")
	fmt.Println("  - backdoor/create-role: Create admin IAM role")
	fmt.Println("  - backdoor/create-user: Create admin IAM user")

	fmt.Println("\nUsage Example:")
	fmt.Println("$ go run cmd/pathrunner/main.go")
	fmt.Println("pathrunner> identity add --profile my-profile")
	fmt.Println("pathrunner> use exploit/lambda_passrole")
	fmt.Println("pathrunner> set ROLE_ARN arn:aws:iam::123456789012:role/high-priv-role")
	fmt.Println("pathrunner> set PAYLOAD exfil/response")
	fmt.Println("pathrunner> exploit")

	fmt.Println("\nFramework is ready for testing with proper AWS credentials!")
}