// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package repl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/DataDog/pathrunner/pkg/modules"

	"github.com/atotto/clipboard"
)

// resolvedCredentials holds live credential values for an identity.
type resolvedCredentials struct {
	AccessKeyID  string
	SecretKey    string
	SessionToken string
	Region       string
}

// identityCredentials resolves live credential values for an identity.
// Profile and IMDS identities hold live credential providers rather than
// static keys, so their current values are retrieved from the config.
func identityCredentials(identity *modules.Identity) (accessKey, secretKey, sessionToken, region string, err error) {
	if identity.Type == "profile" || identity.Type == "imds" {
		config := identity.GetConfig()
		creds, err := config.Credentials.Retrieve(context.Background())
		if err != nil {
			return "", "", "", "", fmt.Errorf("failed to retrieve credentials from profile: %v", err)
		}
		return creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, config.Region, nil
	}
	return identity.AccessKeyID, identity.SecretKey, identity.SessionToken, identity.Region, nil
}

// cmdShell spawns an interactive shell with the current identity's
// credentials injected as environment variables.
func (r *REPL) cmdShell(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showShellHelp()
	}
	if len(args) > 0 {
		return NewInvalidArgumentsError("shell takes no arguments. Use 'shell help' for usage")
	}

	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	if identity.IsExpired() {
		return NewAuthError("current identity has expired. Use 'identity refresh' or add new credentials", nil)
	}

	accessKey, secretKey, sessionToken, region, err := identityCredentials(identity)
	if err != nil {
		return err
	}
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("identity has no credentials available")
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	fmt.Printf("Spawning %s as identity '%s' (type 'exit' to return to pathrunner)\n", shell, identity.Name)

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", accessKey),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", secretKey),
		fmt.Sprintf("AWS_DEFAULT_REGION=%s", region),
	)
	if sessionToken != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("AWS_SESSION_TOKEN=%s", sessionToken))
	}

	// Connect stdin, stdout, stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil
		}
		return fmt.Errorf("failed to spawn shell: %v", err)
	}

	return nil
}

// showShellHelp shows help for the shell command
func (r *REPL) showShellHelp() error {
	fmt.Println("Shell Command:")
	fmt.Println("  shell    - Spawn an interactive shell with current identity credentials")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Spawns $SHELL (fallback: /bin/bash) with the current identity's")
	fmt.Println("  AWS credentials injected as environment variables. Useful after an")
	fmt.Println("  exploit imports a new identity — run raw aws CLI commands with the")
	fmt.Println("  escalated credentials, then 'exit' to return to pathrunner.")
	fmt.Println()
	fmt.Println("Environment variables set:")
	fmt.Println("  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (if")
	fmt.Println("  present), AWS_DEFAULT_REGION")
	fmt.Println()
	fmt.Println("Requirements:")
	fmt.Println("  - A current, non-expired identity must be selected")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  shell")
	fmt.Println()
	return nil
}

// parseExportArgs parses arguments for the export command.
func parseExportArgs(args []string) (format, name string, copyToClipboard bool, err error) {
	format = "env"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--copy" || arg == "-c":
			copyToClipboard = true
		case arg == "--format" || arg == "-f":
			if i+1 >= len(args) {
				return "", "", false, NewInvalidArgumentsError("--format requires a value: env, profile, or json")
			}
			i++
			format = args[i]
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return "", "", false, NewInvalidArgumentsError(fmt.Sprintf("unknown flag: %s", arg))
		case name == "":
			name = arg
		default:
			return "", "", false, NewInvalidArgumentsError("export accepts at most one identity name")
		}
	}

	switch format {
	case "env", "profile", "json":
	default:
		return "", "", false, NewInvalidArgumentsError(fmt.Sprintf("unknown format: %s. Valid formats: env, profile, json", format))
	}

	return format, name, copyToClipboard, nil
}

// buildExportLines renders credentials in the requested paste-friendly format.
func buildExportLines(identityName string, creds resolvedCredentials, format string) ([]string, error) {
	switch format {
	case "env":
		lines := []string{
			"export AWS_ACCESS_KEY_ID=" + creds.AccessKeyID,
			"export AWS_SECRET_ACCESS_KEY=" + creds.SecretKey,
		}
		if creds.SessionToken != "" {
			lines = append(lines, "export AWS_SESSION_TOKEN="+creds.SessionToken)
		}
		if creds.Region != "" {
			lines = append(lines, "export AWS_DEFAULT_REGION="+creds.Region)
		}
		return lines, nil
	case "profile":
		profileName := identityName
		if profileName == "" {
			profileName = "pathrunner"
		}
		lines := []string{
			"[" + profileName + "]",
			"aws_access_key_id = " + creds.AccessKeyID,
			"aws_secret_access_key = " + creds.SecretKey,
		}
		if creds.SessionToken != "" {
			lines = append(lines, "aws_session_token = "+creds.SessionToken)
		}
		if creds.Region != "" {
			lines = append(lines, "region = "+creds.Region)
		}
		return lines, nil
	case "json":
		payload := map[string]string{
			"AWS_ACCESS_KEY_ID":     creds.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY": creds.SecretKey,
		}
		if creds.SessionToken != "" {
			payload["AWS_SESSION_TOKEN"] = creds.SessionToken
		}
		if creds.Region != "" {
			payload["AWS_DEFAULT_REGION"] = creds.Region
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to encode credentials as json: %v", err)
		}
		return []string{string(data)}, nil
	default:
		return nil, NewInvalidArgumentsError(fmt.Sprintf("unknown format: %s. Valid formats: env, profile, json", format))
	}
}

// cmdExport prints or copies identity credentials in paste-friendly formats.
func (r *REPL) cmdExport(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showExportHelp()
	}

	format, name, copyToClipboard, err := parseExportArgs(args)
	if err != nil {
		return err
	}

	var identity *modules.Identity
	if name != "" {
		identity = r.identityManager.GetIdentities()[name]
		if identity == nil {
			return NewInvalidArgumentsError(fmt.Sprintf("identity not found: %s", name))
		}
	} else {
		identity = r.identityManager.GetCurrent()
		if identity == nil {
			return NewIdentityRequiredError()
		}
	}

	accessKey, secretKey, sessionToken, region, err := identityCredentials(identity)
	if err != nil {
		return err
	}
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("identity has no credentials available")
	}

	if identity.IsExpired() {
		// Warn on stderr so scripted use of stdout stays clean
		fmt.Fprintf(os.Stderr, "Warning: identity '%s' credentials have expired\n", identity.Name)
	}

	creds := resolvedCredentials{
		AccessKeyID:  accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Region:       region,
	}

	lines, err := buildExportLines(identity.Name, creds, format)
	if err != nil {
		return err
	}

	if copyToClipboard {
		if err := clipboard.WriteAll(strings.Join(lines, "\n")); err != nil {
			return fmt.Errorf("failed to copy to clipboard: %v", err)
		}
		fmt.Printf("Credentials for '%s' copied to clipboard (%s format)\n", identity.Name, format)
		return nil
	}

	for _, line := range lines {
		fmt.Println(line)
	}

	return nil
}

// showExportHelp shows help for the export command
func (r *REPL) showExportHelp() error {
	fmt.Println("Identity Export Command:")
	fmt.Println("  identity export [identity-name] [flags]    - Export credentials in paste-friendly formats")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Prints (or copies) the selected identity's AWS credentials so they")
	fmt.Println("  can be pasted into a shell or config file. Defaults to the current")
	fmt.Println("  identity; pass a name to export any identity in the workspace.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --format <env|profile|json>   Output format (default: env)")
	fmt.Println("    env       - 'export AWS_ACCESS_KEY_ID=...' lines for sourcing in a shell")
	fmt.Println("    profile   - '[name]' block for ~/.aws/credentials")
	fmt.Println("    json      - JSON object with AWS_* keys")
	fmt.Println("  --copy, -c                    Copy to system clipboard instead of printing")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  identity export")
	fmt.Println("  identity export --format profile")
	fmt.Println("  identity export stolen-role --copy")
	fmt.Println()
	return nil
}
