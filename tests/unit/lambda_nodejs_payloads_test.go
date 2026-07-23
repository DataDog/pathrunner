// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"strings"
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/payloads/lambda"

	"github.com/DataDog/pathrunner/pkg/payloads"
)

// TestNodejsPayloadRegistration verifies all Node.js payloads are registered.
func TestNodejsPayloadRegistration(t *testing.T) {
	names := []string{
		"exfil/response-nodejs",
		"exfil/https-nodejs",
		"backdoor/attach-policy-nodejs",
		"backdoor/create-access-key-nodejs",
		"backdoor/update-role-trust-nodejs",
		"revshell/tls-nodejs",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			payload, err := payloads.GetPayloadForService(name, payloads.TagServiceLambda)
			if err != nil {
				t.Fatalf("payload %q not registered: %v", name, err)
			}
			if payload.GetName() != name {
				t.Errorf("expected name %q, got %q", name, payload.GetName())
			}
		})
	}
}

// TestNodejsPayloadTags verifies each Node.js payload has the correct tags.
func TestNodejsPayloadTags(t *testing.T) {
	names := []string{
		"exfil/response-nodejs",
		"exfil/https-nodejs",
		"backdoor/attach-policy-nodejs",
		"backdoor/create-access-key-nodejs",
		"backdoor/update-role-trust-nodejs",
		"revshell/tls-nodejs",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			payload, err := payloads.GetPayloadForService(name, payloads.TagServiceLambda)
			if err != nil {
				t.Fatalf("payload %q not found: %v", name, err)
			}

			tags := payload.GetTags()
			if !payloads.HasTag(tags, payloads.TagServiceLambda) {
				t.Errorf("%q missing tag %q", name, payloads.TagServiceLambda)
			}
			if !payloads.HasTag(tags, payloads.TagLanguageNodeJS) {
				t.Errorf("%q missing tag %q", name, payloads.TagLanguageNodeJS)
			}
			if payloads.HasTag(tags, payloads.TagLanguagePython) {
				t.Errorf("%q should not have tag %q", name, payloads.TagLanguagePython)
			}
		})
	}
}

// TestNodejsExfilResponseGenerateCode verifies the generated JS code structure.
func TestNodejsExfilResponseGenerateCode(t *testing.T) {
	payload, err := payloads.GetPayloadForService("exfil/response-nodejs", payloads.TagServiceLambda)
	if err != nil {
		t.Fatalf("payload not found: %v", err)
	}

	code, err := payload.GenerateCode(map[string]string{})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	checks := []string{"exports.handler", "process.env", "AWS_ACCESS_KEY_ID"}
	for _, c := range checks {
		if !strings.Contains(code, c) {
			t.Errorf("generated code missing %q", c)
		}
	}
	if strings.Contains(code, "def lambda_handler") {
		t.Error("generated code should not contain Python handler")
	}
	if strings.Contains(code, "import boto3") {
		t.Error("generated code should not import boto3")
	}
}

// TestNodejsExfilHTTPSGenerateCode verifies the HTTPS exfil payload code.
func TestNodejsExfilHTTPSGenerateCode(t *testing.T) {
	payload, err := payloads.GetPayloadForService("exfil/https-nodejs", payloads.TagServiceLambda)
	if err != nil {
		t.Fatalf("payload not found: %v", err)
	}

	code, err := payload.GenerateCode(map[string]string{"HTTPS_URL": "https://example.com/collect"})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	checks := []string{"exports.handler", "require('https')", "HTTPS_URL"}
	for _, c := range checks {
		if !strings.Contains(code, c) {
			t.Errorf("generated code missing %q", c)
		}
	}
}

// TestNodejsRevshellGenerateCode verifies the TLS reverse shell payload code.
func TestNodejsRevshellGenerateCode(t *testing.T) {
	payload, err := payloads.GetPayloadForService("revshell/tls-nodejs", payloads.TagServiceLambda)
	if err != nil {
		t.Fatalf("payload not found: %v", err)
	}

	code, err := payload.GenerateCode(map[string]string{"LISTENER_IP": "1.2.3.4"})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	checks := []string{"exports.handler", "tls.connect", "LISTENER_IP", "child_process"}
	for _, c := range checks {
		if !strings.Contains(code, c) {
			t.Errorf("generated code missing %q", c)
		}
	}
}

// TestNodejsBackdoorCreateAccessKeyGenerateCode verifies the PATHFINDER_IDENTITY_DATA block is present.
func TestNodejsBackdoorCreateAccessKeyGenerateCode(t *testing.T) {
	payload, err := payloads.GetPayloadForService("backdoor/create-access-key-nodejs", payloads.TagServiceLambda)
	if err != nil {
		t.Fatalf("payload not found: %v", err)
	}

	code, err := payload.GenerateCode(map[string]string{"TARGET_ARN": "arn:aws:iam::123456789012:user/testuser"})
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if !strings.Contains(code, "PATHFINDER_IDENTITY_DATA") {
		t.Error("generated code missing PATHFINDER_IDENTITY_DATA block")
	}
}

// TestNodejsPayloadValidation verifies required option validation.
func TestNodejsPayloadValidation(t *testing.T) {
	t.Run("exfil/https-nodejs requires HTTPS_URL", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("exfil/https-nodejs", payloads.TagServiceLambda)
		if err := payload.Validate(map[string]string{}); err == nil {
			t.Error("expected error when HTTPS_URL missing")
		}
		if err := payload.Validate(map[string]string{"HTTPS_URL": "https://example.com"}); err != nil {
			t.Errorf("unexpected error with valid HTTPS_URL: %v", err)
		}
	})

	t.Run("backdoor/create-access-key-nodejs rejects role ARNs", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key-nodejs", payloads.TagServiceLambda)
		err := payload.Validate(map[string]string{"TARGET_ARN": "arn:aws:iam::123456789012:role/AdminRole"})
		if err == nil {
			t.Error("expected error for role ARN")
		}
	})

	t.Run("backdoor/create-access-key-nodejs accepts user ARNs", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/create-access-key-nodejs", payloads.TagServiceLambda)
		if err := payload.Validate(map[string]string{"TARGET_ARN": "arn:aws:iam::123456789012:user/testuser"}); err != nil {
			t.Errorf("unexpected error for user ARN: %v", err)
		}
	})

	t.Run("revshell/tls-nodejs requires LISTENER_IP", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("revshell/tls-nodejs", payloads.TagServiceLambda)
		if err := payload.Validate(map[string]string{}); err == nil {
			t.Error("expected error when LISTENER_IP missing")
		}
	})

	t.Run("backdoor/attach-policy-nodejs requires TARGET_ARN", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/attach-policy-nodejs", payloads.TagServiceLambda)
		if err := payload.Validate(map[string]string{}); err == nil {
			t.Error("expected error when TARGET_ARN missing")
		}
	})

	t.Run("backdoor/update-role-trust-nodejs requires both options", func(t *testing.T) {
		payload, _ := payloads.GetPayloadForService("backdoor/update-role-trust-nodejs", payloads.TagServiceLambda)
		if err := payload.Validate(map[string]string{"TARGET_ROLE": "my-role"}); err == nil {
			t.Error("expected error when TRUST_PRINCIPAL missing")
		}
	})
}

// TestGetPayloadsByTagsNodeJS verifies tag-based filtering separates Python and Node.js payloads.
func TestGetPayloadsByTagsNodeJS(t *testing.T) {
	nodejsPayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceLambda, payloads.TagLanguageNodeJS})
	if len(nodejsPayloads) < 6 {
		t.Errorf("expected at least 6 Node.js payloads, got %d", len(nodejsPayloads))
	}
	for _, p := range nodejsPayloads {
		if !payloads.HasTag(p.GetTags(), payloads.TagLanguageNodeJS) {
			t.Errorf("payload %q returned by nodejs filter but lacks nodejs tag", p.GetName())
		}
	}

	pythonPayloads := payloads.GetPayloadsByTags([]string{payloads.TagServiceLambda, payloads.TagLanguagePython})
	if len(pythonPayloads) < 9 {
		t.Errorf("expected at least 9 Python payloads, got %d", len(pythonPayloads))
	}
	for _, p := range pythonPayloads {
		if payloads.HasTag(p.GetTags(), payloads.TagLanguageNodeJS) {
			t.Errorf("Python filter returned Node.js payload %q", p.GetName())
		}
	}
}
