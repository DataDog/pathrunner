// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"strings"
	"testing"

	_ "github.com/DataDog/pathrunner/pkg/exploits/lambda_updatecode"
	_ "github.com/DataDog/pathrunner/pkg/exploits/lambda_updatecode_addpermission"
	_ "github.com/DataDog/pathrunner/pkg/exploits/lambda_updatecode_invoke"
	_ "github.com/DataDog/pathrunner/pkg/payloads/lambda"

	"github.com/DataDog/pathrunner/pkg/exploits/shared"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/payloads"
)

// TestRuntimeToLanguageTag verifies runtime string mapping to language tags.
func TestRuntimeToLanguageTag(t *testing.T) {
	tests := []struct {
		runtime string
		want    string
	}{
		{"python3.12", payloads.TagLanguagePython},
		{"python3.11", payloads.TagLanguagePython},
		{"python3.9", payloads.TagLanguagePython},
		{"python3.8", payloads.TagLanguagePython},
		{"nodejs20.x", payloads.TagLanguageNodeJS},
		{"nodejs18.x", payloads.TagLanguageNodeJS},
		{"nodejs16.x", payloads.TagLanguageNodeJS},
		{"java21", ""},
		{"java11", ""},
		{"provided.al2", ""},
		{"provided.al2023", ""},
		{"ruby3.2", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.runtime, func(t *testing.T) {
			got := shared.RuntimeToLanguageTag(tt.runtime)
			if got != tt.want {
				t.Errorf("RuntimeToLanguageTag(%q) = %q, want %q", tt.runtime, got, tt.want)
			}
		})
	}
}

// TestInjectEnvVarsJS verifies JS env var injection inserts before exports.
func TestInjectEnvVarsJS(t *testing.T) {
	code := `'use strict';

exports.handler = async (event) => {
  const x = process.env.KEY;
  return x;
};
`
	envVars := map[string]string{"LISTENER_IP": "1.2.3.4", "LISTENER_PORT": "4444"}
	result := shared.InjectEnvVarsJS(code, envVars)

	if !strings.Contains(result, "process.env['LISTENER_IP'] = '1.2.3.4';") {
		t.Error("missing LISTENER_IP injection")
	}
	if !strings.Contains(result, "process.env['LISTENER_PORT'] = '4444';") {
		t.Error("missing LISTENER_PORT injection")
	}
	// Injection must appear before the exports declaration
	injIdx := strings.Index(result, "process.env['LISTENER_IP']")
	exportsIdx := strings.Index(result, "exports.handler")
	if injIdx > exportsIdx {
		t.Error("env var injection should appear before exports.handler")
	}
}

// TestInjectEnvVarsJS_NoOp verifies empty envVars leaves code unchanged.
func TestInjectEnvVarsJS_NoOp(t *testing.T) {
	code := `exports.handler = async () => {};`
	result := shared.InjectEnvVarsJS(code, map[string]string{})
	if result != code {
		t.Error("empty envVars should leave code unchanged")
	}
}

// TestInjectEnvVarsPython verifies Python env var injection inserts before def.
func TestInjectEnvVarsPython(t *testing.T) {
	code := `import json
import boto3

def lambda_handler(event, context):
    return {}
`
	envVars := map[string]string{"TARGET_ARN": "arn:aws:iam::123:user/foo"}
	result := shared.InjectEnvVarsPython(code, envVars)

	if !strings.Contains(result, "os.environ['TARGET_ARN'] = 'arn:aws:iam::123:user/foo'") {
		t.Error("missing TARGET_ARN injection")
	}
	// Injection must appear before the handler definition
	injIdx := strings.Index(result, "os.environ['TARGET_ARN']")
	defIdx := strings.Index(result, "def lambda_handler")
	if injIdx > defIdx {
		t.Error("env var injection should appear before def lambda_handler")
	}
}

// TestAdaptHandlerNameJS verifies JS handler name replacement.
func TestAdaptHandlerNameJS(t *testing.T) {
	code := `exports.handler = async (event) => { return {}; };`

	// No-op when name is already "handler"
	result := shared.AdaptHandlerNameJS(code, "handler")
	if result != code {
		t.Error("should be no-op when exportName == 'handler'")
	}

	// Rename to custom export
	result = shared.AdaptHandlerNameJS(code, "myHandler")
	if !strings.Contains(result, "exports.myHandler =") {
		t.Error("should rename to exports.myHandler")
	}
	if strings.Contains(result, "exports.handler =") {
		t.Error("should not keep original exports.handler after rename")
	}
}

// TestAdaptHandlerNamePython verifies Python handler name replacement.
func TestAdaptHandlerNamePython(t *testing.T) {
	code := `def lambda_handler(event, context): return {}`

	// No-op when name is already lambda_handler
	result := shared.AdaptHandlerNamePython(code, "lambda_handler")
	if result != code {
		t.Error("should be no-op when funcName == 'lambda_handler'")
	}

	// Rename to custom name
	result = shared.AdaptHandlerNamePython(code, "my_handler")
	if !strings.Contains(result, "def my_handler(") {
		t.Error("should rename to def my_handler")
	}
	if strings.Contains(result, "def lambda_handler(") {
		t.Error("should not keep original def lambda_handler after rename")
	}
}

// TestListPayloadsForLanguage verifies payload filtering by language.
func TestListPayloadsForLanguage(t *testing.T) {
	t.Run("nodejs only", func(t *testing.T) {
		result := shared.ListPayloadsForLanguage(payloads.TagServiceLambda, payloads.TagLanguageNodeJS)
		if len(result) == 0 {
			t.Fatal("expected nodejs payloads")
		}
		for _, p := range result {
			if strings.HasSuffix(p.Name, "-nodejs") == false {
				// Check by looking up the actual payload tags
				pl, err := payloads.GetPayloadForService(p.Name, payloads.TagServiceLambda)
				if err != nil {
					continue
				}
				if payloads.HasTag(pl.GetTags(), payloads.TagLanguagePython) {
					t.Errorf("python payload %q returned by nodejs filter", p.Name)
				}
			}
		}
	})

	t.Run("python only", func(t *testing.T) {
		result := shared.ListPayloadsForLanguage(payloads.TagServiceLambda, payloads.TagLanguagePython)
		if len(result) == 0 {
			t.Fatal("expected python payloads")
		}
		for _, p := range result {
			pl, err := payloads.GetPayloadForService(p.Name, payloads.TagServiceLambda)
			if err != nil {
				continue
			}
			if payloads.HasTag(pl.GetTags(), payloads.TagLanguageNodeJS) {
				t.Errorf("nodejs payload %q returned by python filter", p.Name)
			}
		}
	})

	t.Run("all when langTag empty", func(t *testing.T) {
		allPayloads := shared.ListPayloadsForLanguage(payloads.TagServiceLambda, "")
		nodejsPayloads := shared.ListPayloadsForLanguage(payloads.TagServiceLambda, payloads.TagLanguageNodeJS)
		pythonPayloads := shared.ListPayloadsForLanguage(payloads.TagServiceLambda, payloads.TagLanguagePython)
		if len(allPayloads) < len(nodejsPayloads)+len(pythonPayloads) {
			t.Error("all payloads should include both nodejs and python payloads")
		}
	})
}

// TestRuntimeFilteredPayloadLister_Lambda003 verifies lambda-003 implements the interface correctly.
func TestRuntimeFilteredPayloadLister_Lambda003(t *testing.T) {
	module, err := modules.LoadModule("lambda-003")
	if err != nil {
		t.Fatalf("failed to load lambda-003: %v", err)
	}

	lister, ok := module.(modules.RuntimeFilteredPayloadLister)
	if !ok {
		t.Fatal("lambda-003 should implement RuntimeFilteredPayloadLister")
	}

	t.Run("nodejs runtime shows only nodejs payloads", func(t *testing.T) {
		result := lister.ListPayloadsForOptions(map[string]string{"FUNCTION_RUNTIME": "nodejs20.x"})
		if len(result) == 0 {
			t.Fatal("expected nodejs payloads")
		}
		for _, p := range result {
			if !strings.HasSuffix(p.Name, "-nodejs") {
				// Verify via registry
				pl, err := payloads.GetPayloadForService(p.Name, payloads.TagServiceLambda)
				if err == nil && payloads.HasTag(pl.GetTags(), payloads.TagLanguagePython) {
					t.Errorf("python payload %q returned for nodejs runtime", p.Name)
				}
			}
		}
	})

	t.Run("python runtime shows only python payloads", func(t *testing.T) {
		result := lister.ListPayloadsForOptions(map[string]string{"FUNCTION_RUNTIME": "python3.12"})
		if len(result) == 0 {
			t.Fatal("expected python payloads")
		}
		for _, p := range result {
			pl, err := payloads.GetPayloadForService(p.Name, payloads.TagServiceLambda)
			if err == nil && payloads.HasTag(pl.GetTags(), payloads.TagLanguageNodeJS) {
				t.Errorf("nodejs payload %q returned for python runtime", p.Name)
			}
		}
	})

	t.Run("unknown runtime shows all payloads", func(t *testing.T) {
		empty := lister.ListPayloadsForOptions(map[string]string{"FUNCTION_RUNTIME": ""})
		nodejs := lister.ListPayloadsForOptions(map[string]string{"FUNCTION_RUNTIME": "nodejs20.x"})
		python := lister.ListPayloadsForOptions(map[string]string{"FUNCTION_RUNTIME": "python3.12"})
		if len(empty) < len(nodejs)+len(python) {
			t.Error("unknown runtime should show all payloads (more than just nodejs or python)")
		}
	})
}
