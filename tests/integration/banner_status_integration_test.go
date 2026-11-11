// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package integration

import (
	"strings"
	"testing"
)

func TestContextStatusHasNoEmoji(t *testing.T) {
	r, _, _, cleanup := setupTest(t)
	defer cleanup()

	output := captureOutput(func() {
		err := r.ExecuteCommand("context")
		if err != nil {
			t.Errorf("Expected no error for 'context', got: %v", err)
		}
	})

	if !strings.Contains(output, "No identity configured") {
		t.Errorf("Expected plain status text, got: %s", output)
	}
	for _, emoji := range []string{"❌", "✅", "🟡"} {
		if strings.Contains(output, emoji) {
			t.Errorf("Expected no %q emoji in context output, got: %s", emoji, output)
		}
	}
}
