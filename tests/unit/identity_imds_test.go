// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package unit

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/pathrunner/pkg/modules"
)

// TestIMDSIdentityConfigAfterSessionReload verifies that an IMDS identity
// survives a session save/load cycle: aws.Config is not serialized, so the
// identity must rebuild a live IMDS credential provider on first use. This is
// what makes 'identity add --from-imds' work across restarts even though EC2
// instance role credentials rotate.
func TestIMDSIdentityConfigAfterSessionReload(t *testing.T) {
	identity := &modules.Identity{
		Name:     "pl-lab-ec2-role",
		Type:     "imds",
		Region:   "us-west-2",
		Metadata: map[string]string{"role": "pl-lab-ec2-role"},
	}

	// Simulate session persistence: aws.Config is json:"-" so it is dropped
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("failed to marshal identity: %v", err)
	}

	var reloaded modules.Identity
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("failed to unmarshal identity: %v", err)
	}
	if reloaded.Name != "pl-lab-ec2-role" || reloaded.Type != "imds" || reloaded.Region != "us-west-2" {
		t.Fatalf("identity fields lost in round trip: %+v", reloaded)
	}
	if reloaded.IsExpired() {
		t.Error("IMDS identity should never be considered expired")
	}

	// GetConfig must rebuild a live credential provider without static keys
	cfg := reloaded.GetConfig()
	if cfg.Credentials == nil {
		t.Error("expected GetConfig to rebuild a live IMDS credential provider after reload")
	}
	if cfg.Region != "us-west-2" {
		t.Errorf("expected region us-west-2, got %q", cfg.Region)
	}

	// RefreshConfig must also succeed for IMDS identities
	if err := reloaded.RefreshConfig(); err != nil {
		t.Errorf("expected RefreshConfig to succeed for IMDS identity: %v", err)
	}
}
