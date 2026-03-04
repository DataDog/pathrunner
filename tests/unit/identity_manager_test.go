package unit

import (
	"encoding/json"
	"pathrunner/pkg/core"
	"pathrunner/pkg/modules"
	"strings"
	"testing"
	"time"
)

func TestIdentityManagerCreation(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	if im == nil {
		t.Fatal("Expected IdentityManager instance, got nil")
	}

	if im.GetCurrent() != nil {
		t.Error("Expected no current identity on new IdentityManager")
	}

	identities := im.GetIdentities()
	if identities == nil {
		t.Fatal("Expected identities map to be initialized")
	}

	if len(identities) != 0 {
		t.Errorf("Expected empty identities map, got %d identities", len(identities))
	}
}

func TestSetIdentities(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	testIdentities := map[string]*modules.Identity{
		"test1": {
			Name:   "test1",
			Type:   "profile",
			Region: "us-east-1",
		},
		"test2": {
			Name:   "test2",
			Type:   "keys",
			Region: "us-west-2",
		},
	}

	im.SetIdentities(testIdentities)

	identities := im.GetIdentities()
	if len(identities) != 2 {
		t.Errorf("Expected 2 identities, got %d", len(identities))
	}

	if identities["test1"] == nil {
		t.Error("Expected test1 identity to exist")
	}

	if identities["test2"] == nil {
		t.Error("Expected test2 identity to exist")
	}
}

func TestSetIdentitiesReplacesExisting(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	// Set initial identities
	initial := map[string]*modules.Identity{
		"identity1": {Name: "identity1", Type: "profile", Region: "us-east-1"},
		"identity2": {Name: "identity2", Type: "profile", Region: "us-west-2"},
	}
	im.SetIdentities(initial)

	if len(im.GetIdentities()) != 2 {
		t.Errorf("Expected 2 initial identities, got %d", len(im.GetIdentities()))
	}

	// Replace with new set
	replacement := map[string]*modules.Identity{
		"identity3": {Name: "identity3", Type: "keys", Region: "eu-west-1"},
	}
	im.SetIdentities(replacement)

	identities := im.GetIdentities()
	if len(identities) != 1 {
		t.Errorf("Expected 1 identity after replacement, got %d", len(identities))
	}

	if identities["identity1"] != nil {
		t.Error("Expected identity1 to be removed")
	}

	if identities["identity3"] == nil {
		t.Error("Expected identity3 to exist")
	}
}

func TestSetCurrentIdentity(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	testIdentity := &modules.Identity{
		Name:   "test-identity",
		Type:   "profile",
		Region: "us-east-1",
	}

	im.SetCurrent(testIdentity)

	current := im.GetCurrent()
	if current == nil {
		t.Fatal("Expected current identity to be set")
	}

	if current.Name != "test-identity" {
		t.Errorf("Expected current identity name 'test-identity', got '%s'", current.Name)
	}
}

func TestSetCurrentToNil(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	// First set an identity
	testIdentity := &modules.Identity{
		Name:   "test-identity",
		Type:   "profile",
		Region: "us-east-1",
	}
	im.SetCurrent(testIdentity)

	if im.GetCurrent() == nil {
		t.Fatal("Expected identity to be set")
	}

	// Now set to nil
	im.SetCurrent(nil)

	if im.GetCurrent() != nil {
		t.Error("Expected current identity to be nil")
	}
}

func TestSwitchIdentity(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	identities := map[string]*modules.Identity{
		"identity1": {Name: "identity1", Type: "profile", Region: "us-east-1"},
		"identity2": {Name: "identity2", Type: "keys", Region: "us-west-2"},
	}
	im.SetIdentities(identities)
	im.SetCurrent(identities["identity1"])

	// Switch to identity2
	err := im.SwitchIdentity("identity2")
	if err != nil {
		t.Fatalf("Expected no error switching identity, got: %v", err)
	}

	current := im.GetCurrent()
	if current == nil {
		t.Fatal("Expected current identity to be set")
	}

	if current.Name != "identity2" {
		t.Errorf("Expected current identity 'identity2', got '%s'", current.Name)
	}
}

func TestSwitchIdentityNotFound(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	identities := map[string]*modules.Identity{
		"identity1": {Name: "identity1", Type: "profile", Region: "us-east-1"},
	}
	im.SetIdentities(identities)

	err := im.SwitchIdentity("nonexistent")
	if err == nil {
		t.Error("Expected error when switching to non-existent identity")
	}

	if err.Error() != "identity 'nonexistent' not found" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

func TestSwitchIdentityExpired(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	// Create an expired identity
	pastTime := time.Now().Add(-1 * time.Hour)
	expiredIdentity := &modules.Identity{
		Name:      "expired",
		Type:      "keys",
		Region:    "us-east-1",
		ExpiresAt: &pastTime,
	}

	identities := map[string]*modules.Identity{
		"expired": expiredIdentity,
	}
	im.SetIdentities(identities)

	err := im.SwitchIdentity("expired")
	if err == nil {
		t.Error("Expected error when switching to expired identity")
	}

	if err.Error() != "identity 'expired' has expired" {
		t.Errorf("Expected expired identity error, got: %v", err)
	}
}

func TestRemoveIdentity(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	identities := map[string]*modules.Identity{
		"identity1": {Name: "identity1", Type: "profile", Region: "us-east-1"},
		"identity2": {Name: "identity2", Type: "keys", Region: "us-west-2"},
	}
	im.SetIdentities(identities)
	im.SetCurrent(identities["identity1"])

	// Remove identity2 (not current)
	err := im.RemoveIdentity([]string{"identity2"})
	if err != nil {
		t.Fatalf("Expected no error removing identity, got: %v", err)
	}

	remaining := im.GetIdentities()
	if len(remaining) != 1 {
		t.Errorf("Expected 1 identity remaining, got %d", len(remaining))
	}

	if remaining["identity2"] != nil {
		t.Error("Expected identity2 to be removed")
	}

	if remaining["identity1"] == nil {
		t.Error("Expected identity1 to still exist")
	}
}

func TestRemoveCurrentIdentityFails(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	identity := &modules.Identity{
		Name:   "current-identity",
		Type:   "profile",
		Region: "us-east-1",
	}

	identities := map[string]*modules.Identity{
		"current-identity": identity,
	}
	im.SetIdentities(identities)
	im.SetCurrent(identity)

	err := im.RemoveIdentity([]string{"current-identity"})
	if err == nil {
		t.Error("Expected error when removing current identity")
	}

	// Verify identity still exists
	if im.GetIdentities()["current-identity"] == nil {
		t.Error("Expected current identity to still exist")
	}
}

func TestRemoveIdentityNotFound(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	err := im.RemoveIdentity([]string{"nonexistent"})
	if err == nil {
		t.Error("Expected error when removing non-existent identity")
	}
}

func TestRemoveExpiredIdentities(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	pastTime := time.Now().Add(-1 * time.Hour)
	futureTime := time.Now().Add(1 * time.Hour)

	identities := map[string]*modules.Identity{
		"expired1": {
			Name:      "expired1",
			Type:      "keys",
			Region:    "us-east-1",
			ExpiresAt: &pastTime,
		},
		"expired2": {
			Name:      "expired2",
			Type:      "keys",
			Region:    "us-west-2",
			ExpiresAt: &pastTime,
		},
		"valid": {
			Name:      "valid",
			Type:      "keys",
			Region:    "eu-west-1",
			ExpiresAt: &futureTime,
		},
		"profile": {
			Name:   "profile",
			Type:   "profile",
			Region: "ap-south-1",
		},
	}

	im.SetIdentities(identities)
	im.SetCurrent(identities["valid"])

	err := im.RemoveIdentity([]string{"--expired"})
	if err != nil {
		t.Fatalf("Expected no error removing expired identities, got: %v", err)
	}

	remaining := im.GetIdentities()
	if len(remaining) != 2 {
		t.Errorf("Expected 2 identities remaining, got %d", len(remaining))
	}

	if remaining["expired1"] != nil {
		t.Error("Expected expired1 to be removed")
	}

	if remaining["expired2"] != nil {
		t.Error("Expected expired2 to be removed")
	}

	if remaining["valid"] == nil {
		t.Error("Expected valid identity to remain")
	}

	if remaining["profile"] == nil {
		t.Error("Expected profile identity to remain")
	}
}

func TestRemoveExpiredIdentitiesSkipsCurrent(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	pastTime := time.Now().Add(-1 * time.Hour)

	expiredCurrent := &modules.Identity{
		Name:      "expired-current",
		Type:      "keys",
		Region:    "us-east-1",
		ExpiresAt: &pastTime,
	}

	identities := map[string]*modules.Identity{
		"expired-current": expiredCurrent,
		"expired-other": {
			Name:      "expired-other",
			Type:      "keys",
			Region:    "us-west-2",
			ExpiresAt: &pastTime,
		},
	}

	im.SetIdentities(identities)
	im.SetCurrent(expiredCurrent)

	err := im.RemoveIdentity([]string{"--expired"})
	if err != nil {
		t.Fatalf("Expected no error removing expired identities, got: %v", err)
	}

	remaining := im.GetIdentities()
	if len(remaining) != 1 {
		t.Errorf("Expected 1 identity remaining (current), got %d", len(remaining))
	}

	if remaining["expired-current"] == nil {
		t.Error("Expected expired current identity to be skipped")
	}

	if remaining["expired-other"] != nil {
		t.Error("Expected expired-other to be removed")
	}
}

func TestRemoveIdentityRequiresArgument(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	err := im.RemoveIdentity([]string{})
	if err == nil {
		t.Error("Expected error when RemoveIdentity called with no arguments")
	}
}

func TestIsAdminNilByDefault(t *testing.T) {
	identity := &modules.Identity{
		Name:   "test",
		Type:   "keys",
		Region: "us-east-1",
	}

	if identity.IsAdmin != nil {
		t.Error("Expected IsAdmin to be nil by default")
	}
}

func TestIsAdminJsonRoundTrip(t *testing.T) {
	// Test nil (unchecked)
	identity := &modules.Identity{
		Name:   "test",
		Type:   "keys",
		Region: "us-east-1",
	}

	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("Failed to marshal identity: %v", err)
	}

	var decoded modules.Identity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal identity: %v", err)
	}

	if decoded.IsAdmin != nil {
		t.Errorf("Expected IsAdmin nil after round-trip, got %v", *decoded.IsAdmin)
	}

	// Test true (admin)
	isAdmin := true
	identity.IsAdmin = &isAdmin

	data, err = json.Marshal(identity)
	if err != nil {
		t.Fatalf("Failed to marshal identity: %v", err)
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal identity: %v", err)
	}

	if decoded.IsAdmin == nil || !*decoded.IsAdmin {
		t.Error("Expected IsAdmin true after round-trip")
	}

	// Test false (not admin)
	notAdmin := false
	identity.IsAdmin = &notAdmin

	data, err = json.Marshal(identity)
	if err != nil {
		t.Fatalf("Failed to marshal identity: %v", err)
	}

	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal identity: %v", err)
	}

	if decoded.IsAdmin == nil || *decoded.IsAdmin {
		t.Error("Expected IsAdmin false after round-trip")
	}
}

func TestCallerARNJsonRoundTrip(t *testing.T) {
	// Test empty CallerARN omitted
	identity := &modules.Identity{
		Name:   "test",
		Type:   "keys",
		Region: "us-east-1",
	}

	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("Failed to marshal identity: %v", err)
	}

	// CallerARN should not appear in JSON when empty
	if strings.Contains(string(data), "caller_arn") {
		t.Error("Expected caller_arn to be omitted when empty")
	}

	// Test with CallerARN set
	identity.CallerARN = "arn:aws:iam::123456789012:user/testuser"

	data, err = json.Marshal(identity)
	if err != nil {
		t.Fatalf("Failed to marshal identity: %v", err)
	}

	var decoded modules.Identity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal identity: %v", err)
	}

	if decoded.CallerARN != "arn:aws:iam::123456789012:user/testuser" {
		t.Errorf("Expected CallerARN 'arn:aws:iam::123456789012:user/testuser', got '%s'", decoded.CallerARN)
	}
}

func TestCheckAdminNoCurrentIdentity(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	err := im.CheckAdmin("")
	if err == nil {
		t.Error("Expected error when checking admin with no current identity")
	}

	if !strings.Contains(err.Error(), "no current identity") {
		t.Errorf("Expected 'no current identity' error, got: %v", err)
	}
}

func TestCheckAdminNonExistentIdentity(t *testing.T) {
	im := core.NewIdentityManager(nil, nil)

	err := im.CheckAdmin("nonexistent")
	if err == nil {
		t.Error("Expected error when checking admin for non-existent identity")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}
