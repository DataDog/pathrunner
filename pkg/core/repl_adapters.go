// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package core

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/core/repl"
	"github.com/DataDog/pathrunner/pkg/modules"
	"time"
)

// SessionAdapter wraps SessionManager to implement repl.SessionManager interface
type SessionAdapter struct {
	*SessionManager
}

func NewSessionAdapter(sm *SessionManager) *SessionAdapter {
	return &SessionAdapter{SessionManager: sm}
}

func (sa *SessionAdapter) GetCurrentSession() repl.Session {
	return &SessionInterfaceAdapter{Session: sa.SessionManager.GetCurrentSession()}
}

func (sa *SessionAdapter) ListSessions() ([]repl.Session, error) {
	sessions, err := sa.SessionManager.ListSessions()
	if err != nil {
		return nil, err
	}

	result := make([]repl.Session, len(sessions))
	for i := range sessions {
		result[i] = &SessionInterfaceAdapter{Session: &sessions[i]}
	}
	return result, nil
}

func (sa *SessionAdapter) SaveSession(session repl.Session) error {
	// Convert interface back to concrete type
	if adapter, ok := session.(*SessionInterfaceAdapter); ok {
		return sa.SessionManager.SaveSession(adapter.Session)
	}
	return fmt.Errorf("invalid session type")
}

func (sa *SessionAdapter) AddCreatedResource(resource repl.CreatedResource) {
	sa.SessionManager.AddCreatedResource(CreatedResource{
		Type:           resource.Type,
		Name:           resource.Name,
		ARN:            resource.ARN,
		Region:         resource.Region,
		Created:        parseTime(resource.Created),
		CleanupMethod:  resource.CleanupMethod,
		ModuleID:       resource.ModuleID,
		Metadata:       resource.Metadata,
		AccountContext: resource.AccountContext,
	})
}

func (sa *SessionAdapter) GetCreatedResources() []repl.CreatedResource {
	resources := sa.SessionManager.GetCreatedResources()
	result := make([]repl.CreatedResource, len(resources))
	for i, r := range resources {
		result[i] = repl.CreatedResource{
			Type:           r.Type,
			Name:           r.Name,
			ARN:            r.ARN,
			Region:         r.Region,
			Created:        r.Created.Format(time.RFC3339),
			CleanupMethod:  r.CleanupMethod,
			ModuleID:       r.ModuleID,
			Metadata:       r.Metadata,
			AccountContext: r.AccountContext,
		}
	}
	return result
}

// SessionInterfaceAdapter wraps Session to implement repl.Session interface
type SessionInterfaceAdapter struct {
	*Session
}

func (sia *SessionInterfaceAdapter) GetName() string {
	return sia.Session.Name
}

func (sia *SessionInterfaceAdapter) GetCreated() string {
	return sia.Session.Created.Format("2006-01-02 15:04")
}

func (sia *SessionInterfaceAdapter) GetLastAccessed() string {
	return sia.Session.LastAccessed.Format("2006-01-02 15:04")
}

func (sia *SessionInterfaceAdapter) GetCommandCount() int {
	return len(sia.Session.CommandLog)
}

func (sia *SessionInterfaceAdapter) GetResourceCount() int {
	return len(sia.Session.CreatedResources)
}

func (sia *SessionInterfaceAdapter) GetIdentities() map[string]*modules.Identity {
	return sia.Session.Identities
}

func (sia *SessionInterfaceAdapter) GetCurrentIdentity() string {
	return sia.Session.CurrentIdentity
}

func (sia *SessionInterfaceAdapter) GetCurrentModule() string {
	return sia.Session.CurrentModule
}

func (sia *SessionInterfaceAdapter) GetOptions() map[string]string {
	return sia.Session.Options
}

func (sia *SessionInterfaceAdapter) SetCurrentModule(module string) {
	sia.Session.CurrentModule = module
}

func (sia *SessionInterfaceAdapter) SetOptions(options map[string]string) {
	sia.Session.Options = options
}

func (sia *SessionInterfaceAdapter) SetIdentities(identities map[string]*modules.Identity) {
	sia.Session.Identities = identities
}

func (sia *SessionInterfaceAdapter) SetCurrentIdentity(name string) {
	sia.Session.CurrentIdentity = name
}

func (sia *SessionInterfaceAdapter) GetCommandLog() []repl.CommandLogEntry {
	entries := make([]repl.CommandLogEntry, len(sia.Session.CommandLog))
	for i, entry := range sia.Session.CommandLog {
		entries[i] = repl.CommandLogEntry{
			Timestamp: entry.Timestamp.Format("2006-01-02 15:04:05"),
			Command:   entry.Command,
			Success:   entry.Success,
			Error:     entry.Error,
			Output:    entry.Output,
		}
	}
	return entries
}

// IdentityManagerAdapter wraps IdentityManager to implement repl.IdentityManager interface
type IdentityManagerAdapter struct {
	*IdentityManager
}

func NewIdentityManagerAdapter(im *IdentityManager) *IdentityManagerAdapter {
	return &IdentityManagerAdapter{IdentityManager: im}
}

func (ima *IdentityManagerAdapter) GetIdentities() map[string]*modules.Identity {
	return ima.IdentityManager.GetIdentities()
}

func (ima *IdentityManagerAdapter) SetIdentities(identities map[string]*modules.Identity) {
	ima.IdentityManager.SetIdentities(identities)
}

func (ima *IdentityManagerAdapter) SetCurrent(identity *modules.Identity) {
	ima.IdentityManager.SetCurrent(identity)
}

func (ima *IdentityManagerAdapter) GetAttackerIdentity() *modules.Identity {
	return ima.IdentityManager.GetAttackerIdentity()
}

func (ima *IdentityManagerAdapter) SetAttackerIdentity(identity *modules.Identity) {
	ima.IdentityManager.SetAttackerIdentity(identity)
}

func (ima *IdentityManagerAdapter) ClearAttackerIdentity() {
	ima.IdentityManager.ClearAttackerIdentity()
}

// Helper function to parse time string
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}
