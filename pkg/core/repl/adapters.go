package repl

import (
	"pathrunner/pkg/modules"
	"time"
)

// IdentityManagerAdapter adapts the core IdentityManager to our interface
type IdentityManagerAdapter struct {
	impl interface {
		GetCurrent() *modules.Identity
		ListIdentities() error
		ShowCurrent() error
		AddIdentity(args []string) error
		SwitchIdentity(name string) error
		RefreshCurrentIdentity() error
	}
}

func NewIdentityManagerAdapter(impl interface {
	GetCurrent() *modules.Identity
	ListIdentities() error
	ShowCurrent() error
	AddIdentity(args []string) error
	SwitchIdentity(name string) error
	RefreshCurrentIdentity() error
}) *IdentityManagerAdapter {
	return &IdentityManagerAdapter{impl: impl}
}

func (a *IdentityManagerAdapter) GetCurrent() *modules.Identity {
	return a.impl.GetCurrent()
}

func (a *IdentityManagerAdapter) ListIdentities() error {
	return a.impl.ListIdentities()
}

func (a *IdentityManagerAdapter) ShowCurrent() error {
	return a.impl.ShowCurrent()
}

func (a *IdentityManagerAdapter) AddIdentity(args []string) error {
	return a.impl.AddIdentity(args)
}

func (a *IdentityManagerAdapter) SwitchIdentity(name string) error {
	return a.impl.SwitchIdentity(name)
}

func (a *IdentityManagerAdapter) RefreshCurrentIdentity() error {
	return a.impl.RefreshCurrentIdentity()
}

// SessionManagerAdapter adapts the core SessionManager to our interface
type SessionManagerAdapter struct {
	impl interface {
		GetCurrentSession() interface{}
		CreateSession(name string) error
		SwitchSession(name string) error
		ListSessions() ([]interface{}, error)
		DeleteSession(name string) error
		SaveSession(session interface{}) error
		LogCommand(command string, success bool, errorMsg, output string)
		AddCreatedResource(resource interface{})
		RemoveCreatedResource(resourceName string)
		GetCreatedResources() []interface{}
		TrackResource(resource modules.CreatedResource)
	}
}

func NewSessionManagerAdapter(impl interface {
	GetCurrentSession() interface{}
	CreateSession(name string) error
	SwitchSession(name string) error
	ListSessions() ([]interface{}, error)
	DeleteSession(name string) error
	SaveSession(session interface{}) error
	LogCommand(command string, success bool, errorMsg, output string)
	AddCreatedResource(resource interface{})
	RemoveCreatedResource(resourceName string)
	GetCreatedResources() []interface{}
	TrackResource(resource modules.CreatedResource)
}) *SessionManagerAdapter {
	return &SessionManagerAdapter{impl: impl}
}

func (a *SessionManagerAdapter) GetCurrentSession() Session {
	session := a.impl.GetCurrentSession()
	return &SessionAdapter{impl: session}
}

func (a *SessionManagerAdapter) CreateSession(name string) error {
	return a.impl.CreateSession(name)
}

func (a *SessionManagerAdapter) SwitchSession(name string) error {
	return a.impl.SwitchSession(name)
}

func (a *SessionManagerAdapter) ListSessions() ([]Session, error) {
	sessions, err := a.impl.ListSessions()
	if err != nil {
		return nil, err
	}

	result := make([]Session, len(sessions))
	for i, session := range sessions {
		result[i] = &SessionAdapter{impl: session}
	}
	return result, nil
}

func (a *SessionManagerAdapter) DeleteSession(name string) error {
	return a.impl.DeleteSession(name)
}

func (a *SessionManagerAdapter) SaveSession(session Session) error {
	return a.impl.SaveSession(session.(*SessionAdapter).impl)
}

func (a *SessionManagerAdapter) LogCommand(command string, success bool, errorMsg, output string) {
	a.impl.LogCommand(command, success, errorMsg, output)
}

func (a *SessionManagerAdapter) AddCreatedResource(resource CreatedResource) {
	a.impl.AddCreatedResource(resource)
}

func (a *SessionManagerAdapter) RemoveCreatedResource(resourceName string) {
	a.impl.RemoveCreatedResource(resourceName)
}

func (a *SessionManagerAdapter) GetCreatedResources() []CreatedResource {
	resources := a.impl.GetCreatedResources()
	result := make([]CreatedResource, len(resources))

	for i := range resources {
		// This would need to convert from the actual resource type
		// to our CreatedResource interface
		result[i] = CreatedResource{
			Type:          "unknown", // Would need proper conversion
			Name:          "unknown", // Would need proper conversion
			Region:        "unknown", // Would need proper conversion
			Created:       time.Now().Format("2006-01-02 15:04:05"),
			CleanupMethod: "manual",
		}
	}
	return result
}

func (a *SessionManagerAdapter) TrackResource(resource modules.CreatedResource) {
	a.impl.TrackResource(resource)
}

// SessionAdapter adapts a session to our interface
type SessionAdapter struct {
	impl interface{}
}

func (s *SessionAdapter) GetName() string {
	// This would need to be implemented based on the actual session type
	return "default"
}

func (s *SessionAdapter) GetCreated() string {
	return time.Now().Format("2006-01-02 15:04")
}

func (s *SessionAdapter) GetLastAccessed() string {
	return time.Now().Format("2006-01-02 15:04")
}

func (s *SessionAdapter) GetCommandCount() int {
	return 0 // Would need proper implementation
}

func (s *SessionAdapter) GetResourceCount() int {
	return 0 // Would need proper implementation
}

func (s *SessionAdapter) GetIdentities() map[string]*modules.Identity {
	return make(map[string]*modules.Identity) // Would need proper implementation
}

func (s *SessionAdapter) GetCurrentIdentity() string {
	return ""
}

func (s *SessionAdapter) GetCurrentModule() string {
	return ""
}

func (s *SessionAdapter) GetOptions() map[string]string {
	return make(map[string]string)
}

func (s *SessionAdapter) SetCurrentModule(module string) {
	// Would need proper implementation
}

func (s *SessionAdapter) SetOptions(options map[string]string) {
	// Would need proper implementation
}

func (s *SessionAdapter) SetIdentities(identities map[string]*modules.Identity) {
	// Would need proper implementation
}

func (s *SessionAdapter) SetCurrentIdentity(name string) {
	// Would need proper implementation
}

func (s *SessionAdapter) GetCommandLog() []CommandLogEntry {
	return make([]CommandLogEntry, 0) // Would need proper implementation
}

func (s *SessionAdapter) GetAttackerIdentity() *modules.Identity {
	return nil
}

func (s *SessionAdapter) SetAttackerIdentity(identity *modules.Identity) {
}