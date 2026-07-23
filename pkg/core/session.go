// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/pathrunner/pkg/modules"
)

type Session struct {
	Name             string                       `json:"name"`
	Created          time.Time                    `json:"created"`
	LastAccessed     time.Time                    `json:"last_accessed"`
	Identities       map[string]*modules.Identity `json:"identities"`
	CurrentIdentity  string                       `json:"current_identity"`
	AttackerIdentity *modules.Identity            `json:"attacker_identity,omitempty"`
	CurrentModule    string                       `json:"current_module"`
	Options          map[string]string            `json:"options"`
	CommandLog       []CommandLogEntry            `json:"command_log"`
	CreatedResources []CreatedResource            `json:"created_resources"`
	LastResult       string                       `json:"last_result"`
}

type CommandLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Output    string    `json:"output,omitempty"`
}

type CreatedResource struct {
	Type           string            `json:"type"`
	Name           string            `json:"name"`
	ARN            string            `json:"arn,omitempty"`
	Region         string            `json:"region"`
	Created        time.Time         `json:"created"`
	CleanupMethod  string            `json:"cleanup_method"`
	ModuleID       string            `json:"module_id,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	AccountContext string            `json:"account_context,omitempty"`
}

type SessionManager struct {
	currentSession *Session
	sessionsDir    string
	configManager  *ConfigManager
}

func NewSessionManager() *SessionManager {
	homeDir, _ := os.UserHomeDir()
	sessionsDir := filepath.Join(homeDir, ".pathrunner", "sessions")

	// Create sessions directory if it doesn't exist
	_ = os.MkdirAll(sessionsDir, 0700)

	// Create config manager
	configManager := NewConfigManager()

	sm := &SessionManager{
		sessionsDir:   sessionsDir,
		configManager: configManager,
	}

	// PATHRUNNER_WORKSPACE env var overrides the shared config.json workspace pointer.
	// This lets concurrent test agents each use their own isolated workspace without
	// overwriting each other's "current workspace" entry in the shared config file.
	// When the env var is set, workspace switch commands still switch within the
	// process but do not persist the change to config.json.
	forcedWorkspace := os.Getenv("PATHRUNNER_WORKSPACE")

	var currentWorkspace string
	if forcedWorkspace != "" {
		currentWorkspace = forcedWorkspace
	} else {
		// Load the last active workspace from config
		currentWorkspace = configManager.GetCurrentWorkspace()
	}

	// Try to load the last active session
	session, err := sm.LoadSession(currentWorkspace)
	if err != nil {
		if forcedWorkspace != "" {
			// PATHRUNNER_WORKSPACE is set but the workspace file doesn't exist yet.
			// Create it automatically so the first pathrunner invocation bootstraps
			// the workspace without needing a separate 'workspace create' call.
			session = &Session{
				Name:             forcedWorkspace,
				Created:          time.Now(),
				LastAccessed:     time.Now(),
				Identities:       make(map[string]*modules.Identity),
				Options:          make(map[string]string),
				CommandLog:       make([]CommandLogEntry, 0),
				CreatedResources: make([]CreatedResource, 0),
			}
			_ = sm.SaveSession(session)
		} else {
			// If the configured workspace doesn't exist, fall back to default
			session, err = sm.LoadSession("default")
			if err != nil {
				// Create default session if it doesn't exist
				session = &Session{
					Name:             "default",
					Created:          time.Now(),
					LastAccessed:     time.Now(),
					Identities:       make(map[string]*modules.Identity),
					Options:          make(map[string]string),
					CommandLog:       make([]CommandLogEntry, 0),
					CreatedResources: make([]CreatedResource, 0),
				}
				_ = sm.SaveSession(session)
			}
			// Update config to default since the configured one didn't exist
			_ = configManager.SetCurrentWorkspace("default")
		}
	}

	sm.currentSession = session
	return sm
}

func (sm *SessionManager) GetCurrentSession() *Session {
	return sm.currentSession
}

func (sm *SessionManager) CreateSession(name string) error {
	if name == "" {
		return fmt.Errorf("session name cannot be empty")
	}

	// Check if session already exists
	sessionFile := filepath.Join(sm.sessionsDir, name+".json")
	if _, err := os.Stat(sessionFile); err == nil {
		return fmt.Errorf("session '%s' already exists", name)
	}

	session := &Session{
		Name:             name,
		Created:          time.Now(),
		LastAccessed:     time.Now(),
		Identities:       make(map[string]*modules.Identity),
		Options:          make(map[string]string),
		CommandLog:       make([]CommandLogEntry, 0),
		CreatedResources: make([]CreatedResource, 0),
	}

	err := sm.SaveSession(session)
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}

	return nil
}

func (sm *SessionManager) SwitchSession(name string) error {
	session, err := sm.LoadSession(name)
	if err != nil {
		return fmt.Errorf("failed to switch to session '%s': %v", name, err)
	}

	// Save current session before switching
	if sm.currentSession != nil {
		_ = sm.SaveSession(sm.currentSession)
	}

	sm.currentSession = session
	sm.currentSession.LastAccessed = time.Now()
	_ = sm.SaveSession(sm.currentSession)

	// Only update config.json when not using an env-var-forced workspace.
	// When PATHRUNNER_WORKSPACE is set, we skip config.json writes so that
	// concurrent agents don't overwrite each other's workspace pointer.
	if sm.configManager != nil && os.Getenv("PATHRUNNER_WORKSPACE") == "" {
		_ = sm.configManager.SetCurrentWorkspace(name)
	}

	return nil
}

func (sm *SessionManager) ListSessions() ([]Session, error) {
	files, err := os.ReadDir(sm.sessionsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read sessions directory: %v", err)
	}

	var sessions []Session
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			sessionName := strings.TrimSuffix(file.Name(), ".json")
			session, err := sm.LoadSession(sessionName)
			if err != nil {
				continue // Skip corrupted sessions
			}
			sessions = append(sessions, *session)
		}
	}

	// Sort sessions by last accessed time (most recent first)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastAccessed.After(sessions[j].LastAccessed)
	})

	return sessions, nil
}

func (sm *SessionManager) DeleteSession(name string) error {
	if name == "default" {
		return fmt.Errorf("cannot delete the default session")
	}

	if sm.currentSession != nil && sm.currentSession.Name == name {
		return fmt.Errorf("cannot delete the currently active session")
	}

	sessionFile := filepath.Join(sm.sessionsDir, name+".json")
	err := os.Remove(sessionFile)
	if err != nil {
		return fmt.Errorf("failed to delete session '%s': %v", name, err)
	}

	return nil
}

func (sm *SessionManager) SaveSession(session *Session) error {
	session.LastAccessed = time.Now()

	sessionFile := filepath.Join(sm.sessionsDir, session.Name+".json")
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	err = os.WriteFile(sessionFile, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write session file: %v", err)
	}

	return nil
}

func (sm *SessionManager) LoadSession(name string) (*Session, error) {
	sessionFile := filepath.Join(sm.sessionsDir, name+".json")
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %v", err)
	}

	var session Session
	err = json.Unmarshal(data, &session)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %v", err)
	}

	return &session, nil
}

func (sm *SessionManager) LogCommand(command string, success bool, errorMsg, output string) {
	if sm.currentSession == nil {
		return
	}

	logEntry := CommandLogEntry{
		Timestamp: time.Now(),
		Command:   command,
		Success:   success,
		Error:     errorMsg,
		Output:    output,
	}

	sm.currentSession.CommandLog = append(sm.currentSession.CommandLog, logEntry)

	// Keep only last 1000 commands to prevent excessive growth
	if len(sm.currentSession.CommandLog) > 1000 {
		sm.currentSession.CommandLog = sm.currentSession.CommandLog[len(sm.currentSession.CommandLog)-1000:]
	}
}

func (sm *SessionManager) AddCreatedResource(resource CreatedResource) {
	if sm.currentSession == nil {
		return
	}

	resource.Created = time.Now()
	sm.currentSession.CreatedResources = append(sm.currentSession.CreatedResources, resource)
}

func (sm *SessionManager) RemoveCreatedResource(resourceName string) {
	if sm.currentSession == nil {
		return
	}

	for i, resource := range sm.currentSession.CreatedResources {
		if resource.Name == resourceName {
			sm.currentSession.CreatedResources = append(
				sm.currentSession.CreatedResources[:i],
				sm.currentSession.CreatedResources[i+1:]...,
			)
			break
		}
	}
}

func (sm *SessionManager) GetCreatedResources() []CreatedResource {
	if sm.currentSession == nil {
		return nil
	}
	return sm.currentSession.CreatedResources
}

func (sm *SessionManager) TrackResource(resource modules.CreatedResource) {
	if sm.currentSession == nil {
		return
	}

	// Convert modules.CreatedResource to core.CreatedResource
	coreResource := CreatedResource{
		Type:           resource.Type,
		Name:           resource.Name,
		ARN:            resource.ARN,
		Region:         resource.Region,
		Created:        resource.Created,
		CleanupMethod:  resource.CleanupMethod,
		ModuleID:       resource.ModuleID,
		Metadata:       resource.Metadata,
		AccountContext: resource.AccountContext,
	}

	sm.currentSession.CreatedResources = append(sm.currentSession.CreatedResources, coreResource)
}