package repl

import (
	"io"
	"os"
	"pathrunner/pkg/modules"
	"strings"

	"github.com/chzyer/readline"
)

type REPL struct {
	rl              *readline.Instance
	identityManager IdentityManager
	sessionManager  SessionManager
	currentModule   modules.Module
	options         map[string]string
	lastResult      string
	aliases         map[string]string // command aliases
}

type Command struct {
	Name        string
	Description string
	Handler     func(*REPL, []string) error
}

// IdentityManager interface for dependency injection
type IdentityManager interface {
	GetCurrent() *modules.Identity
	GetIdentities() map[string]*modules.Identity
	ListIdentities() error
	ShowCurrent() error
	AddIdentity(args []string) error
	SwitchIdentity(name string) error
	RemoveIdentity(args []string) error
	RefreshCurrentIdentity() error
	CheckAdmin(identityName string) error
	SetIdentities(identities map[string]*modules.Identity)
	SetCurrent(identity *modules.Identity)
}

// SessionManager interface for dependency injection
type SessionManager interface {
	GetCurrentSession() Session
	CreateSession(name string) error
	SwitchSession(name string) error
	ListSessions() ([]Session, error)
	DeleteSession(name string) error
	SaveSession(session Session) error
	LogCommand(command string, success bool, errorMsg, output string)
	AddCreatedResource(resource CreatedResource)
	RemoveCreatedResource(resourceName string)
	GetCreatedResources() []CreatedResource
	TrackResource(resource modules.CreatedResource)
}

// Session interface to avoid circular dependencies
type Session interface {
	GetName() string
	GetCreated() string
	GetLastAccessed() string
	GetCommandCount() int
	GetResourceCount() int
	GetIdentities() map[string]*modules.Identity
	GetCurrentIdentity() string
	GetCurrentModule() string
	GetOptions() map[string]string
	GetCommandLog() []CommandLogEntry
	SetCurrentModule(module string)
	SetOptions(options map[string]string)
	SetIdentities(identities map[string]*modules.Identity)
	SetCurrentIdentity(name string)
}

// CommandLogEntry represents a logged command
type CommandLogEntry struct {
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Output    string `json:"output,omitempty"`
}

// CreatedResource to avoid circular dependency
type CreatedResource struct {
	Type          string            `json:"type"`
	Name          string            `json:"name"`
	ARN           string            `json:"arn,omitempty"`
	Region        string            `json:"region"`
	Created       string            `json:"created"`
	CleanupMethod string            `json:"cleanup_method"`
	ModuleID      string            `json:"module_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

func NewREPL(identityManager IdentityManager, sessionManager SessionManager) *REPL {
	r := &REPL{
		options:         make(map[string]string),
		identityManager: identityManager,
		sessionManager:  sessionManager,
		aliases:         make(map[string]string),
	}

	// Register command aliases
	r.aliases["identities"] = "identity"
	r.aliases["id"] = "identity"
	r.aliases["ids"] = "identity"
	r.aliases["workspaces"] = "workspace"
	r.aliases["quit"] = "exit"
	// Note: "modules" and "payloads" are now top-level commands with subcommands,
	// registered directly in getCommands(), so no aliases needed.

	// Load state from current session
	r.loadSessionState()

	return r
}

func (r *REPL) Start() error {
	// Get home directory for history file
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	historyFile := homeDir + "/.pathrunner/history"

	var rlErr error
	r.rl, rlErr = readline.NewEx(&readline.Config{
		Prompt:          r.BuildContextualPrompt(),
		HistoryFile:     historyFile,
		AutoComplete:    r.getCompleter(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if rlErr != nil {
		return rlErr
	}
	defer r.rl.Close()

	for {
		line, err := r.rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		} else if err == io.EOF {
			break
		}

		if err := r.handleCommand(strings.TrimSpace(line)); err != nil {
			if err == io.EOF {
				break
			}
			r.rl.Write([]byte("Error: " + err.Error() + "\n"))
		}
	}

	return nil
}

// ExecuteCommand executes a command and handles state management/persistence
// This is the public API for CLI to use
func (r *REPL) ExecuteCommand(line string) error {
	return r.handleCommand(line)
}

func (r *REPL) handleCommand(line string) error {
	if line == "" {
		return nil
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	cmd := parts[0]
	args := parts[1:]

	// Resolve alias if exists
	if alias, exists := r.aliases[cmd]; exists {
		// If alias contains spaces, it's a multi-word command
		if strings.Contains(alias, " ") {
			// Reconstruct the full line with the expanded alias
			line = alias
			if len(args) > 0 {
				line += " " + strings.Join(args, " ")
			}
			// Re-parse the expanded line
			parts = strings.Fields(line)
			cmd = parts[0]
			args = parts[1:]
		} else {
			cmd = alias
		}
	}

	commands := r.getCommands()
	if command, exists := commands[cmd]; exists {
		// Log command execution
		err := command.Handler(r, args)
		success := err == nil
		errorMsg := ""
		if err != nil {
			errorMsg = err.Error()
		}
		r.sessionManager.LogCommand(line, success, errorMsg, r.lastResult)

		// Save state after each command
		r.saveCurrentState()
		// Persist session to disk
		current := r.sessionManager.GetCurrentSession()
		if current != nil {
			r.sessionManager.SaveSession(current)
		}
		return err
	}

	return NewCommandNotFoundError(cmd)
}

// GetLastResult returns the last command result for testing/external access
func (r *REPL) GetLastResult() string {
	return r.lastResult
}

// SetLastResult sets the last command result
func (r *REPL) SetLastResult(result string) {
	r.lastResult = result
}

// GetCurrentModule returns the current module
func (r *REPL) GetCurrentModule() modules.Module {
	return r.currentModule
}

// SetCurrentModule sets the current module
func (r *REPL) SetCurrentModule(module modules.Module) {
	r.currentModule = module
	if r.rl != nil {
		r.updateCompletion()
		r.UpdatePrompt()
	}
}

// GetOptions returns the current options
func (r *REPL) GetOptions() map[string]string {
	return r.options
}

// SetOption sets a single option
func (r *REPL) SetOption(key, value string) {
	r.options[key] = value
}

// UnsetOption removes an option
func (r *REPL) UnsetOption(key string) {
	delete(r.options, key)
}

// GetIdentityManager returns the identity manager
func (r *REPL) GetIdentityManager() IdentityManager {
	return r.identityManager
}

// GetSessionManager returns the session manager
func (r *REPL) GetSessionManager() SessionManager {
	return r.sessionManager
}

// UpdatePrompt updates the REPL prompt (public method)
func (r *REPL) UpdatePrompt() {
	if r.rl != nil {
		prompt := r.BuildContextualPrompt()
		r.rl.SetPrompt(prompt)
	}
}

// BuildContextualPrompt builds a dynamic prompt showing current context (public for testing)
func (r *REPL) BuildContextualPrompt() string {
	const (
		cyan       = "\033[36m"
		brightCyan = "\033[96m"
		reset      = "\033[0m"
	)

	var parts []string
	var moduleIndex int = -1

	// Always show workspace
	session := r.sessionManager.GetCurrentSession()
	sessionName := session.GetName()
	parts = append(parts, sessionName)

	// Add identity if present
	if identity := r.identityManager.GetCurrent(); identity != nil {
		identityPart := identity.Name
		if identity.IsExpired() {
			identityPart += "*" // Mark expired with asterisk
		}
		if identity.IsAdmin != nil && *identity.IsAdmin {
			identityPart += "!" // Mark admin with exclamation
		}
		parts = append(parts, identityPart)
	}

	// Add module if selected
	if r.currentModule != nil {
		moduleName := r.currentModule.Name()
		// Extract the last part after the last slash
		moduleParts := strings.Split(moduleName, "/")
		if len(moduleParts) > 0 {
			moduleIndex = len(parts) // Track which part is the module
			parts = append(parts, moduleParts[len(moduleParts)-1])
		}
	}

	// Note: Payload is not shown in prompt to keep it shorter
	// Users can see payload with 'context' or 'show options' commands

	// Build single-line prompt with separator
	// Using spaced brackets for clean, readable display
	// Whole prompt is cyan, but module is bright cyan
	var prompt string
	if len(parts) > 0 {
		var coloredParts []string
		for i, part := range parts {
			if i == moduleIndex {
				// Module gets bright cyan
				coloredParts = append(coloredParts, brightCyan+"["+part+"]"+cyan)
			} else {
				// Other parts get regular cyan
				coloredParts = append(coloredParts, "["+part+"]")
			}
		}
		prompt = cyan + strings.Join(coloredParts, " ") + " > " + reset
	} else {
		prompt = cyan + "> " + reset
	}

	return prompt
}
