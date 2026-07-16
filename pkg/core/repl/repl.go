package repl

import (
	"fmt"
	"io"
	"os"
	"github.com/DataDog/pathrunner/pkg/attacker"
	"github.com/DataDog/pathrunner/pkg/modules"
	"github.com/DataDog/pathrunner/pkg/pmapper"
	"github.com/DataDog/pathrunner/pkg/resources"
	"github.com/DataDog/pathrunner/pkg/ui"
	"strings"
	"sync"

	"github.com/chzyer/readline"
)

type REPL struct {
	rl              *readline.Instance
	rlConfig        *readline.Config
	identityManager  IdentityManager
	sessionManager   SessionManager
	pmapperManager   *pmapper.Manager
	resourcesManager *resources.Manager
	currentModule    modules.Module
	options         map[string]string
	lastResult      string
	aliases         map[string]string // command aliases
	listener        *attacker.UnifiedListener
	shellActive     chan struct{} // closed when a shell session ends; nil when no shell
	shellMu         sync.Mutex
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
	AddIdentityFromCredentials(accessKey, secret, token, region, name string) error
	SwitchIdentity(name string) error
	RemoveIdentity(args []string) error
	RefreshCurrentIdentity() error
	CheckAdmin(identityName string) error
	SetIdentities(identities map[string]*modules.Identity)
	SetCurrent(identity *modules.Identity)
	GetAttackerIdentity() *modules.Identity
	SetAttackerIdentity(identity *modules.Identity)
	ClearAttackerIdentity()
	ClearIdentity()
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
	Type           string            `json:"type"`
	Name           string            `json:"name"`
	ARN            string            `json:"arn,omitempty"`
	Region         string            `json:"region"`
	Created        string            `json:"created"`
	CleanupMethod  string            `json:"cleanup_method"`
	ModuleID       string            `json:"module_id,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	AccountContext string            `json:"account_context,omitempty"`
}

func NewREPL(identityManager IdentityManager, sessionManager SessionManager) *REPL {
	r := &REPL{
		options:          make(map[string]string),
		identityManager:  identityManager,
		sessionManager:   sessionManager,
		pmapperManager:   pmapper.NewManager(),
		resourcesManager: resources.NewManager(),
		aliases:          make(map[string]string),
	}

	// Register command aliases
	r.aliases["identities"] = "identity"
	r.aliases["id"] = "identity"
	r.aliases["ids"] = "identity"
	r.aliases["workspaces"] = "workspace"
	r.aliases["quit"] = "exit"
	r.aliases["session"] = "sessions"
	r.aliases["listener"] = "attacker listener"
	r.aliases["infra"] = "attacker infra"
	r.aliases["run"] = "exploit"

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

	r.rlConfig = &readline.Config{
		Prompt:          r.BuildContextualPrompt(),
		HistoryFile:     historyFile,
		AutoComplete:    r.getCompleter(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}

	var rlErr error
	r.rl, rlErr = readline.NewEx(r.rlConfig)
	if rlErr != nil {
		return rlErr
	}
	defer r.rl.Close()

	ui.ClearScreen()
	r.PrintStartupBanner()

	// Auto-restart listener if one was running in a previous session
	r.restoreListener()

	for {
		// If a shell session is active, wait for it to finish before reading input
		r.shellMu.Lock()
		shellDone := r.shellActive
		r.shellMu.Unlock()
		if shellDone != nil {
			<-shellDone
			continue
		}

		line, err := r.rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		} else if err == io.EOF {
			// EOF can be from Close() during shell takeover -- check if shell is active
			r.shellMu.Lock()
			shellDone = r.shellActive
			r.shellMu.Unlock()
			if shellDone != nil {
				<-shellDone
				continue
			}
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

// PauseForShell closes readline so a shell session can take exclusive control
// of stdin/stdout. Returns a function to call when the shell session ends.
func (r *REPL) PauseForShell() func() {
	r.shellMu.Lock()
	r.shellActive = make(chan struct{})
	r.shellMu.Unlock()

	// Close readline so it stops reading stdin
	if r.rl != nil {
		r.rl.Close()
	}

	return func() {
		// Reinitialize readline
		var err error
		r.rl, err = readline.NewEx(r.rlConfig)
		if err != nil {
			fmt.Printf("[!] Failed to reinitialize readline: %v\n", err)
		}
		r.UpdatePrompt()

		r.shellMu.Lock()
		close(r.shellActive)
		r.shellActive = nil
		r.shellMu.Unlock()
	}
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

// GetPMapperManager returns the PMapper graph manager
func (r *REPL) GetPMapperManager() *pmapper.Manager {
	return r.pmapperManager
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
	session := r.sessionManager.GetCurrentSession()
	workspace := session.GetName()

	identityName := ""
	expired := false
	admin := false
	if identity := r.identityManager.GetCurrent(); identity != nil {
		identityName = identity.Name
		expired = identity.IsExpired()
		admin = identity.IsAdmin != nil && *identity.IsAdmin
	}

	moduleName := ""
	if r.currentModule != nil {
		moduleName = r.currentModule.Name()
	}

	return ui.Prompt(workspace, identityName, moduleName, expired, admin)
}
