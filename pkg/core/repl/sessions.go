// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package repl

import (
	"fmt"
	"github.com/DataDog/pathrunner/pkg/ui"
	"strconv"
	"time"
)

// cmdSessions handles the "sessions" command for managing shell sessions.
func (r *REPL) cmdSessions(repl *REPL, args []string) error {
	if len(args) == 0 {
		return r.sessionsList()
	}

	switch args[0] {
	case "list", "-l":
		return r.sessionsList()
	case "interact", "-i":
		if len(args) < 2 {
			return NewInvalidArgumentsError("usage: sessions interact <id>")
		}
		return r.sessionsInteract(args[1])
	case "kill", "-k":
		if len(args) < 2 {
			return NewInvalidArgumentsError("usage: sessions kill <id>")
		}
		return r.sessionsKill(args[1])
	case "help":
		return r.showSessionsHelp()
	default:
		// Try to parse as "sessions <id>" shorthand for interact
		if _, err := strconv.Atoi(args[0]); err == nil {
			return r.sessionsInteract(args[0])
		}
		return NewInvalidArgumentsError(fmt.Sprintf("unknown sessions subcommand: %s. Use 'sessions help' for available commands", args[0]))
	}
}

// sessionsList displays all tracked shell sessions.
func (r *REPL) sessionsList() error {
	if r.listener == nil || !r.listener.IsRunning() {
		fmt.Println("No listener is running.")
		fmt.Println("Use 'attacker listener start' to start the listener.")
		return nil
	}

	sessionManager := r.listener.SessionManager
	sessions := sessionManager.List()

	if len(sessions) == 0 {
		fmt.Println("No active sessions.")
		return nil
	}

	fmt.Println()
	rows := make([][]string, 0, len(sessions))
	for _, s := range sessions {
		status := ui.Success.Render("alive")
		if !s.IsAlive() {
			status = ui.Error.Render("dead")
		}
		duration := time.Since(s.ConnectedAt()).Truncate(time.Second).String()
		rows = append(rows, []string{
			fmt.Sprintf("%d", s.ID),
			s.SourceIP(),
			duration,
			status,
		})
	}

	ui.Table([]string{"ID", "Remote Address", "Duration", "Status"}, rows)
	fmt.Println()

	return nil
}

// sessionsInteract bridges the terminal to a specific session.
func (r *REPL) sessionsInteract(idStr string) error {
	if r.listener == nil || !r.listener.IsRunning() {
		return fmt.Errorf("no listener is running")
	}

	sessionID, err := strconv.Atoi(idStr)
	if err != nil {
		return NewInvalidArgumentsError("session ID must be a number")
	}

	session := r.listener.SessionManager.Get(sessionID)
	if session == nil {
		return fmt.Errorf("session %d not found", sessionID)
	}

	if !session.IsAlive() {
		r.listener.SessionManager.Remove(sessionID)
		return fmt.Errorf("session %d is no longer alive", sessionID)
	}

	fmt.Printf("[*] Starting interaction with session %d (%s)\n", sessionID, session.SourceIP())
	fmt.Println("[*] Press Ctrl+Z to background the session.")

	// Pause readline so the shell gets exclusive stdin access
	resumeREPL := r.PauseForShell()

	backgrounded := session.Bridge()

	if backgrounded {
		fmt.Printf("\n[*] Session %d backgrounded.\n", sessionID)
	} else {
		fmt.Printf("\n[*] Session %d closed.\n", sessionID)
		r.listener.SessionManager.Remove(sessionID)
	}

	// Restore readline and resume the REPL loop
	resumeREPL()

	return nil
}

// sessionsKill terminates a specific session.
func (r *REPL) sessionsKill(idStr string) error {
	if r.listener == nil || !r.listener.IsRunning() {
		return fmt.Errorf("no listener is running")
	}

	sessionID, err := strconv.Atoi(idStr)
	if err != nil {
		return NewInvalidArgumentsError("session ID must be a number")
	}

	if r.listener.SessionManager.Kill(sessionID) {
		fmt.Printf("[*] Session %d killed.\n", sessionID)
	} else {
		return fmt.Errorf("session %d not found", sessionID)
	}

	return nil
}

func (r *REPL) showSessionsHelp() error {
	fmt.Println("Session Management Commands:")
	fmt.Println("  sessions                  - List all shell sessions")
	fmt.Println("  sessions list             - List all shell sessions")
	fmt.Println("  sessions interact <id>    - Interact with a session")
	fmt.Println("  sessions <id>             - Shorthand for interact")
	fmt.Println("  sessions kill <id>        - Kill a session")
	fmt.Println("  sessions -i <id>          - Shorthand for interact")
	fmt.Println("  sessions -k <id>          - Shorthand for kill")
	fmt.Println("  sessions help             - Show this help message")
	fmt.Println()
	fmt.Println("When interacting with a session:")
	fmt.Println("  Ctrl+Z    Background the session (keeps connection alive)")
	fmt.Println()
	fmt.Println("Sessions are collected automatically when reverse shells connect")
	fmt.Println("to the listener's shell port.")
	return nil
}
