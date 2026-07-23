// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/term"
)

// ShellSession represents an active reverse shell connection.
type ShellSession struct {
	ID          int
	conn        net.Conn
	sourceIP    string
	connectedAt time.Time
	done        chan struct{} // closed when connection is fully dead
	mu          sync.Mutex
}

// newShellListener creates a TLS listener for reverse shell connections on the given address.
func newShellListener(addr string, cert tls.Certificate) (net.Listener, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to start shell listener on %s: %v", addr, err)
	}
	return listener, nil
}

// acceptShellConnection blocks until a connection arrives on the listener.
// Returns a ShellSession that can be bridged to the terminal.
func acceptShellConnection(listener net.Listener) (*ShellSession, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	// Enable TCP keepalive to prevent idle connections from being dropped
	// by NAT gateways or firewalls before the user interacts with the session.
	enableTCPKeepAlive(conn)

	sourceIP := conn.RemoteAddr().String()

	return &ShellSession{
		conn:        conn,
		sourceIP:    sourceIP,
		connectedAt: time.Now(),
		done:        make(chan struct{}),
	}, nil
}

// enableTCPKeepAlive sets TCP keepalive on the underlying connection if possible.
// TLS connections wrap a net.TCPConn; we unwrap to configure keepalive.
func enableTCPKeepAlive(conn net.Conn) {
	type tlsUnwrapper interface {
		NetConn() net.Conn
	}
	if unwrapper, ok := conn.(tlsUnwrapper); ok {
		if tcpConn, ok := unwrapper.NetConn().(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}
}

// Bridge connects the shell session's I/O to stdin/stdout, blocking until
// the user backgrounds the session (Ctrl+Z) or the connection drops.
// Returns true if the session was backgrounded, false if it ended.
func (s *ShellSession) Bridge() (backgrounded bool) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		return false
	}

	// Put terminal in raw mode so Ctrl+Z is delivered as a byte (0x1a)
	// instead of being interpreted as SIGTSTP by the terminal driver.
	// Raw mode also disables local echo and line buffering.
	stdinFd := int(os.Stdin.Fd())
	oldState, rawErr := term.MakeRaw(stdinFd)
	if rawErr != nil {
		fmt.Printf("[!] Failed to set raw terminal mode: %v\n", rawErr)
	}
	defer func() {
		if oldState != nil {
			_ = term.Restore(stdinFd, oldState)
		}
	}()

	// Quick connectivity test: try a 1-byte read with a short deadline.
	// If the connection is dead, this returns an error immediately.
	// If alive, we get a timeout (no data) or actual data to replay.
	var pendingData []byte
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	testBuf := make([]byte, 4096)
	n, err := conn.Read(testBuf)
	_ = conn.SetReadDeadline(time.Time{})
	if n > 0 {
		pendingData = make([]byte, n)
		copy(pendingData, testBuf[:n])
	}
	if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			// Real error -- connection is dead
			s.markDone()
			return false
		}
	}

	// Replay any data that was buffered before Bridge() was called
	if len(pendingData) > 0 {
		_, _ = os.Stdout.Write(pendingData)
	}

	// Channel to coordinate shutdown between goroutines
	stop := make(chan struct{})
	stopOnce := sync.Once{}
	signalStop := func() { stopOnce.Do(func() { close(stop) }) }

	// Remote -> local stdout
	go func() {
		buf := make([]byte, 4096)
		for {
			// Use a read deadline so we can check the stop signal periodically
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			readN, readErr := conn.Read(buf)
			if readN > 0 {
				_, _ = os.Stdout.Write(buf[:readN])
			}
			select {
			case <-stop:
				return
			default:
			}
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					continue
				}
				// Connection dropped
				signalStop()
				return
			}
		}
	}()

	// Local stdin -> remote, with Ctrl+Z detection for backgrounding
	buf := make([]byte, 256)
	for {
		select {
		case <-stop:
			// Remote disconnected while we were waiting for stdin
			_ = conn.SetReadDeadline(time.Time{})
			s.markDone()
			return false
		default:
		}

		stdinN, stdinErr := os.Stdin.Read(buf)
		if stdinErr != nil {
			signalStop()
			_ = conn.SetReadDeadline(time.Time{})
			s.markDone()
			return false
		}

		if stdinN > 0 {
			// Scan for Ctrl+Z (0x1a) to background the session
			for i := range stdinN {
				if buf[i] == 0x1a {
					// Send any bytes before the Ctrl+Z
					if i > 0 {
						_, _ = conn.Write(buf[:i])
					}
					signalStop()
					_ = conn.SetReadDeadline(time.Time{})
					return true
				}
			}
			if _, writeErr := conn.Write(buf[:stdinN]); writeErr != nil {
				signalStop()
				_ = conn.SetReadDeadline(time.Time{})
				s.markDone()
				return false
			}
		}

		// Re-check stop after processing input
		select {
		case <-stop:
			_ = conn.SetReadDeadline(time.Time{})
			s.markDone()
			return false
		default:
		}
	}
}

// markDone closes the done channel exactly once, signaling the session has ended.
func (s *ShellSession) markDone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		// already closed
	default:
		close(s.done)
	}
}

// Close terminates the shell session.
func (s *ShellSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}

	if s.done != nil {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
}

// IsAlive returns true if the connection has not been closed.
// This checks local state only -- a remotely-dropped connection won't be
// detected until the next read/write in Bridge().
func (s *ShellSession) IsAlive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return false
	}
	// Check if done channel is closed (session already ended)
	if s.done != nil {
		select {
		case <-s.done:
			return false
		default:
		}
	}
	return true
}

// SourceIP returns the remote address of the shell connection.
func (s *ShellSession) SourceIP() string {
	return s.sourceIP
}

// ConnectedAt returns when the session was established.
func (s *ShellSession) ConnectedAt() time.Time {
	return s.connectedAt
}

// Done returns a channel that closes when the session ends.
func (s *ShellSession) Done() <-chan struct{} {
	return s.done
}

// ShellSessionManager tracks multiple shell sessions with auto-incrementing IDs.
type ShellSessionManager struct {
	sessions map[int]*ShellSession
	nextID   int
	mu       sync.RWMutex
}

// NewShellSessionManager creates a new session manager.
func NewShellSessionManager() *ShellSessionManager {
	return &ShellSessionManager{
		sessions: make(map[int]*ShellSession),
	}
}

// Add registers a new session and returns its assigned ID.
func (m *ShellSessionManager) Add(session *ShellSession) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	session.ID = m.nextID
	m.sessions[m.nextID] = session
	return m.nextID
}

// Get returns a session by ID, or nil if not found.
func (m *ShellSessionManager) Get(id int) *ShellSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// List returns all sessions sorted by ID.
func (m *ShellSessionManager) List() []*ShellSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*ShellSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return result
}

// Kill closes and removes a session by ID.
func (m *ShellSessionManager) Kill(id int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok {
		return false
	}
	session.Close()
	delete(m.sessions, id)
	return true
}

// Remove removes a session from tracking without closing it.
// Used to clean up dead sessions.
func (m *ShellSessionManager) Remove(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// ActiveCount returns the number of sessions with live connections.
func (m *ShellSessionManager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, s := range m.sessions {
		if s.IsAlive() {
			count++
		}
	}
	return count
}

// TotalCount returns the total number of tracked sessions.
func (m *ShellSessionManager) TotalCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Cleanup removes dead sessions from tracking.
func (m *ShellSessionManager) Cleanup() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, s := range m.sessions {
		if !s.IsAlive() {
			delete(m.sessions, id)
			removed++
		}
	}
	return removed
}
