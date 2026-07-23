// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package attacker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ListenerEventType categorizes listener events.
type ListenerEventType string

const (
	EventHTTPRequest    ListenerEventType = "http_request"
	EventCredsParsed    ListenerEventType = "creds_parsed"
	EventCredsError     ListenerEventType = "creds_error"
	EventShellConnect   ListenerEventType = "shell_connect"
	EventShellDisconnect ListenerEventType = "shell_disconnect"
)

// ListenerEvent represents a single listener event for logging and display.
type ListenerEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	Type      ListenerEventType `json:"type"`
	SourceIP  string            `json:"source_ip,omitempty"`
	Method    string            `json:"method,omitempty"`
	Path      string            `json:"path,omitempty"`
	Status    int               `json:"status,omitempty"`
	Message   string            `json:"message"`
	Error     string            `json:"error,omitempty"`
}

// FormatEvent returns a Metasploit-style display string for a listener event.
func (e ListenerEvent) FormatEvent() string {
	ts := e.Timestamp.Format("15:04:05")

	switch e.Type {
	case EventHTTPRequest:
		return fmt.Sprintf("[%s] [*] %s %s from %s", ts, e.Method, e.Path, e.SourceIP)
	case EventCredsParsed:
		return fmt.Sprintf("[%s] [+] %s", ts, e.Message)
	case EventCredsError:
		return fmt.Sprintf("[%s] [-] %s from %s: %s", ts, e.Message, e.SourceIP, e.Error)
	case EventShellConnect:
		return fmt.Sprintf("[%s] [+] %s", ts, e.Message)
	case EventShellDisconnect:
		return fmt.Sprintf("[%s] [*] %s", ts, e.Message)
	default:
		return fmt.Sprintf("[%s] [*] %s", ts, e.Message)
	}
}

// ListenerEventLog writes events to a log file on disk.
type ListenerEventLog struct {
	filePath string
	file     *os.File
	mu       sync.Mutex
}

func listenerLogPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".pathrunner", "listener.log")
}

// NewListenerEventLog creates or opens the listener log file.
func NewListenerEventLog() (*ListenerEventLog, error) {
	logPath := listenerLogPath()

	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open listener log: %v", err)
	}

	return &ListenerEventLog{
		filePath: logPath,
		file:     file,
	}, nil
}

// Write appends an event to the log file as a JSON line.
func (l *ListenerEventLog) Write(event ListenerEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	_, _ = l.file.Write(append(data, '\n'))
}

// Close closes the log file.
func (l *ListenerEventLog) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
	}
}

// ReadRecentEvents reads the last N events from the log file.
func ReadRecentEvents(count int) ([]ListenerEvent, error) {
	logPath := listenerLogPath()

	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// Split into lines, parse each as JSON
	var allEvents []ListenerEvent
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			line := data[start:i]
			start = i + 1
			if len(line) == 0 {
				continue
			}
			var event ListenerEvent
			if err := json.Unmarshal(line, &event); err != nil {
				continue
			}
			allEvents = append(allEvents, event)
		}
	}

	// Return last N
	if len(allEvents) <= count {
		return allEvents, nil
	}
	return allEvents[len(allEvents)-count:], nil
}
