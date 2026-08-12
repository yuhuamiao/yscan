package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ServerStatus string

const (
	ServerStopped  ServerStatus = "stopped"
	ServerStarting ServerStatus = "starting"
	ServerRunning  ServerStatus = "running"
	ServerDegraded ServerStatus = "degraded"
)

// ServerState is health metadata, not an inter-process lock.
type ServerState struct {
	PID           int          `json:"pid"`
	Status        ServerStatus `json:"status"`
	ListenAddress string       `json:"listen_address"`
	HealthToken   string       `json:"health_token"`
	StartedAt     time.Time    `json:"started_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
	Diagnostic    string       `json:"diagnostic,omitempty"`
}

type ServerInspection struct {
	Status ServerStatus
	State  *ServerState
	Error  string
}

type ServerSession struct {
	paths  HomePaths
	mu     sync.Mutex
	state  ServerState
	closed bool
}

func AcquireServerSession(paths HomePaths, listenAddress string) (*ServerSession, error) {
	healthToken, err := randomHealthToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	session := &ServerSession{paths: paths, state: ServerState{
		PID: os.Getpid(), Status: ServerStarting, ListenAddress: listenAddress,
		HealthToken: healthToken, StartedAt: now, UpdatedAt: now,
	}}
	if err := writeServerStateAtomic(paths.ServerState, session.state); err != nil {
		return nil, err
	}
	return session, nil
}

func AcquireServerSessionForStartup(paths HomePaths, listenAddress string) (*ServerSession, error) {
	return AcquireServerSession(paths, listenAddress)
}

func (session *ServerSession) MarkRunning() error { return session.update(ServerRunning, "") }

func (session *ServerSession) MarkDegraded(diagnostic string) error {
	return session.update(ServerDegraded, diagnostic)
}

func (session *ServerSession) State() ServerState {
	if session == nil {
		return ServerState{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.state
}

func (session *ServerSession) Close() error {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	current, err := ReadServerState(session.paths.ServerState)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.PID != session.state.PID || current.HealthToken != session.state.HealthToken {
		return nil
	}
	if err := os.Remove(session.paths.ServerState); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove server state: %w", err)
	}
	return nil
}

func (session *ServerSession) update(status ServerStatus, diagnostic string) error {
	if session == nil {
		return errors.New("server session is unavailable")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return errors.New("server session is closed")
	}
	session.state.Status = status
	session.state.Diagnostic = diagnostic
	session.state.UpdatedAt = time.Now().UTC()
	return writeServerStateAtomic(session.paths.ServerState, session.state)
}

func InspectServer(paths HomePaths) ServerInspection {
	state, err := ReadServerState(paths.ServerState)
	if errors.Is(err, os.ErrNotExist) {
		return ServerInspection{Status: ServerStopped}
	}
	if err != nil {
		return ServerInspection{Status: ServerDegraded, Error: err.Error()}
	}
	if !processExists(state.PID) {
		return ServerInspection{Status: ServerStopped, State: &state, Error: "stale server state"}
	}
	switch state.Status {
	case ServerStarting, ServerRunning, ServerDegraded:
		return ServerInspection{Status: state.Status, State: &state, Error: state.Diagnostic}
	default:
		return ServerInspection{Status: ServerDegraded, State: &state, Error: fmt.Sprintf("invalid server status %q", state.Status)}
	}
}

func ReadServerState(path string) (ServerState, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return ServerState{}, fmt.Errorf("read server state %s: %w", path, err)
	}
	var state ServerState
	if err := json.Unmarshal(content, &state); err != nil {
		return ServerState{}, fmt.Errorf("decode server state %s: %w", path, err)
	}
	if state.PID <= 0 || state.HealthToken == "" || state.ListenAddress == "" || state.StartedAt.IsZero() {
		return ServerState{}, fmt.Errorf("invalid server state %s", path)
	}
	return state, nil
}

func writeServerStateAtomic(path string, state ServerState) error {
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".server.state.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary server state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish server state: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func randomHealthToken() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("create Server health token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
