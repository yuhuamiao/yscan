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

const ServerStateProtocolVersion = 1

type ServerStatus string

const (
	ServerStopped  ServerStatus = "stopped"
	ServerStarting ServerStatus = "starting"
	ServerRunning  ServerStatus = "running"
	ServerDegraded ServerStatus = "degraded"
)

type ServerState struct {
	ProtocolVersion int          `json:"protocol_version"`
	InstanceID      string       `json:"instance_id"`
	PID             int          `json:"pid"`
	Status          ServerStatus `json:"status"`
	ListenAddress   string       `json:"listen_address"`
	MaxConcurrency  int          `json:"max_concurrency"`
	StartedAt       time.Time    `json:"started_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
	Diagnostic      string       `json:"diagnostic,omitempty"`
}

type ServerInspection struct {
	Status ServerStatus
	State  *ServerState
	Error  string
}

type ServerSession struct {
	paths HomePaths
	lock  *FileLock
	mu    sync.Mutex
	state ServerState
}

func AcquireServerSession(paths HomePaths, listenAddress string, maxConcurrency int) (*ServerSession, error) {
	lock, err := TryExclusiveLock(paths.ServerLock)
	if err != nil {
		if errors.Is(err, ErrLockHeld) {
			return nil, fmt.Errorf("yscan Server is already running for home %s: %w", paths.Home, err)
		}
		return nil, err
	}
	instanceID, err := randomInstanceID()
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	now := time.Now().UTC()
	session := &ServerSession{
		paths: paths,
		lock:  lock,
		state: ServerState{
			ProtocolVersion: ServerStateProtocolVersion,
			InstanceID:      instanceID,
			PID:             os.Getpid(),
			Status:          ServerStarting,
			ListenAddress:   listenAddress,
			MaxConcurrency:  maxConcurrency,
			StartedAt:       now,
			UpdatedAt:       now,
		},
	}
	if err := writeServerStateAtomic(paths.ServerState, session.state); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return session, nil
}

func AcquireServerSessionForStartup(paths HomePaths, listenAddress string, maxConcurrency int, timeout time.Duration) (*ServerSession, error) {
	deadline := time.Now().Add(timeout)
	for {
		session, err := AcquireServerSession(paths, listenAddress, maxConcurrency)
		if err == nil {
			return session, nil
		}
		if !errors.Is(err, ErrLockHeld) {
			return nil, err
		}
		if _, stateErr := os.Stat(paths.ServerState); stateErr == nil {
			return nil, err
		} else if !errors.Is(stateErr, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect Server startup state: %w", stateErr)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("wait for database initialization before Server startup: %w", err)
		}
		time.Sleep(databaseLockPollInterval)
	}
}

func (session *ServerSession) MarkRunning() error {
	return session.update(ServerRunning, "")
}

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
	if session.lock == nil {
		return nil
	}
	removeErr := os.Remove(session.paths.ServerState)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	lock := session.lock
	session.lock = nil
	lockErr := lock.Close()
	if removeErr != nil {
		return fmt.Errorf("remove server state: %w", removeErr)
	}
	return lockErr
}

func (session *ServerSession) update(status ServerStatus, diagnostic string) error {
	if session == nil {
		return errors.New("server session is unavailable")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.lock == nil {
		return errors.New("server session is closed")
	}
	session.state.Status = status
	session.state.Diagnostic = diagnostic
	session.state.UpdatedAt = time.Now().UTC()
	return writeServerStateAtomic(session.paths.ServerState, session.state)
}

func InspectServer(paths HomePaths) ServerInspection {
	probe, err := TryExclusiveLock(paths.ServerLock)
	if err == nil {
		_ = probe.Close()
		return ServerInspection{Status: ServerStopped}
	}
	if !errors.Is(err, ErrLockHeld) {
		return ServerInspection{Status: ServerDegraded, Error: err.Error()}
	}
	state, err := ReadServerState(paths.ServerState)
	if err != nil {
		return ServerInspection{Status: ServerDegraded, Error: err.Error()}
	}
	if state.ProtocolVersion != ServerStateProtocolVersion {
		return ServerInspection{Status: ServerDegraded, State: &state, Error: fmt.Sprintf("unsupported server state protocol %d", state.ProtocolVersion)}
	}
	switch state.Status {
	case ServerStarting, ServerRunning, ServerDegraded:
		return ServerInspection{Status: state.Status, State: &state, Error: state.Diagnostic}
	default:
		return ServerInspection{Status: ServerDegraded, State: &state, Error: fmt.Sprintf("invalid server status %q", state.Status)}
	}
}

func ActiveServerConcurrency(paths HomePaths, configured int) (int, bool, error) {
	inspection := InspectServer(paths)
	if inspection.Status == ServerStopped {
		return configured, false, nil
	}
	if inspection.State == nil || inspection.State.MaxConcurrency < 1 || inspection.State.MaxConcurrency > 8 {
		if inspection.Error == "" {
			inspection.Error = "active Server state does not contain a valid concurrency value"
		}
		return 0, false, errors.New(inspection.Error)
	}
	if inspection.State.ProtocolVersion != ServerStateProtocolVersion {
		return 0, false, fmt.Errorf("active Server uses unsupported state protocol %d", inspection.State.ProtocolVersion)
	}
	return inspection.State.MaxConcurrency, inspection.State.MaxConcurrency != configured, nil
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
	if state.InstanceID == "" || state.PID <= 0 {
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

func randomInstanceID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("create Server instance ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
