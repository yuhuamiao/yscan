package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	defaultEnvFile = "# yscan configuration\nYSCAN_LISTEN_ADDR=127.0.0.1:8080\nYSCAN_MAX_CONCURRENCY=2\nYSCAN_SQLITE_BUSY_TIMEOUT=5s\nYSCAN_LOG_MAX_BYTES=10485760\nYSCAN_LOG_MAX_FILES=3\nYSCAN_NUCLEI_BINARY=nuclei\nYSCAN_NUCLEI_TEMPLATES=\nYSCAN_ALLOW_CIDRS=\n"
)

type DatabaseMode string

const (
	DatabaseUninitialized DatabaseMode = "uninitialized"
	DatabaseCurrent       DatabaseMode = "current"
	DatabaseLegacy        DatabaseMode = "legacy"
)

type HomePaths struct {
	Home           string
	Executable     string
	EnvFile        string
	DataDir        string
	Database       string
	LegacyDatabase string
	ReportsDir     string
	LogsDir        string
	RunLogsDir     string
	RunDir         string
	ServerState    string
	MigrationState string
}

type DatabaseSelection struct {
	Mode DatabaseMode
	Path string
}

func ResolveHome(executablePath, override string) (HomePaths, error) {
	if executablePath == "" {
		resolved, err := os.Executable()
		if err != nil {
			return HomePaths{}, fmt.Errorf("resolve executable: %w", err)
		}
		executablePath = resolved
	}

	executablePath, err := canonicalPath(executablePath)
	if err != nil {
		return HomePaths{}, fmt.Errorf("resolve executable path: %w", err)
	}
	home := filepath.Dir(executablePath)
	if override != "" {
		home, err = canonicalPath(override)
		if err != nil {
			return HomePaths{}, fmt.Errorf("resolve yscan home: %w", err)
		}
	}

	paths := HomePaths{
		Home:           home,
		Executable:     executablePath,
		EnvFile:        filepath.Join(home, ".env"),
		DataDir:        filepath.Join(home, "data"),
		Database:       filepath.Join(home, "data", "asm.db"),
		LegacyDatabase: filepath.Join(home, "asm.db"),
		ReportsDir:     filepath.Join(home, "reports"),
		LogsDir:        filepath.Join(home, "logs"),
		RunLogsDir:     filepath.Join(home, "logs", "runs"),
		RunDir:         filepath.Join(home, "run"),
		ServerState:    filepath.Join(home, "run", "server.state"),
		MigrationState: filepath.Join(home, "run", "migration.state"),
	}
	return paths, nil
}

func (paths HomePaths) SelectDatabase() (DatabaseSelection, error) {
	currentExists, err := regularFileExists(paths.Database)
	if err != nil {
		return DatabaseSelection{}, err
	}
	legacyExists, err := regularFileExists(paths.LegacyDatabase)
	if err != nil {
		return DatabaseSelection{}, err
	}
	if currentExists && legacyExists {
		return DatabaseSelection{}, fmt.Errorf("both current and legacy databases exist: %s and %s", paths.Database, paths.LegacyDatabase)
	}
	if currentExists {
		return DatabaseSelection{Mode: DatabaseCurrent, Path: paths.Database}, nil
	}
	if legacyExists {
		return DatabaseSelection{Mode: DatabaseLegacy, Path: paths.LegacyDatabase}, nil
	}
	return DatabaseSelection{Mode: DatabaseUninitialized, Path: paths.Database}, nil
}

func (paths HomePaths) Prepare() error {
	for _, directory := range []string{paths.Home, paths.DataDir, paths.ReportsDir, paths.LogsDir, paths.RunLogsDir, paths.RunDir} {
		if err := os.MkdirAll(directory, 0750); err != nil {
			return fmt.Errorf("create yscan directory %s: %w", directory, err)
		}
	}
	return createDefaultEnvAtomic(paths.EnvFile)
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return filepath.Clean(resolved), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent, err := nearestExistingPath(absolute)
	if err != nil {
		return "", err
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	remainder, err := filepath.Rel(parent, absolute)
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(resolvedParent, remainder)), nil
}

func nearestExistingPath(path string) (string, error) {
	candidate := filepath.Clean(path)
	for {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect %s: %w", candidate, err)
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", fmt.Errorf("no existing parent for %s", path)
		}
		candidate = parent
	}
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("database path is not a regular file: %s", path)
	}
	return true, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func createDefaultEnvAtomic(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".env.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary environment file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(defaultEnvFile); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("initialize %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary environment file: %w", err)
	}
	if err := os.Link(temporaryPath, path); errors.Is(err, os.ErrExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return syncDirectory(filepath.Dir(path))
}
