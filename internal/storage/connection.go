package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	appRuntime "golandproject/yscan/internal/runtime"
)

const (
	CurrentSchemaVersion = 1
	MinimumSchemaVersion = 1
)

var (
	ErrDatabaseUpgradeRequired = errors.New("database upgrade is required")
	ErrDatabaseTooNew          = errors.New("database schema is newer than this yscan binary")
)

type ManagedDatabase struct {
	DB        *sql.DB
	Path      string
	Mode      appRuntime.DatabaseMode
	lifecycle *appRuntime.DatabaseLifecycle
}

type ManagedDatabaseOptions struct {
	Paths             appRuntime.HomePaths
	BusyTimeout       time.Duration
	ServerLockHeld    bool
	LockTimeout       time.Duration
	InitializeContent func(*sql.DB) error
}

func OpenManagedDatabase(options ManagedDatabaseOptions) (*ManagedDatabase, error) {
	if options.LockTimeout <= 0 {
		options.LockTimeout = 2 * time.Minute
	}
	if options.BusyTimeout <= 0 {
		options.BusyTimeout = 5 * time.Second
	}
	for {
		selection, err := options.Paths.SelectDatabase()
		if err != nil {
			return nil, err
		}
		if selection.Mode == appRuntime.DatabaseUninitialized {
			managed, retry, err := initializeManagedDatabase(options)
			if retry {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			return managed, err
		}
		lifecycle, err := appRuntime.AcquireDatabaseShared(options.Paths, options.ServerLockHeld, options.LockTimeout)
		if err != nil {
			return nil, err
		}
		selectionAfterLock, err := options.Paths.SelectDatabase()
		if err != nil {
			_ = lifecycle.Close()
			return nil, err
		}
		if selectionAfterLock != selection {
			_ = lifecycle.Close()
			continue
		}
		managed, err := openLockedDatabase(selection, lifecycle, options.BusyTimeout)
		if err != nil {
			_ = lifecycle.Close()
			return nil, err
		}
		return managed, nil
	}
}

func (managed *ManagedDatabase) Close() error {
	if managed == nil {
		return nil
	}
	var result error
	if managed.DB != nil {
		result = managed.DB.Close()
		managed.DB = nil
	}
	if managed.lifecycle != nil {
		result = errors.Join(result, managed.lifecycle.Close())
		managed.lifecycle = nil
	}
	return result
}

func initializeManagedDatabase(options ManagedDatabaseOptions) (*ManagedDatabase, bool, error) {
	lifecycle, err := appRuntime.AcquireDatabaseExclusive(options.Paths, options.ServerLockHeld, options.LockTimeout)
	if err != nil {
		if errors.Is(err, appRuntime.ErrLockHeld) {
			return nil, true, nil
		}
		return nil, false, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = lifecycle.Close()
		}
	}()
	selection, err := options.Paths.SelectDatabase()
	if err != nil {
		return nil, false, err
	}
	if selection.Mode != appRuntime.DatabaseUninitialized {
		return nil, true, nil
	}
	if err := os.MkdirAll(options.Paths.DataDir, 0750); err != nil {
		return nil, false, err
	}
	temporary, err := os.CreateTemp(options.Paths.DataDir, ".asm.db.init-*")
	if err != nil {
		return nil, false, err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return nil, false, err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return nil, false, err
	}
	defer os.Remove(temporaryPath)

	db, err := InitDBAt(temporaryPath)
	if err != nil {
		return nil, false, err
	}
	closeDB := true
	defer func() {
		if closeDB {
			_ = db.Close()
		}
	}()
	if _, err := db.Exec(`PRAGMA journal_mode = DELETE`); err != nil {
		return nil, false, err
	}
	if err := writeSchemaVersion(db, CurrentSchemaVersion); err != nil {
		return nil, false, err
	}
	if options.InitializeContent != nil {
		if err := options.InitializeContent(db); err != nil {
			return nil, false, err
		}
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return nil, false, fmt.Errorf("new database integrity check failed: %s: %w", integrity, err)
	}
	if err := db.Close(); err != nil {
		return nil, false, err
	}
	closeDB = false
	if err := syncRegularFile(temporaryPath); err != nil {
		return nil, false, err
	}
	if err := os.Rename(temporaryPath, options.Paths.Database); err != nil {
		return nil, false, fmt.Errorf("publish initialized database: %w", err)
	}
	if err := syncStorageDirectory(options.Paths.DataDir); err != nil {
		return nil, false, err
	}
	if err := lifecycle.DowngradeToShared(); err != nil {
		return nil, false, err
	}
	selection = appRuntime.DatabaseSelection{Mode: appRuntime.DatabaseCurrent, Path: options.Paths.Database}
	managed, err := openLockedDatabase(selection, lifecycle, options.BusyTimeout)
	if err != nil {
		return nil, false, err
	}
	cleanup = false
	return managed, false, nil
}

func openLockedDatabase(selection appRuntime.DatabaseSelection, lifecycle *appRuntime.DatabaseLifecycle, busyTimeout time.Duration) (*ManagedDatabase, error) {
	databaseURL := url.URL{Scheme: "file", Path: selection.Path}
	query := databaseURL.Query()
	query.Set("_busy_timeout", fmt.Sprintf("%d", busyTimeout.Milliseconds()))
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "DELETE")
	databaseURL.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", databaseURL.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	version, exists, err := readSchemaVersion(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if !exists {
		if selection.Mode != appRuntime.DatabaseLegacy {
			_ = db.Close()
			return nil, fmt.Errorf("%w: database has no schema_version", ErrDatabaseUpgradeRequired)
		}
	} else if version > CurrentSchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("%w: database=%d binary=%d", ErrDatabaseTooNew, version, CurrentSchemaVersion)
	} else if version < MinimumSchemaVersion || version < CurrentSchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("%w: database=%d binary=%d", ErrDatabaseUpgradeRequired, version, CurrentSchemaVersion)
	}
	return &ManagedDatabase{DB: db, Path: selection.Path, Mode: selection.Mode, lifecycle: lifecycle}, nil
}

func writeSchemaVersion(db *sql.DB, version int) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS yscan_schema (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL,
		updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO yscan_schema (id, version, updated_at) VALUES (1, ?, datetime('now'))
		ON CONFLICT(id) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at`, version)
	return err
}

func readSchemaVersion(db *sql.DB) (int, bool, error) {
	var exists int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'yscan_schema'`).Scan(&exists); err != nil {
		return 0, false, err
	}
	if exists == 0 {
		return 0, false, nil
	}
	var version int
	if err := db.QueryRow(`SELECT version FROM yscan_schema WHERE id = 1`).Scan(&version); err != nil {
		return 0, true, err
	}
	return version, true, nil
}

func syncRegularFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncStorageDirectory(path string) error {
	directory, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
