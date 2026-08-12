package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	appRuntime "golandproject/yscan/internal/runtime"
)

const (
	MigrationPrepared  = "prepared"
	MigrationCopied    = "copied"
	MigrationVerified  = "verified"
	MigrationPublished = "published"
	MigrationCompleted = "completed"
)

type HomeUpgradeOptions struct {
	Paths             appRuntime.HomePaths
	ServerLockHeld    bool
	LockTimeout       time.Duration
	InitializeContent func(*sql.DB) error
	AfterStage        func(string) error
}

type HomeMigrationState struct {
	MigrationID  string `json:"migration_id"`
	SourcePath   string `json:"source_path"`
	WorkingPath  string `json:"working_path"`
	TargetPath   string `json:"target_path"`
	BackupPath   string `json:"backup_path"`
	SourceSHA256 string `json:"source_sha256"`
	TargetSHA256 string `json:"target_sha256,omitempty"`
	Stage        string `json:"stage"`
	UpdatedAt    string `json:"updated_at"`
}

func HomeMigrationPending(paths appRuntime.HomePaths) (bool, error) {
	_, err := os.Lstat(paths.MigrationState)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("inspect migration state: %w", err)
}

func UpgradeLegacyHome(options HomeUpgradeOptions) (bool, error) {
	if options.LockTimeout <= 0 {
		options.LockTimeout = 2 * time.Minute
	}
	pending, err := HomeMigrationPending(options.Paths)
	if err != nil {
		return false, err
	}
	if !pending {
		current, currentErr := regularDatabaseFile(options.Paths.Database)
		legacy, legacyErr := regularDatabaseFile(options.Paths.LegacyDatabase)
		if currentErr != nil || legacyErr != nil {
			return false, errors.Join(currentErr, legacyErr)
		}
		if current && legacy {
			return false, fmt.Errorf("both current and legacy databases exist without migration state: %s and %s", options.Paths.Database, options.Paths.LegacyDatabase)
		}
		if current || !legacy {
			return false, nil
		}
	}

	lifecycle, err := appRuntime.AcquireDatabaseExclusive(options.Paths, options.ServerLockHeld, options.LockTimeout)
	if err != nil {
		return false, err
	}
	defer lifecycle.Close()

	state, created, err := loadOrCreateMigrationState(options.Paths)
	if err != nil {
		return false, err
	}
	if created && options.AfterStage != nil {
		if err := options.AfterStage(MigrationPrepared); err != nil {
			return false, err
		}
	}
	for {
		switch state.Stage {
		case MigrationPrepared:
			if err := verifyFileSHA(state.SourcePath, state.SourceSHA256); err != nil {
				return false, err
			}
			if err := copyFileSynced(state.SourcePath, state.BackupPath, 0600); err != nil {
				return false, err
			}
			if err := copyFileSynced(state.SourcePath, state.WorkingPath, 0600); err != nil {
				return false, err
			}
			if err := advanceMigration(options, &state, MigrationCopied); err != nil {
				return false, err
			}
		case MigrationCopied:
			if err := verifyFileSHA(state.BackupPath, state.SourceSHA256); err != nil {
				return false, fmt.Errorf("verify migration backup: %w", err)
			}
			// Recreate the working copy on every replay. A process can die after
			// SQLite modified it but before the verified stage was persisted.
			if err := copyFileSynced(state.BackupPath, state.WorkingPath, 0600); err != nil {
				return false, fmt.Errorf("restore migration working copy: %w", err)
			}
			if err := upgradeWorkingDatabase(options, state.WorkingPath); err != nil {
				return false, err
			}
			state.TargetSHA256, err = fileSHA256(state.WorkingPath)
			if err != nil {
				return false, err
			}
			if err := advanceMigration(options, &state, MigrationVerified); err != nil {
				return false, err
			}
		case MigrationVerified:
			if targetExists, err := regularDatabaseFile(state.TargetPath); err != nil {
				return false, err
			} else if targetExists {
				if err := verifyFileSHA(state.TargetPath, state.TargetSHA256); err != nil {
					return false, fmt.Errorf("published database does not match migration state: %w", err)
				}
			} else {
				if err := verifyFileSHA(state.WorkingPath, state.TargetSHA256); err != nil {
					return false, err
				}
				if err := os.Rename(state.WorkingPath, state.TargetPath); err != nil {
					return false, fmt.Errorf("publish migrated database: %w", err)
				}
				if err := syncStorageDirectory(filepath.Dir(state.TargetPath)); err != nil {
					return false, err
				}
			}
			if err := advanceMigration(options, &state, MigrationPublished); err != nil {
				return false, err
			}
		case MigrationPublished:
			if err := verifyFileSHA(state.TargetPath, state.TargetSHA256); err != nil {
				return false, err
			}
			if err := verifyFileSHA(state.BackupPath, state.SourceSHA256); err != nil {
				return false, err
			}
			if err := os.Remove(state.SourcePath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("retire legacy database: %w", err)
			}
			if err := syncStorageDirectory(filepath.Dir(state.SourcePath)); err != nil {
				return false, err
			}
			if err := advanceMigration(options, &state, MigrationCompleted); err != nil {
				return false, err
			}
		case MigrationCompleted:
			if err := verifyFileSHA(state.TargetPath, state.TargetSHA256); err != nil {
				return false, err
			}
			if err := os.Remove(options.Paths.MigrationState); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
			if err := syncStorageDirectory(options.Paths.RunDir); err != nil {
				return false, err
			}
			return true, nil
		default:
			return false, fmt.Errorf("invalid migration stage %q", state.Stage)
		}
	}
}

func loadOrCreateMigrationState(paths appRuntime.HomePaths) (HomeMigrationState, bool, error) {
	content, err := os.ReadFile(paths.MigrationState)
	if err == nil {
		var state HomeMigrationState
		if err := json.Unmarshal(content, &state); err != nil {
			return HomeMigrationState{}, false, fmt.Errorf("decode migration state: %w", err)
		}
		if state.SourcePath != paths.LegacyDatabase || state.TargetPath != paths.Database || state.MigrationID == "" {
			return HomeMigrationState{}, false, errors.New("migration state does not match this yscan home")
		}
		return state, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return HomeMigrationState{}, false, err
	}
	if current, err := regularDatabaseFile(paths.Database); err != nil {
		return HomeMigrationState{}, false, err
	} else if current {
		return HomeMigrationState{}, false, errors.New("current and legacy databases coexist without migration state")
	}
	if legacy, err := regularDatabaseFile(paths.LegacyDatabase); err != nil {
		return HomeMigrationState{}, false, err
	} else if !legacy {
		return HomeMigrationState{}, false, errors.New("legacy database is unavailable for migration")
	}
	sourceSHA, err := fileSHA256(paths.LegacyDatabase)
	if err != nil {
		return HomeMigrationState{}, false, err
	}
	migrationID := fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), os.Getpid())
	backupDir := filepath.Join(paths.DataDir, "backups")
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return HomeMigrationState{}, false, err
	}
	state := HomeMigrationState{
		MigrationID: migrationID, SourcePath: paths.LegacyDatabase,
		WorkingPath: filepath.Join(paths.DataDir, ".asm.db.migration-"+migrationID), TargetPath: paths.Database,
		BackupPath:   filepath.Join(backupDir, "asm-before-schema-1-"+migrationID+".db"),
		SourceSHA256: sourceSHA, Stage: MigrationPrepared, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeMigrationState(paths.MigrationState, state); err != nil {
		return HomeMigrationState{}, false, err
	}
	return state, true, nil
}

func advanceMigration(options HomeUpgradeOptions, state *HomeMigrationState, stage string) error {
	state.Stage = stage
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeMigrationState(options.Paths.MigrationState, *state); err != nil {
		return err
	}
	if options.AfterStage != nil {
		return options.AfterStage(stage)
	}
	return nil
}

func writeMigrationState(path string, state HomeMigrationState) error {
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".migration.state.tmp-*")
	if err != nil {
		return err
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
		return err
	}
	return syncStorageDirectory(filepath.Dir(path))
}

func upgradeWorkingDatabase(options HomeUpgradeOptions, path string) error {
	db, err := InitDBAt(path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := migrateStoredReportPaths(db, options.Paths); err != nil {
		return err
	}
	if err := writeSchemaVersion(db, CurrentSchemaVersion); err != nil {
		return err
	}
	if options.InitializeContent != nil {
		if err := options.InitializeContent(db); err != nil {
			return err
		}
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("migrated database integrity check failed: %s: %w", integrity, err)
	}
	if err := db.Close(); err != nil {
		return err
	}
	return syncRegularFile(path)
}

func migrateStoredReportPaths(db *sql.DB, paths appRuntime.HomePaths) error {
	targets := []struct{ table, id, column string }{
		{"scan_task_runs", "id", "report_path"},
		{"scan_task_runs", "id", "audit_report_path"},
	}
	available := make([]struct{ table, id, column string }, 0, len(targets))
	for _, target := range targets {
		exists, err := sqliteTableHasColumn(db, target.table, target.column)
		if err != nil {
			return err
		}
		if exists {
			available = append(available, target)
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, target := range available {
		query := fmt.Sprintf(`SELECT %s, %s FROM %s WHERE COALESCE(%s, '') <> ''`, target.id, target.column, target.table, target.column)
		rows, err := tx.Query(query)
		if err != nil {
			return err
		}
		var updates [][2]interface{}
		for rows.Next() {
			var id int64
			var stored string
			if err := rows.Scan(&id, &stored); err != nil {
				_ = rows.Close()
				return err
			}
			relative, err := normalizeLegacyArtifactPath(paths, stored)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("%s.%s row %d: %w", target.table, target.column, id, err)
			}
			updates = append(updates, [2]interface{}{relative, id})
		}
		if err := rows.Close(); err != nil {
			return err
		}
		statement := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, target.table, target.column, target.id)
		for _, update := range updates {
			if _, err := tx.Exec(statement, update[0], update[1]); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func normalizeLegacyArtifactPath(paths appRuntime.HomePaths, stored string) (string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", errors.New("artifact path is empty")
	}
	if hasParentTraversal(stored) {
		return "", errors.New("artifact path contains parent traversal")
	}
	absolute := stored
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(paths.Home, filepath.FromSlash(stored))
	}
	absolute = filepath.Clean(absolute)
	reportsRoot := filepath.Clean(paths.ReportsDir)
	relativeToReports, err := filepath.Rel(reportsRoot, absolute)
	if err != nil || relativeToReports == "." || relativeToReports == ".." || strings.HasPrefix(relativeToReports, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path is outside %s", reportsRoot)
	}
	if err := rejectSymlinkComponents(reportsRoot, relativeToReports); err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect artifact %s: %w", absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("artifact is not a regular file: %s", absolute)
	}
	relativeToHome, err := filepath.Rel(paths.Home, absolute)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(relativeToHome), nil
}

func hasParentTraversal(path string) bool {
	for _, part := range strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool { return r == '/' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

func rejectSymlinkComponents(root, relative string) error {
	candidate := root
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		candidate = filepath.Join(candidate, component)
		info, err := os.Lstat(candidate)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact path contains symbolic link: %s", candidate)
		}
	}
	return nil
}

func copyFileSynced(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".copy-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, input); err != nil {
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
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	return syncStorageDirectory(filepath.Dir(target))
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyFileSHA(path, expected string) error {
	actual, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("SHA-256 mismatch for %s: got %s want %s", path, actual, expected)
	}
	return nil
}

func regularDatabaseFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("database is not a regular file: %s", path)
	}
	return true, nil
}
