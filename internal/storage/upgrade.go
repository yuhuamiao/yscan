package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"

	appRuntime "golandproject/yscan/internal/runtime"
)

type HomeUpgradeOptions struct {
	Paths             appRuntime.HomePaths
	SourceHome        string
	InitializeContent func(*sql.DB) error
}

func HomeMigrationPending(paths appRuntime.HomePaths) (bool, error) {
	for _, pattern := range []string{".asm.db.upgrade-*", ".asm.db.original-*"} {
		matches, err := filepath.Glob(filepath.Join(paths.DataDir, pattern))
		if err != nil {
			return false, err
		}
		if len(matches) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// UpgradeLegacyHome performs an offline migration. It never coordinates with
// active CLI processes: callers must stop the Server and wait for CLI scans.
func UpgradeLegacyHome(options HomeUpgradeOptions) (bool, error) {
	if inspection := appRuntime.InspectServerHealth(options.Paths); inspection.Status != appRuntime.ServerStopped {
		return false, fmt.Errorf("stop the yscan Server before offline upgrade (status: %s)", inspection.Status)
	}
	if err := rejectUpgradeTemporaryFiles(options.Paths); err != nil {
		return false, err
	}
	sourceHome, sourcePath, err := resolveUpgradeSource(options.Paths, options.SourceHome)
	if err != nil {
		return false, err
	}
	current, err := regularDatabaseFile(options.Paths.Database)
	if err != nil {
		return false, err
	}
	sourceExists, err := regularDatabaseFile(sourcePath)
	if err != nil {
		return false, err
	}
	explicitSource := strings.TrimSpace(options.SourceHome) != ""
	if explicitSource && current {
		return false, fmt.Errorf("target yscan home already contains a database at %s; automatic merge from %s is not supported", options.Paths.Database, sourceHome)
	}
	replacingCurrent := false
	if !explicitSource && current {
		if sourceExists && filepath.Clean(sourcePath) != filepath.Clean(options.Paths.Database) {
			return false, fmt.Errorf("both current and legacy databases exist: %s and %s; move one aside after making a backup", options.Paths.Database, sourcePath)
		}
		version, exists, err := databaseSchemaVersion(options.Paths.Database)
		if err != nil {
			return false, fmt.Errorf("inspect current database schema: %w", err)
		}
		if exists && version > CurrentSchemaVersion {
			return false, fmt.Errorf("%w: database=%d binary=%d", ErrDatabaseTooNew, version, CurrentSchemaVersion)
		}
		if exists && version == CurrentSchemaVersion {
			if err := os.Chmod(options.Paths.Database, 0600); err != nil {
				return false, fmt.Errorf("secure current database permissions: %w", err)
			}
			return false, nil
		}
		sourceHome = options.Paths.Home
		sourcePath = options.Paths.Database
		sourceExists = true
		replacingCurrent = true
	}
	if !sourceExists {
		if explicitSource {
			return false, fmt.Errorf("legacy database not found: %s", sourcePath)
		}
		return false, nil
	}
	if err := os.MkdirAll(options.Paths.DataDir, 0750); err != nil {
		return false, err
	}
	identifier := fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), os.Getpid())
	backupDir := filepath.Join(options.Paths.DataDir, "backups")
	backupPath := filepath.Join(backupDir, "asm-before-upgrade-"+identifier+".db")
	workingPath := filepath.Join(options.Paths.DataDir, ".asm.db.upgrade-"+identifier)
	if err := backupSQLiteDatabase(sourcePath, backupPath); err != nil {
		return false, fmt.Errorf("create pre-upgrade backup: %w", err)
	}
	if err := verifySQLiteIntegrity(backupPath); err != nil {
		return false, fmt.Errorf("verify pre-upgrade backup: %w", err)
	}
	if err := copyFileSynced(backupPath, workingPath, 0600); err != nil {
		return false, fmt.Errorf("create upgrade working database: %w", err)
	}
	keepWorking := true
	defer func() {
		if !keepWorking {
			_ = os.Remove(workingPath)
		}
	}()
	workingOptions := options
	workingOptions.SourceHome = sourceHome
	if err := upgradeWorkingDatabase(workingOptions, workingPath); err != nil {
		keepWorking = false
		return false, fmt.Errorf("upgrade working database: %w (original database remains usable; backup: %s)", err, backupPath)
	}
	if err := verifySQLiteIntegrity(workingPath); err != nil {
		keepWorking = false
		return false, fmt.Errorf("verify upgraded database: %w", err)
	}
	if err := publishOfflineDatabase(workingPath, options.Paths.Database, replacingCurrent, identifier); err != nil {
		return false, fmt.Errorf("publish upgraded database: %w; working file: %s; backup: %s", err, workingPath, backupPath)
	}
	keepWorking = false
	if sameFilePath(sourcePath, options.Paths.LegacyDatabase) {
		if err := os.Remove(sourcePath); err != nil {
			_ = os.Remove(options.Paths.Database)
			return false, fmt.Errorf("retire legacy root database: %w; original remains at %s and backup at %s", err, sourcePath, backupPath)
		}
		if err := syncStorageDirectory(filepath.Dir(sourcePath)); err != nil {
			return false, err
		}
	}
	return true, nil
}

func rejectUpgradeTemporaryFiles(paths appRuntime.HomePaths) error {
	for _, pattern := range []string{".asm.db.upgrade-*", ".asm.db.original-*"} {
		matches, err := filepath.Glob(filepath.Join(paths.DataDir, pattern))
		if err != nil {
			return err
		}
		if len(matches) > 0 {
			return fmt.Errorf("an interrupted offline upgrade left temporary database %s; keep data/backups, inspect the temporary database with PRAGMA integrity_check, then either restore it manually or remove it before retrying", matches[0])
		}
	}
	return nil
}

func databaseSchemaVersion(path string) (int, bool, error) {
	databaseURL := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite3", databaseURL.String()+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return 0, false, err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return 0, false, err
	}
	return readSchemaVersion(db)
}

func publishOfflineDatabase(workingPath, targetPath string, replacingCurrent bool, identifier string) error {
	if !replacingCurrent {
		if err := os.Rename(workingPath, targetPath); err != nil {
			return err
		}
		return syncStorageDirectory(filepath.Dir(targetPath))
	}
	retiredPath := filepath.Join(filepath.Dir(targetPath), ".asm.db.original-"+identifier)
	if err := os.Rename(targetPath, retiredPath); err != nil {
		return fmt.Errorf("retain current database before publish: %w", err)
	}
	restore := func(cause error) error {
		_ = os.Remove(targetPath)
		if err := os.Rename(retiredPath, targetPath); err != nil {
			return fmt.Errorf("%v; restore current database from %s: %w", cause, retiredPath, err)
		}
		_ = syncStorageDirectory(filepath.Dir(targetPath))
		return cause
	}
	if err := os.Rename(workingPath, targetPath); err != nil {
		return restore(err)
	}
	if err := syncStorageDirectory(filepath.Dir(targetPath)); err != nil {
		return restore(err)
	}
	if err := os.Remove(retiredPath); err != nil {
		return restore(fmt.Errorf("retire replaced database %s: %w", retiredPath, err))
	}
	return nil
}

func sameFilePath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(leftAbsolute) == filepath.Clean(rightAbsolute)
}

func resolveUpgradeSource(paths appRuntime.HomePaths, sourceHome string) (string, string, error) {
	if strings.TrimSpace(sourceHome) == "" {
		return paths.Home, paths.LegacyDatabase, nil
	}
	absolute, err := filepath.Abs(sourceHome)
	if err != nil {
		return "", "", err
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", "", fmt.Errorf("inspect legacy home %s: %w", absolute, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("legacy home is not a regular directory: %s", absolute)
	}
	return absolute, filepath.Join(absolute, "asm.db"), nil
}

func upgradeWorkingDatabase(options HomeUpgradeOptions, path string) error {
	db, err := InitDBAt(path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := migrateStoredReportPaths(db, options.Paths, options.SourceHome); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS yscan_schema (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL,
		updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO yscan_schema (id, version, updated_at) VALUES (1, ?, datetime('now'))
		ON CONFLICT(id) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at`, CurrentSchemaVersion); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if options.InitializeContent != nil {
		if err := options.InitializeContent(db); err != nil {
			return err
		}
	}
	if err := db.Close(); err != nil {
		return err
	}
	return syncRegularFile(path)
}

func verifySQLiteIntegrity(path string) error {
	databaseURL := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite3", databaseURL.String()+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("integrity_check returned %q", integrity)
	}
	return nil
}

func migrateStoredReportPaths(db *sql.DB, paths appRuntime.HomePaths, sourceHomeOption string) error {
	sourceHome, _, err := resolveUpgradeSource(paths, sourceHomeOption)
	if err != nil {
		return err
	}
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
			relative, source, err := normalizeLegacyArtifactPath(sourceHome, stored)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("%s.%s row %d: %w", target.table, target.column, id, err)
			}
			targetPath := filepath.Join(paths.Home, filepath.FromSlash(relative))
			if filepath.Clean(source) != filepath.Clean(targetPath) {
				if err := copyLegacyArtifact(source, targetPath); err != nil {
					_ = rows.Close()
					return fmt.Errorf("%s.%s row %d: %w", target.table, target.column, id, err)
				}
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

func normalizeLegacyArtifactPath(sourceHome, stored string) (string, string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", "", errors.New("artifact path is empty")
	}
	if hasParentTraversal(stored) {
		return "", "", errors.New("artifact path contains parent traversal")
	}
	absolute := stored
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(sourceHome, filepath.FromSlash(stored))
	}
	absolute = filepath.Clean(absolute)
	reportsRoot := filepath.Join(filepath.Clean(sourceHome), "reports")
	rootInfo, err := os.Lstat(reportsRoot)
	if err != nil {
		return "", "", fmt.Errorf("inspect legacy reports directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("legacy reports directory is not a regular directory: %s", reportsRoot)
	}
	relativeToReports, err := filepath.Rel(reportsRoot, absolute)
	if err != nil || relativeToReports == "." || relativeToReports == ".." || strings.HasPrefix(relativeToReports, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("artifact path is outside %s", reportsRoot)
	}
	if err := rejectSymlinkComponents(reportsRoot, relativeToReports); err != nil {
		return "", "", err
	}
	realRoot, err := filepath.EvalSymlinks(reportsRoot)
	if err != nil {
		return "", "", err
	}
	realArtifact, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", "", err
	}
	realRelative, err := filepath.Rel(realRoot, realArtifact)
	if err != nil || realRelative == "." || realRelative == ".." || strings.HasPrefix(realRelative, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("resolved artifact path is outside %s", realRoot)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", "", fmt.Errorf("inspect artifact %s: %w", absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("artifact is not a regular file: %s", absolute)
	}
	return filepath.ToSlash(filepath.Join("reports", relativeToReports)), absolute, nil
}

func copyLegacyArtifact(source, target string) error {
	if exists, err := regularDatabaseFile(target); err != nil {
		return err
	} else if exists {
		sourceSHA, err := fileSHA256(source)
		if err != nil {
			return err
		}
		return verifyFileSHA(target, sourceSHA)
	}
	return copyFileSynced(source, target, 0600)
}

func backupSQLiteDatabase(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".sqlite-backup-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)

	sourceURL := url.URL{Scheme: "file", Path: source}
	sourceDB, err := sql.Open("sqlite3", sourceURL.String()+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return err
	}
	defer sourceDB.Close()
	destinationURL := url.URL{Scheme: "file", Path: temporaryPath}
	destinationDB, err := sql.Open("sqlite3", destinationURL.String()+"?_busy_timeout=5000")
	if err != nil {
		return err
	}
	defer destinationDB.Close()
	sourceConn, err := sourceDB.Conn(context.Background())
	if err != nil {
		return err
	}
	defer sourceConn.Close()
	destinationConn, err := destinationDB.Conn(context.Background())
	if err != nil {
		return err
	}
	defer destinationConn.Close()
	err = destinationConn.Raw(func(destinationDriver interface{}) error {
		return sourceConn.Raw(func(sourceDriver interface{}) error {
			destinationSQLite, ok := destinationDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("unexpected SQLite destination connection")
			}
			sourceSQLite, ok := sourceDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("unexpected SQLite source connection")
			}
			backup, err := destinationSQLite.Backup("main", sourceSQLite, "main")
			if err != nil {
				return err
			}
			for {
				done, stepErr := backup.Step(256)
				if stepErr != nil {
					_ = backup.Finish()
					return stepErr
				}
				if done {
					break
				}
				time.Sleep(time.Millisecond)
			}
			return backup.Finish()
		})
	})
	if err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := destinationConn.Close(); err != nil {
		return err
	}
	if err := destinationDB.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0600); err != nil {
		return fmt.Errorf("secure SQLite backup: %w", err)
	}
	if err := syncRegularFile(temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	return syncStorageDirectory(filepath.Dir(target))
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
