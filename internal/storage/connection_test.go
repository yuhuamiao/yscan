package storage

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appRuntime "golandproject/yscan/internal/runtime"
)

func TestOpenManagedDatabaseInitializesAtomicallyAndRejectsNewerSchema(t *testing.T) {
	home := t.TempDir()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, BusyTimeout: 1379 * time.Millisecond, InitializeContent: func(*sql.DB) error {
		calls.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if managed.Path != paths.Database || managed.Mode != appRuntime.DatabaseCurrent || calls.Load() != 1 {
		t.Fatalf("managed=%#v calls=%d", managed, calls.Load())
	}
	assertPrivateDatabaseMode(t, paths.Database)
	for pragma, want := range map[string]string{"journal_mode": "delete", "foreign_keys": "1", "busy_timeout": "1379"} {
		var got string
		if err := managed.DB.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil || strings.ToLower(got) != want {
			t.Fatalf("PRAGMA %s = %q, %v; want %q", pragma, got, err, want)
		}
	}
	if _, err := managed.DB.Exec(`UPDATE yscan_schema SET version = ? WHERE id = 1`, CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if !errors.Is(err, ErrDatabaseTooNew) {
		t.Fatalf("newer database error = %v", err)
	}
}

func assertPrivateDatabaseMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("database mode = %04o, want 0600: %s", mode, path)
	}
}

func TestManagedDatabaseInitializationFailureDoesNotPublish(t *testing.T) {
	home := t.TempDir()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	want := errors.New("injected initialization failure")
	_, err = OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, InitializeContent: func(db *sql.DB) error {
		if _, err := db.Exec(`CREATE TABLE must_not_publish (id INTEGER)`); err != nil {
			return err
		}
		return want
	}})
	if !errors.Is(err, want) {
		t.Fatalf("initialization error = %v", err)
	}
	if _, err := os.Stat(paths.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed database was published: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(paths.DataDir, ".asm.db.init-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary databases = %v, %v", matches, err)
	}
}

func TestManagedLegacyDatabaseDoesNotCreateCurrentDatabase(t *testing.T) {
	home := t.TempDir()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	legacy, err := InitDBAt(paths.LegacyDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	if managed.Path != paths.LegacyDatabase || managed.Mode != appRuntime.DatabaseLegacy {
		t.Fatalf("managed = %#v", managed)
	}
	if _, err := os.Stat(paths.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy open created current database: %v", err)
	}
}

func TestOpenManagedDatabaseNormalizesExistingDatabasePermissions(t *testing.T) {
	home := t.TempDir()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.Database, 0644); err != nil {
		t.Fatal(err)
	}
	managed, err = OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	assertPrivateDatabaseMode(t, paths.Database)
}
