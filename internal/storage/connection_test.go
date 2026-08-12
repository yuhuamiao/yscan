package storage

import (
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	appRuntime "golandproject/yscan/internal/runtime"
)

func TestManagedDatabaseHelper(t *testing.T) {
	if os.Getenv("YSCAN_DATABASE_HELPER") != "1" {
		return
	}
	home := os.Getenv("YSCAN_DATABASE_HOME")
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	serverMode := os.Getenv("YSCAN_DATABASE_SERVER") == "1"
	var session *appRuntime.ServerSession
	if serverMode {
		session, err = appRuntime.AcquireServerSessionForStartup(paths, "127.0.0.1:0", 2, 20*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{
		Paths: paths, BusyTimeout: time.Second, ServerLockHeld: serverMode, LockTimeout: 20 * time.Second,
		InitializeContent: func(db *sql.DB) error {
			_, err := db.Exec(`CREATE TABLE initialization_marker (owner TEXT NOT NULL)`)
			if err == nil {
				_, err = db.Exec(`INSERT INTO initialization_marker (owner) VALUES (?)`, os.Getenv("YSCAN_DATABASE_OWNER"))
			}
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	var count int
	if err := managed.DB.QueryRow(`SELECT COUNT(*) FROM initialization_marker`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("marker count=%d error=%v", count, err)
	}
}

func TestConcurrentFirstInitializationPublishesOneDatabase(t *testing.T) {
	for _, serverSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "CLI_CLI", true: "CLI_Server"}[serverSecond], func(t *testing.T) {
			home := t.TempDir()
			commands := make([]*exec.Cmd, 2)
			for index := range commands {
				command := exec.Command(os.Args[0], "-test.run=TestManagedDatabaseHelper")
				command.Env = append(os.Environ(), "YSCAN_DATABASE_HELPER=1", "YSCAN_DATABASE_HOME="+home, "YSCAN_DATABASE_OWNER=process")
				if index == 1 && serverSecond {
					command.Env = append(command.Env, "YSCAN_DATABASE_SERVER=1")
				}
				commands[index] = command
			}
			results := make(chan error, 2)
			for _, command := range commands {
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				go func(command *exec.Cmd) { results <- command.Wait() }(command)
			}
			for range commands {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			paths, err := appRuntime.ResolveHome(os.Args[0], home)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(paths.Database); err != nil {
				t.Fatal(err)
			}
			matches, err := filepath.Glob(filepath.Join(paths.DataDir, ".asm.db.init-*"))
			if err != nil || len(matches) != 0 {
				t.Fatalf("temporary databases = %v, %v", matches, err)
			}
		})
	}
}

func TestOpenManagedDatabaseInitializesOnceAndRejectsNewerSchema(t *testing.T) {
	home := t.TempDir()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, LockTimeout: time.Second, InitializeContent: func(*sql.DB) error {
		calls.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if managed.Path != paths.Database || managed.Mode != appRuntime.DatabaseCurrent || calls.Load() != 1 {
		t.Fatalf("managed=%#v calls=%d", managed, calls.Load())
	}
	var journalMode string
	if err := managed.DB.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil || journalMode != "delete" {
		t.Fatalf("journal mode = %q, %v", journalMode, err)
	}
	if _, err := appRuntime.AcquireDatabaseExclusive(paths, false, 100*time.Millisecond); err == nil {
		t.Fatal("exclusive database lifecycle lock succeeded while managed database was open")
	}
	if _, err := managed.DB.Exec(`UPDATE yscan_schema SET version = ? WHERE id = 1`, CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, LockTimeout: time.Second})
	if !errors.Is(err, ErrDatabaseTooNew) {
		t.Fatalf("newer database error = %v", err)
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
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, LockTimeout: time.Second})
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
