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
		if readyPath := os.Getenv("YSCAN_DATABASE_SERVER_READY"); readyPath != "" {
			if err := os.WriteFile(readyPath, []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{
		Paths: paths, BusyTimeout: time.Second, ServerLockHeld: serverMode, LockTimeout: 20 * time.Second,
		InitializeContent: func(db *sql.DB) error {
			if delay := os.Getenv("YSCAN_DATABASE_INIT_DELAY"); delay != "" {
				duration, err := time.ParseDuration(delay)
				if err != nil {
					return err
				}
				time.Sleep(duration)
			}
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
	if publishedPath := os.Getenv("YSCAN_DATABASE_PUBLISHED"); publishedPath != "" {
		if err := os.WriteFile(publishedPath, []byte("published"), 0600); err != nil {
			t.Fatal(err)
		}
		releasePath := os.Getenv("YSCAN_DATABASE_RELEASE")
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(releasePath); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("timed out waiting for database helper release")
	}
}

func TestCLIJoinsDatabasePublishedByStartingServer(t *testing.T) {
	home := t.TempDir()
	ready := filepath.Join(home, "server-ready")
	published := filepath.Join(home, "database-published")
	release := filepath.Join(home, "server-release")
	server := exec.Command(os.Args[0], "-test.run=TestManagedDatabaseHelper")
	server.Env = append(os.Environ(),
		"YSCAN_DATABASE_HELPER=1", "YSCAN_DATABASE_HOME="+home, "YSCAN_DATABASE_OWNER=server",
		"YSCAN_DATABASE_SERVER=1", "YSCAN_DATABASE_SERVER_READY="+ready, "YSCAN_DATABASE_INIT_DELAY=500ms",
		"YSCAN_DATABASE_PUBLISHED="+published, "YSCAN_DATABASE_RELEASE="+release)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	waitForStoragePath(t, ready)
	waitForStoragePath(t, published)
	cli := exec.Command(os.Args[0], "-test.run=TestManagedDatabaseHelper")
	cli.Env = append(os.Environ(), "YSCAN_DATABASE_HELPER=1", "YSCAN_DATABASE_HOME="+home, "YSCAN_DATABASE_OWNER=cli")
	if output, err := cli.CombinedOutput(); err != nil {
		t.Fatalf("CLI open failed: %v\n%s", err, output)
	}
	if inspection := appRuntime.InspectServer(mustStoragePaths(t, home)); inspection.Status == appRuntime.ServerStopped {
		t.Fatal("Server exited before CLI joined its published database")
	}
	if err := os.WriteFile(release, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("Server initialization failed: %v", err)
	}
}

func mustStoragePaths(t *testing.T, home string) appRuntime.HomePaths {
	t.Helper()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func waitForStoragePath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
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
