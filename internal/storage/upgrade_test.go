package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	appRuntime "golandproject/yscan/internal/runtime"
)

func TestUpgradeProcessHelper(t *testing.T) {
	mode := os.Getenv("YSCAN_UPGRADE_HELPER")
	if mode == "" {
		return
	}
	paths, err := appRuntime.ResolveHome(os.Args[0], os.Getenv("YSCAN_UPGRADE_HOME"))
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "kill-stage":
		stage := os.Getenv("YSCAN_UPGRADE_STAGE")
		_, err = UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second, AfterStage: func(current string) error {
			if current == stage {
				return syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
	case "hot-journal":
		db, openErr := sql.Open("sqlite3", paths.LegacyDatabase)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, err := db.Exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=1`); err != nil {
			t.Fatal(err)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE migration_probe SET value = 'uncommitted'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO migration_padding(payload) VALUES (randomblob(2097152))`); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(paths.LegacyDatabase + "-journal"); err != nil {
			t.Fatal(err)
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func TestUpgradeLegacyHomeRecoversEveryPersistedStage(t *testing.T) {
	stages := []string{MigrationPrepared, MigrationCopied, MigrationVerified, MigrationPublished, MigrationCompleted}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			paths := prepareLegacyUpgradeFixture(t, "reports/run.md")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUpgradeProcessHelper$")
			command.Env = append(os.Environ(), "YSCAN_UPGRADE_HELPER=kill-stage", "YSCAN_UPGRADE_HOME="+paths.Home, "YSCAN_UPGRADE_STAGE="+stage)
			err := command.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ProcessState.ExitCode() >= 0 {
				t.Fatalf("stage %s helper was not killed: %v", stage, err)
			}
			migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second})
			if err != nil || !migrated {
				t.Fatalf("resume at %s = %t, %v", stage, migrated, err)
			}
			if _, err := os.Stat(paths.LegacyDatabase); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy database remains: %v", err)
			}
			managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
			if err != nil {
				t.Fatal(err)
			}
			var reportPath string
			if err := managed.DB.QueryRow(`SELECT report_path FROM scan_task_runs WHERE id = 1`).Scan(&reportPath); err != nil {
				t.Fatal(err)
			}
			if reportPath != "reports/run.md" {
				t.Fatalf("report path = %q", reportPath)
			}
			_ = managed.Close()
			if pending, err := HomeMigrationPending(paths); err != nil || pending {
				t.Fatalf("migration pending = %t, %v", pending, err)
			}
		})
	}
}

func TestUpgradeLegacyHomeRecoversHotJournalThroughSQLiteBackup(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "")
	db, err := sql.Open("sqlite3", paths.LegacyDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE migration_probe(value TEXT NOT NULL); INSERT INTO migration_probe(value) VALUES ('committed'); CREATE TABLE migration_padding(payload BLOB)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestUpgradeProcessHelper$")
	command.Env = append(os.Environ(), "YSCAN_UPGRADE_HELPER=hot-journal", "YSCAN_UPGRADE_HOME="+paths.Home)
	var exitErr *exec.ExitError
	if err := command.Run(); !errors.As(err, &exitErr) || exitErr.ProcessState.ExitCode() >= 0 {
		t.Fatalf("hot journal helper was not killed: %v", err)
	}
	if _, err := os.Stat(paths.LegacyDatabase + "-journal"); err != nil {
		t.Fatalf("hot journal missing: %v", err)
	}
	if migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second}); err != nil || !migrated {
		t.Fatalf("migrate hot-journal database = %t, %v", migrated, err)
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	var value string
	if err := managed.DB.QueryRow(`SELECT value FROM migration_probe`).Scan(&value); err != nil || value != "committed" {
		t.Fatalf("migrated committed value = %q, %v", value, err)
	}
}

func TestUpgradeLegacyHomeFromExternalDirectoryCopiesReports(t *testing.T) {
	oldPaths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	newHome := t.TempDir()
	newPaths, err := appRuntime.ResolveHome(os.Args[0], newHome)
	if err != nil {
		t.Fatal(err)
	}
	if err := newPaths.Prepare(); err != nil {
		t.Fatal(err)
	}
	if migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: newPaths, SourceHome: oldPaths.Home, LockTimeout: time.Second}); err != nil || !migrated {
		t.Fatalf("external home migration = %t, %v", migrated, err)
	}
	if _, err := os.Stat(filepath.Join(newPaths.ReportsDir, "run.md")); err != nil {
		t.Fatalf("migrated user report: %v", err)
	}
	if _, err := os.Stat(oldPaths.LegacyDatabase); err != nil {
		t.Fatalf("external legacy database must be retained: %v", err)
	}
}

func TestUpgradeLegacyHomeRejectsExplicitMergeIntoInitializedTarget(t *testing.T) {
	oldPaths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	newPaths, err := appRuntime.ResolveHome(os.Args[0], t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := newPaths.Prepare(); err != nil {
		t.Fatal(err)
	}
	current, err := InitDBAt(newPaths.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	if migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: newPaths, SourceHome: oldPaths.Home, LockTimeout: time.Second}); err == nil || migrated || !strings.Contains(err.Error(), "automatic merge") {
		t.Fatalf("explicit merge result = %t, %v", migrated, err)
	}
}

func TestUpgradeLegacyHomeNormalizesAbsoluteReportPath(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "absolute")
	db, err := InitDBAt(paths.LegacyDatabase)
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(paths.ReportsDir, "run.md")
	absoluteAudit := filepath.Join(paths.ReportsDir, "run-audit.md")
	if _, err := db.Exec(`UPDATE scan_task_runs SET report_path = ?, audit_report_path = ? WHERE id = 1`, absolute, absoluteAudit); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	var stored string
	if err := managed.DB.QueryRow(`SELECT report_path FROM scan_task_runs WHERE id = 1`).Scan(&stored); err != nil || stored != "reports/run.md" {
		t.Fatalf("stored path = %q, %v", stored, err)
	}
}

func TestUpgradeLegacyHomeRejectsUnsafeReportPaths(t *testing.T) {
	for _, test := range []struct {
		name string
		path func(appRuntime.HomePaths) string
		prep func(*testing.T, appRuntime.HomePaths)
	}{
		{name: "parent", path: func(appRuntime.HomePaths) string { return "reports/../outside.md" }},
		{name: "outside", path: func(paths appRuntime.HomePaths) string { return filepath.Join(filepath.Dir(paths.Home), "outside.md") }, prep: func(t *testing.T, paths appRuntime.HomePaths) {
			_ = os.WriteFile(filepath.Join(filepath.Dir(paths.Home), "outside.md"), []byte("outside"), 0600)
		}},
		{name: "symlink", path: func(appRuntime.HomePaths) string { return "reports/link.md" }, prep: func(t *testing.T, paths appRuntime.HomePaths) {
			target := filepath.Join(paths.ReportsDir, "target.md")
			if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(paths.ReportsDir, "link.md")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := prepareLegacyUpgradeFixture(t, "")
			if test.prep != nil {
				test.prep(t, paths)
			}
			db, err := InitDBAt(paths.LegacyDatabase)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`UPDATE scan_task_runs SET report_path = ? WHERE id = 1`, test.path(paths)); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second}); err == nil {
				t.Fatal("unsafe report path was accepted")
			}
		})
	}
}

func TestUpgradeLegacyHomeRejectsSymlinkedReportsRoot(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "run.md"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(paths.ReportsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, paths.ReportsDir); err != nil {
		t.Fatal(err)
	}
	if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second}); err == nil || !strings.Contains(err.Error(), "reports directory") {
		t.Fatalf("symlinked reports root error = %v", err)
	}
}

func TestUpgradeLegacyHomeRejectsTwoDatabasesWithoutState(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "")
	current, err := InitDBAt(paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	_ = current.Close()
	if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second}); err == nil || !strings.Contains(err.Error(), "without migration state") {
		t.Fatalf("two database error = %v", err)
	}
}

func prepareLegacyUpgradeFixture(t *testing.T, reportPath string) appRuntime.HomePaths {
	t.Helper()
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
	task, err := CreateScanTask(legacy, model.ScanTask{Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil {
		t.Fatal(err)
	}
	run, err := CreateScanTaskRun(legacy, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: time.Now().UTC().Format(time.RFC3339), Status: model.ScanTaskRunStatusSuccess})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`UPDATE scan_task_runs SET report_path = ? WHERE id = ?`, reportPath, run.ID); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.ReportsDir, "run.md"), []byte("report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.ReportsDir, "run-audit.md"), []byte("audit report"), 0600); err != nil {
		t.Fatal(err)
	}
	return paths
}
