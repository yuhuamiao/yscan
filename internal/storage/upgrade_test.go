package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	appRuntime "golandproject/yscan/internal/runtime"
)

func TestUpgradeLegacyHomeRecoversEveryPersistedStage(t *testing.T) {
	stages := []string{MigrationPrepared, MigrationCopied, MigrationVerified, MigrationPublished, MigrationCompleted}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			paths := prepareLegacyUpgradeFixture(t, "reports/run.md")
			interrupted := errors.New("simulated process interruption")
			_, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second, AfterStage: func(current string) error {
				if current == stage {
					return interrupted
				}
				return nil
			}})
			if !errors.Is(err, interrupted) {
				t.Fatalf("interruption at %s = %v", stage, err)
			}
			migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, LockTimeout: time.Second})
			if err != nil || !migrated {
				t.Fatalf("resume at %s = %t, %v", stage, migrated, err)
			}
			if _, err := os.Stat(paths.LegacyDatabase); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy database remains: %v", err)
			}
			managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, LockTimeout: time.Second})
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
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths, LockTimeout: time.Second})
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
