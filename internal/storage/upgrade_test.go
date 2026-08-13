package storage

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	appRuntime "golandproject/yscan/internal/runtime"
)

func TestUpgradeLegacyHomeCreatesReadableBackupAndMigrates(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths})
	if err != nil || !migrated {
		t.Fatalf("migration = %t, %v", migrated, err)
	}
	if _, err := os.Stat(paths.LegacyDatabase); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy database remains: %v", err)
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	var stored string
	if err := managed.DB.QueryRow(`SELECT report_path FROM scan_task_runs WHERE id = 1`).Scan(&stored); err != nil || stored != "reports/run.md" {
		t.Fatalf("report path = %q, %v", stored, err)
	}
	backups, err := filepath.Glob(filepath.Join(paths.DataDir, "backups", "asm-before-upgrade-*.db"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v, %v", backups, err)
	}
	if err := verifySQLiteIntegrity(backups[0]); err != nil {
		t.Fatalf("backup is unreadable: %v", err)
	}
}

func TestUpgradeLegacyHomeFailureLeavesOriginalAndBackup(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	want := errors.New("injected schema content failure")
	migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, InitializeContent: func(*sql.DB) error { return want }})
	if migrated || !errors.Is(err, want) {
		t.Fatalf("migration = %t, %v", migrated, err)
	}
	if err := verifySQLiteIntegrity(paths.LegacyDatabase); err != nil {
		t.Fatalf("original database was damaged: %v", err)
	}
	if _, err := os.Stat(paths.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed target was published: %v", err)
	}
	backups, _ := filepath.Glob(filepath.Join(paths.DataDir, "backups", "asm-before-upgrade-*.db"))
	if len(backups) != 1 || verifySQLiteIntegrity(backups[0]) != nil {
		t.Fatalf("backup is missing or invalid: %v", backups)
	}
}

func TestUpgradeLegacyHomeRejectsInterruptedTemporaryDatabase(t *testing.T) {
	for _, name := range []string{".asm.db.upgrade-interrupted", ".asm.db.original-interrupted"} {
		t.Run(name, func(t *testing.T) {
			paths := prepareLegacyUpgradeFixture(t, "")
			temporary := filepath.Join(paths.DataDir, name)
			if err := os.WriteFile(temporary, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			if pending, err := HomeMigrationPending(paths); err != nil || !pending {
				t.Fatalf("pending=%t err=%v", pending, err)
			}
			if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths}); err == nil || !strings.Contains(err.Error(), temporary) || !strings.Contains(err.Error(), "integrity_check") {
				t.Fatalf("temporary recovery diagnostic = %v", err)
			}
		})
	}
}

func TestUpgradeLegacyHomeFromExternalDirectoryCopiesReports(t *testing.T) {
	oldPaths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	newPaths, err := appRuntime.ResolveHome(os.Args[0], t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := newPaths.Prepare(); err != nil {
		t.Fatal(err)
	}
	if migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: newPaths, SourceHome: oldPaths.Home}); err != nil || !migrated {
		t.Fatalf("external migration = %t, %v", migrated, err)
	}
	if _, err := os.Stat(filepath.Join(newPaths.ReportsDir, "run.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPaths.LegacyDatabase); err != nil {
		t.Fatalf("external source must be retained: %v", err)
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
	_ = current.Close()
	if migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: newPaths, SourceHome: oldPaths.Home}); err == nil || migrated || !strings.Contains(err.Error(), "automatic merge") {
		t.Fatalf("merge = %t, %v", migrated, err)
	}
}

func TestUpgradeCurrentDatabaseCreatesBackupAndAdvancesSchema(t *testing.T) {
	paths := prepareCurrentUpgradeFixture(t)
	if managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths}); !errors.Is(err, ErrDatabaseUpgradeRequired) || managed != nil {
		t.Fatalf("low schema opened before upgrade: managed=%#v err=%v", managed, err)
	}
	migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths})
	if err != nil || !migrated {
		t.Fatalf("current database upgrade=%t err=%v", migrated, err)
	}
	managed, err := OpenManagedDatabase(ManagedDatabaseOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	assertUpgradeMarker(t, managed.DB, "current-before-upgrade")
	version, exists, err := readSchemaVersion(managed.DB)
	if err != nil || !exists || version != CurrentSchemaVersion {
		t.Fatalf("upgraded schema version=%d exists=%t err=%v", version, exists, err)
	}

	backups, err := filepath.Glob(filepath.Join(paths.DataDir, "backups", "asm-before-upgrade-*.db"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("current database backups=%v err=%v", backups, err)
	}
	backup, err := sql.Open("sqlite3", backups[0])
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	assertUpgradeMarker(t, backup, "current-before-upgrade")
	version, exists, err = readSchemaVersion(backup)
	if err != nil || !exists || version != 0 {
		t.Fatalf("backup schema version=%d exists=%t err=%v", version, exists, err)
	}
}

func TestUpgradeCurrentDatabaseFailureKeepsOriginalAndReadableBackup(t *testing.T) {
	paths := prepareCurrentUpgradeFixture(t)
	want := errors.New("injected current schema upgrade failure")
	migrated, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths, InitializeContent: func(*sql.DB) error { return want }})
	if migrated || !errors.Is(err, want) {
		t.Fatalf("current database upgrade=%t err=%v", migrated, err)
	}
	original, err := sql.Open("sqlite3", paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	assertUpgradeMarker(t, original, "current-before-upgrade")
	version, exists, err := readSchemaVersion(original)
	if err != nil || !exists || version != 0 {
		t.Fatalf("failed upgrade changed original version=%d exists=%t err=%v", version, exists, err)
	}
	backups, _ := filepath.Glob(filepath.Join(paths.DataDir, "backups", "asm-before-upgrade-*.db"))
	if len(backups) != 1 || verifySQLiteIntegrity(backups[0]) != nil {
		t.Fatalf("failed current upgrade backup missing or invalid: %v", backups)
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
			_ = os.WriteFile(target, []byte("target"), 0600)
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
			_, err = db.Exec(`UPDATE scan_task_runs SET report_path = ? WHERE id = 1`, test.path(paths))
			_ = db.Close()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths}); err == nil {
				t.Fatal("unsafe report path was accepted")
			}
		})
	}
}

func TestUpgradeLegacyHomeRejectsSymlinkedReportsRoot(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "reports/run.md")
	external := t.TempDir()
	_ = os.WriteFile(filepath.Join(external, "run.md"), []byte("outside"), 0600)
	if err := os.RemoveAll(paths.ReportsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, paths.ReportsDir); err != nil {
		t.Fatal(err)
	}
	if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths}); err == nil || !strings.Contains(err.Error(), "reports directory") {
		t.Fatalf("symlinked root error = %v", err)
	}
}

func TestUpgradeLegacyHomeRejectsTwoDatabases(t *testing.T) {
	paths := prepareLegacyUpgradeFixture(t, "")
	current, err := InitDBAt(paths.Database)
	if err != nil {
		t.Fatal(err)
	}
	_ = current.Close()
	if _, err := UpgradeLegacyHome(HomeUpgradeOptions{Paths: paths}); err == nil || !strings.Contains(err.Error(), "both current and legacy") {
		t.Fatalf("two database error = %v", err)
	}
}

func prepareLegacyUpgradeFixture(t *testing.T, reportPath string) appRuntime.HomePaths {
	t.Helper()
	paths, err := appRuntime.ResolveHome(os.Args[0], t.TempDir())
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
	if err := os.WriteFile(filepath.Join(paths.ReportsDir, "run-audit.md"), []byte("audit"), 0600); err != nil {
		t.Fatal(err)
	}
	return paths
}

func prepareCurrentUpgradeFixture(t *testing.T) appRuntime.HomePaths {
	t.Helper()
	paths, err := appRuntime.ResolveHome(os.Args[0], t.TempDir())
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
	if _, err := managed.DB.Exec(`CREATE TABLE upgrade_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.DB.Exec(`INSERT INTO upgrade_marker (value) VALUES ('current-before-upgrade')`); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.DB.Exec(`UPDATE yscan_schema SET version = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	return paths
}

func assertUpgradeMarker(t *testing.T, db *sql.DB, expected string) {
	t.Helper()
	var actual string
	if err := db.QueryRow(`SELECT value FROM upgrade_marker`).Scan(&actual); err != nil || actual != expected {
		t.Fatalf("upgrade marker=%q err=%v", actual, err)
	}
}
