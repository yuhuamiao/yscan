package diff

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestCompareRunWithPreviousSuccessUsesSameTaskBaseline(t *testing.T) {
	db := openDiffTestDB(t)
	task := createDiffTask(t, db, "192.168.10.0/24")
	first := createCompletedDiffRun(t, db, task.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.10", Port: 80, ServiceType: "http"}},
		Vulnerabilities: []model.ScanTaskRunVulnerability{{
			FindingKey: "CVE-2026-0001:http://192.168.10.10",
			TemplateID: "CVE-2026-0001",
			Severity:   "high",
			Target:     "http://192.168.10.10",
		}},
	})
	failed := createCompletedDiffRun(t, db, task.ID, "2026-07-25T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.99", IsActive: true}},
	}, model.ScanTaskRunStatusFailed)
	current := createCompletedDiffRun(t, db, task.ID, "2026-07-26T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}, {IP: "192.168.10.20", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.10", Port: 443, ServiceType: "https"}},
		Vulnerabilities: []model.ScanTaskRunVulnerability{{
			FindingKey: "CVE-2026-0002:https://192.168.10.10",
			TemplateID: "CVE-2026-0002",
			Severity:   "critical",
			Target:     "https://192.168.10.10",
		}},
	})
	if failed.ID == 0 {
		t.Fatal("failed run must be persisted for baseline selection")
	}

	changes, err := CompareRunWithPreviousSuccess(db, current.ID)
	if err != nil {
		t.Fatalf("compare current run: %v", err)
	}
	if changes.BaselineRunID != first.ID || changes.CurrentRunID != current.ID || changes.ScanTaskID != task.ID {
		t.Fatalf("comparison metadata = %#v", changes)
	}
	if want := []string{"192.168.10.20"}; !reflect.DeepEqual(changes.HostChanges.NewHosts, want) {
		t.Fatalf("new hosts = %#v, want %#v", changes.HostChanges.NewHosts, want)
	}
	if want := []model.PortChange{{IP: "192.168.10.10", Port: 443}}; !reflect.DeepEqual(changes.PortChanges.Opened, want) {
		t.Fatalf("opened ports = %#v, want %#v", changes.PortChanges.Opened, want)
	}
	if want := []model.PortChange{{IP: "192.168.10.10", Port: 80}}; !reflect.DeepEqual(changes.PortChanges.Closed, want) {
		t.Fatalf("closed ports = %#v, want %#v", changes.PortChanges.Closed, want)
	}
	if want := []model.VulnerabilityChange{{FindingKey: "CVE-2026-0002:https://192.168.10.10", TemplateID: "CVE-2026-0002", Severity: "critical", Target: "https://192.168.10.10"}}; !reflect.DeepEqual(changes.VulnerabilityChanges.New, want) {
		t.Fatalf("new vulnerabilities = %#v, want %#v", changes.VulnerabilityChanges.New, want)
	}
	if want := []model.VulnerabilityChange{{FindingKey: "CVE-2026-0001:http://192.168.10.10", TemplateID: "CVE-2026-0001", Severity: "high", Target: "http://192.168.10.10"}}; !reflect.DeepEqual(changes.VulnerabilityChanges.Resolved, want) {
		t.Fatalf("resolved vulnerabilities = %#v, want %#v", changes.VulnerabilityChanges.Resolved, want)
	}
	if _, err := CompareRunWithPreviousSuccess(db, failed.ID); !errors.Is(err, ErrScanTaskRunNotSuccessful) {
		t.Fatalf("failed current run comparison error = %v, want ErrScanTaskRunNotSuccessful", err)
	}
}

func TestCompareScanTaskRunsRejectsCrossTaskAndSupportsExplicitRuns(t *testing.T) {
	db := openDiffTestDB(t)
	firstTask := createDiffTask(t, db, "192.168.10.0/24")
	secondTask := createDiffTask(t, db, "192.168.20.0/24")
	firstRun := createCompletedDiffRun(t, db, firstTask.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}},
	})
	secondRun := createCompletedDiffRun(t, db, firstTask.ID, "2026-07-25T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.11", IsActive: true}},
	})
	crossTaskRun := createCompletedDiffRun(t, db, secondTask.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.20.10", IsActive: true}},
	})

	changes, err := CompareScanTaskRuns(db, firstRun.ID, secondRun.ID)
	if err != nil {
		t.Fatalf("compare explicit runs: %v", err)
	}
	if want := []string{"192.168.10.11"}; !reflect.DeepEqual(changes.HostChanges.NewHosts, want) {
		t.Fatalf("explicit new hosts = %#v, want %#v", changes.HostChanges.NewHosts, want)
	}
	if _, err := CompareScanTaskRuns(db, firstRun.ID, crossTaskRun.ID); !errors.Is(err, ErrScanTaskRunMismatch) {
		t.Fatalf("cross-task comparison error = %v, want ErrScanTaskRunMismatch", err)
	}
}

func TestCompareRunSkipsDiffAcrossConfigurationVersions(t *testing.T) {
	db := openDiffTestDB(t)
	task := createDiffTask(t, db, "192.168.10.0/24")
	first := createCompletedDiffRun(t, db, task.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}},
	})
	if _, err := db.Exec(`UPDATE scan_task_runs SET config_hash = 'changed' WHERE id = ?`, first.ID); err != nil {
		t.Fatalf("set baseline config hash: %v", err)
	}
	current := createCompletedDiffRun(t, db, task.ID, "2026-07-25T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.20", IsActive: true}},
	})

	changes, err := CompareRunWithPreviousSuccess(db, current.ID)
	if err != nil {
		t.Fatalf("compare changed config: %v", err)
	}
	if !changes.ConfigChanged || changes.BaselineRunID != first.ID {
		t.Fatalf("config change metadata = %#v", changes)
	}
	if len(changes.HostChanges.NewHosts) != 0 || len(changes.PortChanges.Opened) != 0 || len(changes.VulnerabilityChanges.New) != 0 {
		t.Fatalf("cross-config diff must be empty, got %#v", changes)
	}
}

func openDiffTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("enable foreign keys: %v", err)
	}
	statements := []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL, config_hash TEXT NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY, scan_task_id INTEGER NOT NULL REFERENCES scan_tasks(id), sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL, config_hash TEXT NOT NULL, error_message TEXT, report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
		`CREATE TABLE scan_task_run_hosts (scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id), ip TEXT NOT NULL, is_active INTEGER NOT NULL, PRIMARY KEY(scan_task_run_id, ip))`,
		`CREATE TABLE scan_task_run_ports (scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id), ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, product TEXT, banner TEXT, PRIMARY KEY(scan_task_run_id, ip, port))`,
		`CREATE TABLE scan_task_run_vulnerabilities (scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id), finding_key TEXT NOT NULL, template_id TEXT, name TEXT, severity TEXT, target TEXT NOT NULL, target_ip TEXT, target_port INTEGER, matched_at TEXT, evidence TEXT, PRIMARY KEY(scan_task_run_id, finding_key))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create diff schema: %v", err)
		}
	}
	return db
}

func createDiffTask(t *testing.T, db *sql.DB, target string) model.ScanTask {
	t.Helper()
	task, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   target,
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "Asia/Shanghai",
	})
	if err != nil {
		t.Fatalf("create diff task: %v", err)
	}
	return task
}

func createCompletedDiffRun(t *testing.T, db *sql.DB, taskID int64, scheduledFor string, snapshot model.ScanTaskRunSnapshot, statuses ...string) model.ScanTaskRun {
	t.Helper()
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: taskID, ScheduledFor: scheduledFor})
	if err != nil {
		t.Fatalf("create diff run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, run.ID); err != nil {
		t.Fatalf("start diff run: %v", err)
	}
	snapshot.RunID = run.ID
	if err := storage.SaveScanTaskRunSnapshot(db, snapshot); err != nil {
		t.Fatalf("save diff snapshot: %v", err)
	}
	status := model.ScanTaskRunStatusSuccess
	if len(statuses) > 0 {
		status = statuses[0]
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, status, run.ID); err != nil {
		t.Fatalf("finish diff run: %v", err)
	}
	return run
}
