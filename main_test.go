package main

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/workflow"
)

func TestTaskTypeForScan(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		withVuln bool
		want     string
	}{
		{name: "ip", target: "192.168.1.10", want: model.TaskTypeScanIP},
		{name: "ip with vuln", target: "192.168.1.10", withVuln: true, want: model.TaskTypeScanIPVuln},
		{name: "cidr", target: "192.168.1.0/24", want: model.TaskTypeScanSubnet},
		{name: "cidr with vuln", target: "192.168.1.0/24", withVuln: true, want: model.TaskTypeScanSubnetVuln},
		{name: "ipv6 cidr remains non subnet", target: "2001:db8::/64", want: model.TaskTypeScanIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := taskTypeForScan(tt.target, tt.withVuln); got != tt.want {
				t.Fatalf("taskTypeForScan(%q, %t) = %q, want %q", tt.target, tt.withVuln, got, tt.want)
			}
		})
	}
}

func TestTaskTypeForSubnet(t *testing.T) {
	if got := taskTypeForSubnet(false); got != model.TaskTypeScanSubnet {
		t.Fatalf("taskTypeForSubnet(false) = %q", got)
	}
	if got := taskTypeForSubnet(true); got != model.TaskTypeScanSubnetVuln {
		t.Fatalf("taskTypeForSubnet(true) = %q", got)
	}
}

func TestLogicalScanTaskRunExecutorRoutesIPRuns(t *testing.T) {
	originalTargetRun := runTargetTaskRun
	t.Cleanup(func() { runTargetTaskRun = originalTargetRun })
	runTargetTaskRun = func(_ context.Context, options workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		if options.Run.ID != 42 || options.Network != "tcp" {
			t.Fatalf("target run options = %#v", options)
		}
		return model.ScanTaskRunSnapshot{RunID: options.Run.ID}, nil
	}

	snapshot, err := (logicalScanTaskRunExecutor{baseTask: model.Scanner{Network: "tcp"}}).Execute(context.Background(), model.ScanTaskRun{
		ID:       42,
		ScanType: model.ScanTypeIP,
	})
	if err != nil || snapshot.RunID != 42 {
		t.Fatalf("logical IP executor result = %#v, error = %v", snapshot, err)
	}
}

func TestProcessTaskExecutionGeneratesReportFromFinalSnapshot(t *testing.T) {
	db := openTaskExecutionTestDB(t)
	taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	restoreTaskExecutionDependencies(t)
	executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
		return nil
	}
	var reportTask model.Task
	generateTaskReport = func(db *sql.DB, taskID int64, _ string) (string, error) {
		var err error
		reportTask, err = storage.GetTaskByID(db, taskID)
		return "reports/task-1.md", err
	}

	processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
	if reportTask.Status != model.TaskStatusSuccess || reportTask.FinishedAt == "" {
		t.Fatalf("report read non-final task snapshot: %#v", reportTask)
	}

	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get completed task: %v", err)
	}
	if task.Status != model.TaskStatusSuccess || task.FinishedAt == "" || task.ReportError != "" {
		t.Fatalf("completed task = %#v", task)
	}
}

func TestProcessTaskExecutionKeepsSuccessWhenReportFails(t *testing.T) {
	db := openTaskExecutionTestDB(t)
	taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	restoreTaskExecutionDependencies(t)
	executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
		return nil
	}
	generateTaskReport = func(*sql.DB, int64, string) (string, error) {
		return "", errors.New("report directory is read-only")
	}

	processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get task after report failure: %v", err)
	}
	if task.Status != model.TaskStatusSuccess || task.FinishedAt == "" {
		t.Fatalf("report failure changed scan terminal state: %#v", task)
	}
	if task.ReportError != "report directory is read-only" {
		t.Fatalf("report error = %q", task.ReportError)
	}
}

func TestProcessTaskExecutionReportsFailureAndCancellationSnapshots(t *testing.T) {
	tests := []struct {
		name       string
		cancelTask bool
		wantStatus string
	}{
		{name: "failure", wantStatus: model.TaskStatusFailed},
		{name: "cancellation", cancelTask: true, wantStatus: model.TaskStatusCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTaskExecutionTestDB(t)
			taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
			if err != nil {
				t.Fatalf("create task: %v", err)
			}
			if tt.cancelTask {
				if err := storage.CancelTask(db, taskID); err != nil {
					t.Fatalf("request cancellation: %v", err)
				}
			}

			restoreTaskExecutionDependencies(t)
			executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
				return errors.New("scan execution failed")
			}
			var reportTask model.Task
			generateTaskReport = func(db *sql.DB, taskID int64, _ string) (string, error) {
				var err error
				reportTask, err = storage.GetTaskByID(db, taskID)
				return "reports/task-1.md", err
			}

			processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
			if reportTask.Status != tt.wantStatus || reportTask.FinishedAt == "" {
				t.Fatalf("report task = %#v, want status %q with finished time", reportTask, tt.wantStatus)
			}
		})
	}
}

func TestLogicalScanTaskRunDoesNotReportWhileQueuedForGlobalSlot(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	firstTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.80.10",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create first task: %v", err)
	}
	queued, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: "2026-07-28T00:00:00Z"})
	if err != nil {
		t.Fatalf("create queued run: %v", err)
	}
	secondTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.80.11",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create second task: %v", err)
	}
	active, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: secondTask.ID, ScheduledFor: "2026-07-28T00:01:00Z"})
	if err != nil {
		t.Fatalf("create active run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, started_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusRunning, active.ID); err != nil {
		t.Fatalf("mark active run: %v", err)
	}

	originalGenerate := generateScanTaskRunReport
	t.Cleanup(func() { generateScanTaskRunReport = originalGenerate })
	reportCalls := 0
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) {
		reportCalls++
		return "", nil
	}

	err = executeLogicalScanTaskRun(context.Background(), db, model.Scanner{}, queued)
	if !errors.Is(err, schedule.ErrGlobalConcurrencyUnavailable) {
		t.Fatalf("execute queued run error=%v", err)
	}
	persisted, err := storage.GetScanTaskRun(db, queued.ID)
	if err != nil {
		t.Fatalf("get queued run: %v", err)
	}
	if persisted.Status != model.ScanTaskRunStatusQueued || persisted.ReportPath != "" || persisted.ReportError != "" || reportCalls != 0 {
		t.Fatalf("queued run=%#v reportCalls=%d", persisted, reportCalls)
	}
}

func restoreTaskExecutionDependencies(t *testing.T) {
	t.Helper()
	originalExecute := executeTaskForTaskExecution
	originalGenerate := generateTaskReport
	t.Cleanup(func() {
		executeTaskForTaskExecution = originalExecute
		generateTaskReport = originalGenerate
	})
}

func openTaskExecutionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_type TEXT NOT NULL,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			progress INTEGER NOT NULL DEFAULT 0,
			error_msg TEXT,
			report_error TEXT,
			started_at DATETIME,
			finished_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`); err != nil {
		t.Fatalf("create task schema: %v", err)
	}
	return db
}

func openLogicalScanTaskRunTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create scan task run test schema: %v", err)
		}
	}
	return db
}
