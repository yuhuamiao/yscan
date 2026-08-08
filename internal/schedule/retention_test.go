package schedule

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestRetentionPrunesExpiredTerminalRunsAndKeepsBaseline(t *testing.T) {
	db := openExecutorTestDB(t)
	if _, err := db.Exec(`CREATE TABLE host_inventory (ip TEXT PRIMARY KEY, is_active INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create global inventory: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO host_inventory (ip, is_active) VALUES ('192.168.90.10', 1)`); err != nil {
		t.Fatalf("seed global inventory: %v", err)
	}

	directory := t.TempDir()
	oldBaselineTask := createRunnerTask(t, db, "192.168.10.0/24", "2025-12-01 00:00:00")
	historyTask := createRunnerTask(t, db, "192.168.20.0/24", "2025-12-01 00:00:00")
	activeTask := createRunnerTask(t, db, "192.168.30.0/24", "2025-12-01 00:00:00")

	oldBaselineReport := writeRetentionReport(t, directory, "old-baseline.md")
	oldBaseline := createRetentionRun(t, db, oldBaselineTask.ID, "2026-01-01T02:00:00Z", model.ScanTaskRunStatusSuccess, oldBaselineReport, true)

	oldSuccessReport := writeRetentionReport(t, directory, "old-success.md")
	oldSuccess := createRetentionRun(t, db, historyTask.ID, "2026-01-01T02:00:00Z", model.ScanTaskRunStatusSuccess, oldSuccessReport, true)
	oldFailedReport := writeRetentionReport(t, directory, "old-failed.md")
	oldFailed := createRetentionRun(t, db, historyTask.ID, "2026-01-02T02:00:00Z", model.ScanTaskRunStatusFailed, oldFailedReport, false)
	oldCanceledReport := writeRetentionReport(t, directory, "old-canceled.md")
	oldCanceled := createRetentionRun(t, db, historyTask.ID, "2026-01-03T02:00:00Z", model.ScanTaskRunStatusCanceled, oldCanceledReport, false)
	oldSkipped := createRetentionRun(t, db, historyTask.ID, "2026-01-04T02:00:00Z", model.ScanTaskRunStatusSkippedMisfire, "", false)
	freshReport := writeRetentionReport(t, directory, "fresh.md")
	freshSuccess := createRetentionRun(t, db, historyTask.ID, "2026-07-20T02:00:00Z", model.ScanTaskRunStatusSuccess, freshReport, true)

	activeReport := writeRetentionReport(t, directory, "active.md")
	activeRun := createRetentionRun(t, db, activeTask.ID, "2026-01-05T02:00:00Z", model.ScanTaskRunStatusRunning, activeReport, false)

	policy := NewRetentionPolicy(db, ClockFunc(func() time.Time {
		return time.Date(2026, time.July, 24, 0, 0, 0, 0, time.UTC)
	}))
	result, err := policy.Prune(context.Background())
	if err != nil {
		t.Fatalf("prune retention: %v", err)
	}
	if result != (RetentionResult{DeletedRuns: 4, DeletedReports: 6}) {
		t.Fatalf("retention result = %#v", result)
	}

	for _, run := range []model.ScanTaskRun{oldSuccess, oldFailed, oldCanceled, oldSkipped} {
		if _, err := storage.GetScanTaskRun(db, run.ID); !errors.Is(err, storage.ErrScanTaskRunNotFound) {
			t.Fatalf("expired run %d remains, error = %v", run.ID, err)
		}
	}
	for _, run := range []model.ScanTaskRun{oldBaseline, freshSuccess, activeRun} {
		if _, err := storage.GetScanTaskRun(db, run.ID); err != nil {
			t.Fatalf("protected run %d missing: %v", run.ID, err)
		}
	}
	for _, taskID := range []int64{oldBaselineTask.ID, historyTask.ID, activeTask.ID} {
		if _, err := storage.GetScanTask(db, taskID); err != nil {
			t.Fatalf("logical task %d was deleted: %v", taskID, err)
		}
	}
	for _, path := range retentionReportPairs(oldSuccessReport, oldFailedReport, oldCanceledReport) {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired report %s remains, error = %v", path, err)
		}
	}
	for _, path := range retentionReportPairs(oldBaselineReport, freshReport, activeReport) {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("protected report %s missing: %v", path, err)
		}
	}

	for _, table := range []string{"scan_task_run_hosts", "scan_task_run_ports", "scan_task_run_vulnerabilities"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(1) FROM `+table+` WHERE scan_task_run_id = ?`, oldSuccess.ID).Scan(&count); err != nil {
			t.Fatalf("count expired snapshot rows in %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("expired snapshot rows in %s = %d", table, count)
		}
	}
	var inventoryCount int
	if err := db.QueryRow(`SELECT COUNT(1) FROM host_inventory WHERE ip = '192.168.90.10'`).Scan(&inventoryCount); err != nil {
		t.Fatalf("read global inventory: %v", err)
	}
	if inventoryCount != 1 {
		t.Fatalf("global inventory was changed: %d", inventoryCount)
	}
}

func TestExecutorRunsRetentionAfterTerminalState(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.50.0/24", "2025-12-01 00:00:00")
	directory := t.TempDir()
	oldReport := writeRetentionReport(t, directory, "expired.md")
	oldRun := createRetentionRun(t, db, task.ID, "2026-01-01T02:00:00Z", model.ScanTaskRunStatusSuccess, oldReport, true)
	currentRun, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create current run: %v", err)
	}

	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{}, nil
	}))
	executor.Retention = NewRetentionPolicy(db, ClockFunc(func() time.Time {
		return time.Date(2026, time.July, 24, 3, 0, 0, 0, time.UTC)
	}))
	if err := executor.ExecuteRun(context.Background(), currentRun.ID); err != nil {
		t.Fatalf("execute current run: %v", err)
	}
	if _, err := storage.GetScanTaskRun(db, oldRun.ID); !errors.Is(err, storage.ErrScanTaskRunNotFound) {
		t.Fatalf("expired run remains after executor cleanup, error = %v", err)
	}
	if _, err := os.Stat(oldReport); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired report remains after executor cleanup, error = %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, currentRun.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess {
		t.Fatalf("current run = %#v, error = %v", completed, err)
	}
}

func TestExecutorRetentionFailureDoesNotRewriteTerminalState(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.60.0/24", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{}, nil
	}))
	executor.Retention = &RetentionPolicy{DB: db, Clock: ClockFunc(time.Now), MaxAge: 0}
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("retention failure must not fail the completed scan: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess {
		t.Fatalf("completed run = %#v, error = %v", completed, err)
	}
}

func createRetentionRun(t *testing.T, db *sql.DB, taskID int64, scheduledFor, status, reportPath string, writeSnapshot bool) model.ScanTaskRun {
	t.Helper()
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: taskID, ScheduledFor: scheduledFor})
	if err != nil {
		t.Fatalf("create retention run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, run.ID); err != nil {
		t.Fatalf("start retention run: %v", err)
	}
	if writeSnapshot {
		snapshot := model.ScanTaskRunSnapshot{
			RunID:           run.ID,
			Hosts:           []model.ScanTaskRunHost{{IP: "192.168.50.10", IsActive: true}},
			Ports:           []model.ScanTaskRunPort{{IP: "192.168.50.10", Port: 443, ServiceType: "https"}},
			Vulnerabilities: []model.ScanTaskRunVulnerability{{FindingKey: "retention:" + scheduledFor, Target: "https://192.168.50.10"}},
		}
		if err := storage.SaveScanTaskRunSnapshot(db, snapshot); err != nil {
			t.Fatalf("save retention snapshot: %v", err)
		}
	}
	auditReportPath := ""
	if reportPath != "" {
		auditReportPath = reportPath + ".audit"
		if err := os.WriteFile(auditReportPath, []byte("retention audit report\n"), 0600); err != nil {
			t.Fatalf("write retention audit report: %v", err)
		}
	}
	if status == model.ScanTaskRunStatusRunning {
		if _, err := db.Exec(`UPDATE scan_task_runs SET report_path = ?, audit_report_path = ? WHERE id = ?`, reportPath, auditReportPath, run.ID); err != nil {
			t.Fatalf("set active report path: %v", err)
		}
		return run
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, finished_at = ?, report_path = ?, audit_report_path = ? WHERE id = ?`, status, scheduledFor, reportPath, auditReportPath, run.ID); err != nil {
		t.Fatalf("finish retention run: %v", err)
	}
	return run
}

func retentionReportPairs(paths ...string) []string {
	result := make([]string, 0, len(paths)*2)
	for _, path := range paths {
		result = append(result, path, path+".audit")
	}
	return result
}

func writeRetentionReport(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("retention test report\n"), 0600); err != nil {
		t.Fatalf("write retention report: %v", err)
	}
	return path
}
