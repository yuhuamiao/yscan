package schedule

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestExecutorPersistsSnapshotAndSuccessfulRun(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(_ context.Context, received model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		if received.ID != run.ID || received.Status != model.ScanTaskRunStatusRunning {
			t.Fatalf("received run = %#v", received)
		}
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}}}, nil
	}))

	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("execute run: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil {
		t.Fatalf("get completed run: %v", err)
	}
	if completed.Status != model.ScanTaskRunStatusSuccess || completed.StartedAt == "" || completed.FinishedAt == "" || completed.SnapshotWrittenAt == "" {
		t.Fatalf("completed run = %#v", completed)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, run.ID)
	if err != nil || len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != "192.168.10.10" {
		t.Fatalf("stored snapshot = %#v, error = %v", snapshot, err)
	}
}

func TestExecutorRejectsLegacyPublicTargetBeforeNetworkWork(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "8.8.8.8", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	executed := false
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		executed = true
		return model.ScanTaskRunSnapshot{}, nil
	}))
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("reject public run: %v", err)
	}
	failed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || executed || failed.Status != model.ScanTaskRunStatusFailed || !strings.Contains(failed.ErrorMessage, "internal IPv4") {
		t.Fatalf("failed=%#v executed=%v err=%v", failed, executed, err)
	}
}

func TestExecutorFailureDoesNotBlockLaterRun(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	first, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create first run: %v", err)
	}
	second, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-25T02:00:00Z"})
	if err != nil {
		t.Fatalf("create second run: %v", err)
	}
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(_ context.Context, run model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		if run.ID == first.ID {
			return model.ScanTaskRunSnapshot{}, errors.New("target unavailable")
		}
		return model.ScanTaskRunSnapshot{}, nil
	}))

	if err := executor.ExecuteRun(context.Background(), first.ID); err != nil {
		t.Fatalf("failed execution must be contained: %v", err)
	}
	failed, err := storage.GetScanTaskRun(db, first.ID)
	if err != nil || failed.Status != model.ScanTaskRunStatusFailed || failed.ErrorMessage != "target unavailable" {
		t.Fatalf("failed run = %#v, error = %v", failed, err)
	}
	if err := executor.ExecuteRun(context.Background(), second.ID); err != nil {
		t.Fatalf("later execution: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, second.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess {
		t.Fatalf("later run = %#v, error = %v", completed, err)
	}
}

func TestExecutorCancellationRequestWinsBeforeTerminalUpdate(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(_ context.Context, received model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusCancelRequested, received.ID); err != nil {
			t.Fatalf("request cancellation: %v", err)
		}
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.8", IsActive: true}}}, nil
	}))

	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("execute canceled run: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusCanceled {
		t.Fatalf("canceled run = %#v, error = %v", completed, err)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, run.ID)
	if err != nil || len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != "192.168.10.8" {
		t.Fatalf("canceled snapshot = %#v, error = %v", snapshot, err)
	}
}

func TestExecutorFinalizesQueuedCancellationWithoutExecuting(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := storage.CancelScanTaskRun(db, task.ID, run.ID); err != nil {
		t.Fatalf("cancel queued run: %v", err)
	}
	executed := false
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		executed = true
		return model.ScanTaskRunSnapshot{}, nil
	}))
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("execute queued cancellation: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || executed || completed.Status != model.ScanTaskRunStatusCanceled {
		t.Fatalf("run = %#v, executed=%v, err=%v", completed, executed, err)
	}
}

func TestExecutorCancellationCancelsRunContext(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	started := make(chan struct{})
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(ctx context.Context, _ model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		close(started)
		<-ctx.Done()
		return model.ScanTaskRunSnapshot{}, ctx.Err()
	}))
	done := make(chan error, 1)
	go func() { done <- executor.ExecuteRun(context.Background(), run.ID) }()
	<-started
	if err := storage.CancelScanTaskRun(db, task.ID, run.ID); err != nil {
		t.Fatalf("cancel running run: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("execute canceled run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("execution did not observe cancellation")
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusCanceled {
		t.Fatalf("run = %#v, err=%v", completed, err)
	}
}

func TestExecutorKeepsQueuedRunWhenGlobalSlotIsOccupied(t *testing.T) {
	db := openExecutorTestDB(t)
	firstTask := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	secondTask := createRunnerTask(t, db, "192.168.11.0/24", "2026-07-24 00:00:00")
	active, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create active run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, active.ID); err != nil {
		t.Fatalf("mark active run: %v", err)
	}
	queued, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: secondTask.ID, ScheduledFor: "2026-07-24T02:01:00Z"})
	if err != nil {
		t.Fatalf("create queued run: %v", err)
	}
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		t.Fatal("queued run must not execute")
		return model.ScanTaskRunSnapshot{}, nil
	}))
	if err := executor.ExecuteRun(context.Background(), queued.ID); !errors.Is(err, ErrGlobalConcurrencyUnavailable) {
		t.Fatalf("execute error=%v", err)
	}
	persisted, err := storage.GetScanTaskRun(db, queued.ID)
	if err != nil || persisted.Status != model.ScanTaskRunStatusQueued {
		t.Fatalf("queued run=%#v err=%v", persisted, err)
	}
}

func TestExecutorPersistsPartialSnapshotBeforeFailedTerminalState(t *testing.T) {
	db := openExecutorTestDB(t)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	executor := NewExecutor(db, ScanTaskRunExecutorFunc(func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.7", IsActive: true}}}, errors.New("nuclei failed")
	}))
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusFailed || completed.SnapshotWrittenAt == "" {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, run.ID)
	if err != nil || len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != "192.168.10.7" {
		t.Fatalf("partial snapshot=%#v err=%v", snapshot, err)
	}
}

func openExecutorTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openRunnerTestDB(t)
	for _, statement := range []string{
		`CREATE TABLE scan_task_run_hosts (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, is_active INTEGER NOT NULL, PRIMARY KEY(scan_task_run_id, ip))`,
		`CREATE TABLE scan_task_run_ports (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, product TEXT, banner TEXT, PRIMARY KEY(scan_task_run_id, ip, port))`,
		`CREATE TABLE scan_task_run_vulnerabilities (scan_task_run_id INTEGER NOT NULL, finding_key TEXT NOT NULL, template_id TEXT, name TEXT, severity TEXT, target TEXT NOT NULL, target_ip TEXT, target_port INTEGER, matched_at TEXT, description TEXT, evidence TEXT, PRIMARY KEY(scan_task_run_id, finding_key))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create executor schema: %v", err)
		}
	}
	return db
}
