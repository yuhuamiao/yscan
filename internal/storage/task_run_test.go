package storage

import (
	"database/sql"
	"errors"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestScanTaskRunsAreIsolatedAndScheduledForIsUnique(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	firstTask := createScheduledTaskForTest(t, db, "192.168.10.0/24")
	secondTask := createScheduledTaskForTest(t, db, "192.168.10.0/24")
	const firstScheduledFor = "2026-07-24T10:00:00+08:00"

	firstRun, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: firstScheduledFor})
	if err != nil {
		t.Fatalf("create first run: %v", err)
	}
	if firstRun.Sequence != 1 || firstRun.ScheduledFor != "2026-07-24T02:00:00Z" {
		t.Fatalf("first run = %#v", firstRun)
	}
	secondRun, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: "2026-07-25T02:00:00Z"})
	if err != nil {
		t.Fatalf("create second run: %v", err)
	}
	if secondRun.Sequence != 2 {
		t.Fatalf("second run sequence = %d, want 2", secondRun.Sequence)
	}
	if _, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: firstScheduledFor}); err == nil {
		t.Fatal("duplicate scheduled_for must not create a second run")
	}
	otherTaskRun, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: secondTask.ID, ScheduledFor: firstScheduledFor})
	if err != nil {
		t.Fatalf("create same-time run for another task: %v", err)
	}
	if otherTaskRun.Sequence != 1 {
		t.Fatalf("other task sequence = %d, want 1", otherTaskRun.Sequence)
	}

	firstRuns, err := ListScanTaskRuns(db, firstTask.ID)
	if err != nil {
		t.Fatalf("list first task runs: %v", err)
	}
	if len(firstRuns) != 2 || firstRuns[0].ID != firstRun.ID || firstRuns[1].ID != secondRun.ID {
		t.Fatalf("first task runs = %#v", firstRuns)
	}
	secondRuns, err := ListScanTaskRuns(db, secondTask.ID)
	if err != nil {
		t.Fatalf("list second task runs: %v", err)
	}
	if len(secondRuns) != 1 || secondRuns[0].ID != otherTaskRun.ID {
		t.Fatalf("second task runs = %#v", secondRuns)
	}

	if err := PauseScanTask(db, firstTask.ID); err != nil {
		t.Fatalf("pause first task: %v", err)
	}
	if _, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: "2026-07-26T02:00:00Z"}); !errors.Is(err, ErrScanTaskNotEnabled) {
		t.Fatalf("paused task run error = %v, want ErrScanTaskNotEnabled", err)
	}
	if err := ArchiveScanTask(db, secondTask.ID); err != nil {
		t.Fatalf("archive second task: %v", err)
	}
	if _, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: secondTask.ID, ScheduledFor: "2026-07-26T02:00:00Z"}); !errors.Is(err, ErrScanTaskNotEnabled) {
		t.Fatalf("archived task run error = %v, want ErrScanTaskNotEnabled", err)
	}
}

func TestCancelScanTaskRunOnlyAcceptsQueuedOrRunning(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.60.0/24")
	queued, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create queued: %v", err)
	}
	if err := CancelScanTaskRun(db, task.ID, queued.ID); err != nil {
		t.Fatalf("cancel queued: %v", err)
	}
	if err := CancelScanTaskRun(db, task.ID, queued.ID); !errors.Is(err, ErrScanTaskRunNotCancelable) {
		t.Fatalf("repeat cancellation error=%v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusSuccess, queued.ID); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	if err := CancelScanTaskRun(db, task.ID, queued.ID); !errors.Is(err, ErrScanTaskRunNotCancelable) {
		t.Fatalf("terminal cancellation error=%v", err)
	}
	if err := CancelScanTaskRun(db, task.ID+1, queued.ID); !errors.Is(err, ErrScanTaskRunNotFound) {
		t.Fatalf("cross-task cancellation error=%v", err)
	}
}

func TestUpdateScanTaskRunReportErrorPreservesTerminalRun(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.61.0/24")
	run, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, finished_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusSuccess, run.ID); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	if err := UpdateScanTaskRunReportError(db, run.ID, "write report: permission denied"); err != nil {
		t.Fatalf("update report error: %v", err)
	}
	after, err := GetScanTaskRun(db, run.ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if after.Status != model.ScanTaskRunStatusSuccess || after.FinishedAt == "" || after.ReportError != "write report: permission denied" {
		t.Fatalf("run after report failure = %#v", after)
	}
	if err := UpdateScanTaskRunReportError(db, run.ID, ""); err != nil {
		t.Fatalf("clear report error: %v", err)
	}
	cleared, err := GetScanTaskRun(db, run.ID)
	if err != nil || cleared.ReportError != "" {
		t.Fatalf("cleared run=%#v err=%v", cleared, err)
	}
}

func createScheduledTaskForTest(t *testing.T, db *sql.DB, target string) model.ScanTask {
	t.Helper()
	task, err := CreateScanTask(db, model.ScanTask{
		Target:   target,
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "Asia/Shanghai",
	})
	if err != nil {
		t.Fatalf("create scheduled task: %v", err)
	}
	return task
}
