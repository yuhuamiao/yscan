package schedule

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestRunnerClaimsOneDueRunAndEnforcesGlobalConcurrency(t *testing.T) {
	db := openRunnerTestDB(t)
	now := time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	firstTask := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	secondTask := createRunnerTask(t, db, "192.168.20.0/24", "2026-07-24 00:00:00")
	runner := NewRunner(db, clock)

	firstRun, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("claim first run: %v", err)
	}
	if firstRun == nil || firstRun.ScanTaskID != firstTask.ID || firstRun.Status != model.ScanTaskRunStatusRunning {
		t.Fatalf("first claimed run = %#v", firstRun)
	}
	blocked, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("claim while globally busy: %v", err)
	}
	if blocked != nil {
		t.Fatalf("global concurrency must block another run, got %#v", blocked)
	}

	secondRuns, err := storage.ListScanTaskRuns(db, secondTask.ID)
	if err != nil {
		t.Fatalf("list blocked task runs: %v", err)
	}
	if len(secondRuns) != 1 || secondRuns[0].Status != model.ScanTaskRunStatusSkippedOverlap || secondRuns[0].StartedAt != "" || secondRuns[0].FinishedAt == "" {
		t.Fatalf("blocked task run = %#v, want skipped overlap", secondRuns)
	}
}

func TestRunnerRecoversQueuedOneTimeRunAfterRestart(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC) }))
	task, queued, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.10.10", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil || queued == nil {
		t.Fatalf("create once task=%#v run=%#v err=%v", task, queued, err)
	}
	runner := NewRunner(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 24, 2, 1, 0, 0, time.UTC) }))
	recovered, err := runner.RunOnce(context.Background())
	if err != nil || recovered == nil || recovered.ID != queued.ID || recovered.Status != model.ScanTaskRunStatusRunning {
		t.Fatalf("recovered run=%#v err=%v", recovered, err)
	}
	persisted, err := storage.GetScanTaskRun(db, queued.ID)
	if err != nil || persisted.Status != model.ScanTaskRunStatusRunning || persisted.StartedAt == "" {
		t.Fatalf("persisted recovered run=%#v err=%v", persisted, err)
	}
	if duplicate, err := runner.RunOnce(context.Background()); err != nil || duplicate != nil {
		t.Fatalf("second recovery=%#v err=%v", duplicate, err)
	}
}

func TestRunnerStartupFinalizesOrphanedRunningRunBeforeScheduling(t *testing.T) {
	db := openRunnerTestDB(t)
	task := createRunnerTask(t, db, "192.168.11.0/24", "2026-07-24 00:00:00")
	orphan, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create orphan run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, started_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusRunning, orphan.ID); err != nil {
		t.Fatalf("mark orphan running: %v", err)
	}
	runner := NewRunner(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 25, 2, 0, 0, 0, time.UTC) }))
	if err := runner.RecoverStartupState(); err != nil {
		t.Fatalf("recover startup state: %v", err)
	}
	finished, err := storage.GetScanTaskRun(db, orphan.ID)
	if err != nil || finished.Status != model.ScanTaskRunStatusFailed || finished.ErrorMessage != "interrupted by service restart" || finished.FinishedAt == "" {
		t.Fatalf("finished orphan=%#v err=%v", finished, err)
	}
	next, err := runner.RunOnce(context.Background())
	if err != nil || next == nil || next.Status != model.ScanTaskRunStatusRunning || next.ScheduledFor != "2026-07-25T02:00:00Z" {
		t.Fatalf("next scheduled run=%#v err=%v", next, err)
	}
}

func TestRunnerStartupFinalizesOrphanedScheduledQueuedRun(t *testing.T) {
	db := openRunnerTestDB(t)
	task := createRunnerTask(t, db, "192.168.12.0/24", "2026-07-24 00:00:00")
	orphan, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create queued scheduled run: %v", err)
	}
	runner := NewRunner(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 25, 2, 0, 0, 0, time.UTC) }))
	if err := runner.RecoverStartupState(); err != nil {
		t.Fatalf("recover startup state: %v", err)
	}
	finished, err := storage.GetScanTaskRun(db, orphan.ID)
	if err != nil || finished.Status != model.ScanTaskRunStatusSkippedMisfire || finished.ErrorMessage != "skipped because service restarted before execution" {
		t.Fatalf("finished queued run=%#v err=%v", finished, err)
	}
	next, err := runner.RunOnce(context.Background())
	if err != nil || next == nil || next.Status != model.ScanTaskRunStatusRunning || next.ScheduledFor != "2026-07-25T02:00:00Z" {
		t.Fatalf("next scheduled run=%#v err=%v", next, err)
	}
}

func TestRunnerAtomicClaimRejectsDuplicateAndPausedOrArchivedTasks(t *testing.T) {
	db := openRunnerTestDB(t)
	now := time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	runner := NewRunner(db, ClockFunc(func() time.Time { return now }))
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	candidate := dueCandidate{task: task, scheduledFor: now}

	first, claimed, err := runner.claimDueTask(context.Background(), candidate)
	if err != nil || !claimed {
		t.Fatalf("first atomic claim = (%#v, %t, %v)", first, claimed, err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = 'success' WHERE id = ?`, first.ID); err != nil {
		t.Fatalf("finish claimed run: %v", err)
	}
	if _, claimed, err := runner.claimDueTask(context.Background(), candidate); err != nil || claimed {
		t.Fatalf("duplicate scheduled_for claim = (%t, %v), want false, nil", claimed, err)
	}

	pausedTask := createRunnerTask(t, db, "192.168.20.0/24", "2026-07-24 00:00:00")
	pausedCandidate := dueCandidate{task: pausedTask, scheduledFor: now}
	if err := storage.PauseScanTask(db, pausedTask.ID); err != nil {
		t.Fatalf("pause task: %v", err)
	}
	if _, claimed, err := runner.claimDueTask(context.Background(), pausedCandidate); err != nil || claimed {
		t.Fatalf("paused task claim = (%t, %v), want false, nil", claimed, err)
	}

	archivedTask := createRunnerTask(t, db, "192.168.30.0/24", "2026-07-24 00:00:00")
	archivedCandidate := dueCandidate{task: archivedTask, scheduledFor: now}
	if err := storage.ArchiveScanTask(db, archivedTask.ID); err != nil {
		t.Fatalf("archive task: %v", err)
	}
	if _, claimed, err := runner.claimDueTask(context.Background(), archivedCandidate); err != nil || claimed {
		t.Fatalf("archived task claim = (%t, %v), want false, nil", claimed, err)
	}
}

func TestRunnerLoopUsesInjectedClockAndStopsWithContext(t *testing.T) {
	db := openRunnerTestDB(t)
	clock := &mutableClock{now: time.Date(2026, time.July, 24, 1, 59, 0, 0, time.UTC)}
	createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	runner := NewRunner(db, clock)
	runner.PollInterval = time.Millisecond
	claimed := make(chan model.ScanTaskRun, 1)
	runner.OnClaim = func(_ context.Context, run model.ScanTaskRun) {
		claimed <- run
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		if err := runner.Run(ctx); err != nil {
			t.Errorf("run loop: %v", err)
		}
	}()
	time.Sleep(5 * time.Millisecond)
	clock.Set(time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC))

	select {
	case run := <-claimed:
		if run.Status != model.ScanTaskRunStatusRunning {
			t.Fatalf("claimed run status = %q", run.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not claim due task")
	}
	cancel()
	waitGroup.Wait()
}

func TestRunnerRecordsMisfireWithoutReplayingScan(t *testing.T) {
	db := openRunnerTestDB(t)
	now := time.Date(2026, time.July, 24, 3, 0, 0, 0, time.UTC)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-24 00:00:00")
	runner := NewRunner(db, ClockFunc(func() time.Time { return now }))

	run, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("record misfire: %v", err)
	}
	if run != nil {
		t.Fatalf("misfire must not claim a run, got %#v", run)
	}
	runs, err := storage.ListScanTaskRuns(db, task.ID)
	if err != nil {
		t.Fatalf("list misfire runs: %v", err)
	}
	if len(runs) != 1 || runs[0].Status != model.ScanTaskRunStatusSkippedMisfire || runs[0].ScheduledFor != "2026-07-24T02:00:00Z" || runs[0].StartedAt != "" || runs[0].FinishedAt == "" {
		t.Fatalf("misfire run = %#v", runs)
	}
}

func TestRunnerRecordsOverlapWithoutStartingAnotherScan(t *testing.T) {
	db := openRunnerTestDB(t)
	now := time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	task := createRunnerTask(t, db, "192.168.10.0/24", "2026-07-23 00:00:00")
	if _, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{
		ScanTaskID:   task.ID,
		ScheduledFor: "2026-07-23T02:00:00Z",
		Status:       model.ScanTaskRunStatusRunning,
	}); err != nil {
		t.Fatalf("create active run: %v", err)
	}
	runner := NewRunner(db, ClockFunc(func() time.Time { return now }))

	run, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("record overlap: %v", err)
	}
	if run != nil {
		t.Fatalf("overlap must not claim a run, got %#v", run)
	}
	runs, err := storage.ListScanTaskRuns(db, task.ID)
	if err != nil {
		t.Fatalf("list overlap runs: %v", err)
	}
	if len(runs) != 2 || runs[1].Status != model.ScanTaskRunStatusSkippedOverlap || runs[1].ScheduledFor != "2026-07-24T02:00:00Z" {
		t.Fatalf("overlap run = %#v", runs)
	}
}

type mutableClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *mutableClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *mutableClock) Set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

func openRunnerTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:yscan_schedule_runner?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	statements := []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create runner schema: %v", err)
		}
	}
	return db
}

func createRunnerTask(t *testing.T, db *sql.DB, target, createdAt string) model.ScanTask {
	t.Helper()
	task, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   target,
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create runner task: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_tasks SET created_at = ? WHERE id = ?`, createdAt, task.ID); err != nil {
		t.Fatalf("set runner task creation time: %v", err)
	}
	task.CreatedAt = createdAt
	return task
}
