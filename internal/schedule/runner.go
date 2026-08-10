package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

const defaultPollInterval = time.Minute

type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (fn ClockFunc) Now() time.Time {
	return fn()
}

type Runner struct {
	DB           *sql.DB
	Clock        Clock
	PollInterval time.Duration
	OnClaim      func(context.Context, model.ScanTaskRun)
	OnRecovered  func(model.ScanTaskRun) error
}

func NewRunner(db *sql.DB, clock Clock) *Runner {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	return &Runner{DB: db, Clock: clock, PollInterval: defaultPollInterval}
}

// RunOnce claims at most one due scheduled run. The single INSERT ... SELECT
// is the linearization point for both the task enabled check and global
// concurrency limit.
func (runner *Runner) RunOnce(ctx context.Context) (*model.ScanTaskRun, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runner.DB == nil {
		return nil, errors.New("schedule runner database is required")
	}
	if runner.Clock == nil {
		return nil, errors.New("schedule runner clock is required")
	}
	if err := storage.FinalizeQueuedCancellation(runner.DB); err != nil {
		return nil, err
	}
	if recovered, err := storage.ClaimQueuedScanTaskRun(runner.DB); err != nil {
		return nil, err
	} else if recovered != nil {
		return recovered, nil
	}

	now := runner.Clock.Now().UTC()
	candidates, err := runner.dueCandidates(now)
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if ClassifyDueRun(candidate.scheduledFor, now) == DuePolicySkippedMisfire {
			recorded, err := runner.recordPolicyRun(ctx, candidate, model.ScanTaskRunStatusSkippedMisfire, false)
			if err != nil {
				return nil, err
			}
			if recorded {
				return nil, nil
			}
			continue
		}
		run, claimed, err := runner.claimDueTask(ctx, candidate)
		if err != nil {
			return nil, err
		}
		if claimed {
			return &run, nil
		}
		recorded, err := runner.recordPolicyRun(ctx, candidate, model.ScanTaskRunStatusSkippedOverlap, true)
		if err != nil {
			return nil, err
		}
		if recorded {
			return nil, nil
		}
	}
	return nil, nil
}

// recordPolicyRun persists an auditable terminal run without consuming the
// global execution slot. Overlap records are inserted only while a slot is
// genuinely occupied; otherwise a failed claim was caused by a concurrent
// lifecycle change or duplicate insert and is simply ignored.
func (runner *Runner) recordPolicyRun(ctx context.Context, candidate dueCandidate, status string, requireActiveRun bool) (bool, error) {
	activeClause := ""
	arguments := []interface{}{
		candidate.scheduledFor.UTC().Format(time.RFC3339Nano),
		status,
		model.ScanTaskRunTriggerScheduled,
		model.ScanTaskRunStageCompleted,
		candidate.task.ID,
		model.ScanTaskModeScheduled,
		model.ScanTaskStatusEnabled,
	}
	if requireActiveRun {
		activeClause = `
			AND EXISTS (
				SELECT 1 FROM scan_task_runs
				WHERE status IN (?, ?)
			)`
		arguments = append(arguments, model.ScanTaskRunStatusRunning, model.ScanTaskRunStatusCancelRequested)
	}

	query := `
		INSERT INTO scan_task_runs
			(scan_task_id, sequence, scheduled_for, status, trigger, stage, progress, target, scan_type, config_json, config_hash, finished_at, created_at, updated_at)
		SELECT
			scan_tasks.id,
			COALESCE((SELECT MAX(sequence) FROM scan_task_runs WHERE scan_task_id = scan_tasks.id), 0) + 1,
			?, ?, ?, ?, 100, scan_tasks.target, scan_tasks.scan_type, scan_tasks.config_json, scan_tasks.config_hash, datetime('now'), datetime('now'), datetime('now')
		FROM scan_tasks
		WHERE scan_tasks.id = ?
			AND scan_tasks.mode = ?
			AND scan_tasks.status = ?` + activeClause + `
		ON CONFLICT(scan_task_id, scheduled_for) DO NOTHING`
	result, err := runner.DB.ExecContext(ctx, query, arguments...)
	if err != nil {
		return false, err
	}
	recorded, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return recorded != 0, nil
}

func (runner *Runner) Run(ctx context.Context) error {
	if err := runner.RecoverStartupState(); err != nil {
		return err
	}
	return runner.RunLoop(ctx)
}

// RunLoop runs scheduling after startup recovery has completed. Service
// entrypoints that expose task creation must call RecoverStartupState before
// they begin accepting requests, then use this method to avoid a second pass.
func (runner *Runner) RunLoop(ctx context.Context) error {
	interval := runner.PollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		run, err := runner.RunOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if run != nil && runner.OnClaim != nil {
			runner.OnClaim(ctx, *run)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// RecoverStartupState is deliberately separate from RunOnce: it must execute
// only at process startup, never while this process has active workers.
func (runner *Runner) RecoverStartupState() error {
	if runner.DB == nil {
		return errors.New("schedule runner database is required")
	}
	recovered, err := storage.FinalizeInterruptedScanTaskRunsWithResult(runner.DB)
	if err != nil {
		return err
	}
	if runner.OnRecovered == nil {
		return nil
	}
	for _, run := range recovered {
		if err := runner.OnRecovered(run); err != nil {
			return fmt.Errorf("finalize recovered scan task run %d: %w", run.ID, err)
		}
	}
	return nil
}

type dueCandidate struct {
	task         model.ScanTask
	scheduledFor time.Time
}

func (runner *Runner) dueCandidates(now time.Time) ([]dueCandidate, error) {
	tasks, err := storage.ListScanTasks(runner.DB)
	if err != nil {
		return nil, err
	}
	candidates := make([]dueCandidate, 0)
	for _, task := range tasks {
		if task.Status != model.ScanTaskStatusEnabled || task.Mode != model.ScanTaskModeScheduled {
			continue
		}
		anchor, err := runner.taskScheduleAnchor(task)
		if err != nil {
			return nil, err
		}
		scheduledFor, err := NextScheduledAt(task.Cron, task.Timezone, anchor)
		if err != nil {
			return nil, fmt.Errorf("scan task %d schedule: %w", task.ID, err)
		}
		if scheduledFor.After(now) {
			continue
		}
		candidates = append(candidates, dueCandidate{task: task, scheduledFor: scheduledFor})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].scheduledFor.Equal(candidates[j].scheduledFor) {
			return candidates[i].task.ID < candidates[j].task.ID
		}
		return candidates[i].scheduledFor.Before(candidates[j].scheduledFor)
	})
	return candidates, nil
}

func (runner *Runner) taskScheduleAnchor(task model.ScanTask) (time.Time, error) {
	runs, err := storage.ListScanTaskRuns(runner.DB, task.ID)
	if err != nil {
		return time.Time{}, err
	}
	if len(runs) == 0 {
		return parseStoredTime(task.CreatedAt)
	}
	return parseStoredTime(runs[len(runs)-1].ScheduledFor)
}

func (runner *Runner) claimDueTask(ctx context.Context, candidate dueCandidate) (model.ScanTaskRun, bool, error) {
	tx, err := runner.DB.BeginTx(ctx, nil)
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO scan_task_runs
			(scan_task_id, sequence, scheduled_for, status, trigger, stage, progress, target, scan_type, config_json, config_hash, started_at, created_at, updated_at)
		SELECT
			scan_tasks.id,
			COALESCE((SELECT MAX(sequence) FROM scan_task_runs WHERE scan_task_id = scan_tasks.id), 0) + 1,
			?, ?, ?, ?, 1, scan_tasks.target, scan_tasks.scan_type, scan_tasks.config_json, scan_tasks.config_hash, datetime('now'), datetime('now'), datetime('now')
		FROM scan_tasks
		WHERE scan_tasks.id = ?
			AND scan_tasks.mode = ?
			AND scan_tasks.status = ?
			AND NOT EXISTS (
				SELECT 1 FROM scan_task_runs
			WHERE status IN (?, ?)
			)
		ON CONFLICT(scan_task_id, scheduled_for) DO NOTHING`,
		candidate.scheduledFor.UTC().Format(time.RFC3339Nano),
		model.ScanTaskRunStatusRunning,
		model.ScanTaskRunTriggerScheduled,
		model.ScanTaskRunStageStarting,
		candidate.task.ID,
		model.ScanTaskModeScheduled,
		model.ScanTaskStatusEnabled,
		model.ScanTaskRunStatusRunning,
		model.ScanTaskRunStatusCancelRequested,
	)
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	claimed, err := result.RowsAffected()
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	if claimed == 0 {
		return model.ScanTaskRun{}, false, nil
	}
	runID, err := result.LastInsertId()
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	if err := storage.FreezeActiveFingerprintImportsTx(tx, runID); err != nil {
		return model.ScanTaskRun{}, false, fmt.Errorf("freeze scheduled run fingerprint imports: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.ScanTaskRun{}, false, err
	}
	run, err := storage.GetScanTaskRun(runner.DB, runID)
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	return run, true, nil
}

func parseStoredTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid stored timestamp %q", value)
}
