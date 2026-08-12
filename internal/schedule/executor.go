package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

// ScanTaskRunExecutor contains the product-specific scan implementation. The
// scheduling package owns run state and snapshots; implementations only
// receive the immutable run configuration and return observed results.
type ScanTaskRunExecutor interface {
	Execute(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error)
}

type ScanTaskRunExecutorFunc func(context.Context, model.ScanTaskRun) (model.ScanTaskRunSnapshot, error)

func (fn ScanTaskRunExecutorFunc) Execute(ctx context.Context, run model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
	return fn(ctx, run)
}

type Executor struct {
	DB  *sql.DB
	Run ScanTaskRunExecutor
}

var (
	errRunCanceledBeforeStart = errors.New("scan task run was canceled before start")
	// ErrGlobalConcurrencyUnavailable leaves a queued run durable for the
	// Runner to claim once the single global execution slot becomes available.
	ErrGlobalConcurrencyUnavailable = errors.New("global scan task concurrency is unavailable")
)

func NewExecutor(db *sql.DB, run ScanTaskRunExecutor) *Executor {
	return &Executor{DB: db, Run: run}
}

// ExecuteRun owns the queued -> running scan transition. Scan errors are
// persisted as failed/canceled. A reporting-aware caller may defer successful
// terminal publication until its reports are ready.
func (executor *Executor) ExecuteRun(ctx context.Context, runID int64) error {
	if executor.DB == nil {
		return errors.New("scan task executor database is required")
	}
	if executor.Run == nil {
		return errors.New("scan task executor implementation is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := executor.markRunning(ctx, runID); errors.Is(err, errRunCanceledBeforeStart) {
		return executor.completeRun(runID, model.ScanTaskRunStatusCanceled, "canceled by request")
	} else if err != nil {
		return err
	}

	run, err := storage.GetScanTaskRun(executor.DB, runID)
	if err != nil {
		return err
	}
	return executor.executeStartedRun(ctx, run)
}

// ExecuteClaimedRun completes a run already atomically claimed by recovery.
func (executor *Executor) ExecuteClaimedRun(ctx context.Context, runID int64) error {
	run, err := storage.GetScanTaskRun(executor.DB, runID)
	if err != nil {
		return err
	}
	if run.Status != model.ScanTaskRunStatusRunning {
		return fmt.Errorf("scan task run %d is not running", runID)
	}
	return executor.executeStartedRun(ctx, run)
}

func (executor *Executor) executeStartedRun(ctx context.Context, run model.ScanTaskRun) error {
	runID := run.ID
	if _, err := NormalizeInternalScanTarget(run.ScanType, run.Target); err != nil {
		return executor.completeRun(runID, model.ScanTaskRunStatusFailed, err.Error())
	}
	runCtx, stopRunContext := executor.runContext(ctx, runID)
	defer stopRunContext()
	snapshot, executionErr := executor.Run.Execute(runCtx, run)
	if executionErr != nil || runCtx.Err() != nil {
		status := model.ScanTaskRunStatusFailed
		message := ""
		if runCtx.Err() != nil {
			status = model.ScanTaskRunStatusCanceled
			message = runCtx.Err().Error()
		} else {
			message = executionErr.Error()
		}
		if snapshotHasObservations(snapshot) {
			snapshot.RunID = runID
			if snapshotErr := storage.SaveScanTaskRunSnapshot(executor.DB, snapshot); snapshotErr != nil {
				message = fmt.Sprintf("%s; persist partial snapshot: %v", message, snapshotErr)
			}
		}
		return executor.completeRun(runID, status, message)
	}
	snapshot.RunID = runID
	if err := storage.UpdateScanTaskRunProgress(executor.DB, runID, model.ScanTaskRunStageSnapshot, 95); err != nil {
		return err
	}
	if err := storage.SaveScanTaskRunSnapshot(executor.DB, snapshot); err != nil {
		terminalErr := executor.completeRun(runID, model.ScanTaskRunStatusFailed, fmt.Sprintf("persist run snapshot: %v", err))
		if terminalErr != nil {
			return fmt.Errorf("save snapshot: %w; mark failed: %v", err, terminalErr)
		}
		return err
	}
	cancelRequested, err := executor.isCancelRequested(runID)
	if err != nil {
		return err
	}
	if cancelRequested {
		return executor.completeRun(runID, model.ScanTaskRunStatusCanceled, "canceled by request")
	}
	return storage.UpdateScanTaskRunProgress(executor.DB, runID, model.ScanTaskRunStageReporting, 99)
}

func snapshotHasObservations(snapshot model.ScanTaskRunSnapshot) bool {
	return len(snapshot.Hosts) > 0 || len(snapshot.Ports) > 0 || len(snapshot.Vulnerabilities) > 0 ||
		len(snapshot.TemplateCandidates) > 0 || len(snapshot.FingerprintMatches) > 0
}

func (executor *Executor) runContext(parent context.Context, runID int64) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			canceled, err := executor.isCancelRequested(runID)
			if err == nil && canceled {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return ctx, func() { cancel(); <-done }
}

// HandleClaim adapts Executor to Runner.OnClaim. Persistence errors are
// contained to the claimed run and never stop the scheduling loop.
func (executor *Executor) HandleClaim(ctx context.Context, run model.ScanTaskRun) {
	if run.Status == model.ScanTaskRunStatusRunning {
		_ = executor.ExecuteClaimedRun(ctx, run.ID)
		return
	}
	_ = executor.ExecuteRun(ctx, run.ID)
}

func (executor *Executor) markRunning(ctx context.Context, runID int64) error {
	result, err := executor.DB.ExecContext(ctx, `
		UPDATE scan_task_runs
		SET status = ?, stage = ?, progress = CASE WHEN progress < 1 THEN 1 ELSE progress END,
			started_at = COALESCE(started_at, datetime('now')), updated_at = datetime('now')
		WHERE id = ? AND status = ?
			AND NOT EXISTS (
				SELECT 1 FROM scan_task_runs AS active
				WHERE active.id <> scan_task_runs.id AND active.status IN (?, ?)
			)`,
		model.ScanTaskRunStatusRunning,
		model.ScanTaskRunStageStarting,
		runID,
		model.ScanTaskRunStatusQueued,
		model.ScanTaskRunStatusRunning,
		model.ScanTaskRunStatusCancelRequested,
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		canceled, lookupErr := executor.isCancelRequested(runID)
		if lookupErr == nil && canceled {
			return errRunCanceledBeforeStart
		}
		var active int
		if err := executor.DB.QueryRow(`SELECT 1 FROM scan_task_runs WHERE id <> ? AND status IN (?, ?) LIMIT 1`, runID, model.ScanTaskRunStatusRunning, model.ScanTaskRunStatusCancelRequested).Scan(&active); err == nil {
			return ErrGlobalConcurrencyUnavailable
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return fmt.Errorf("scan task run %d is not queued", runID)
	}
	return nil
}

func (executor *Executor) markTerminal(runID int64, status, message string) error {
	stage := model.ScanTaskRunStageFailed
	if status == model.ScanTaskRunStatusSuccess {
		stage = model.ScanTaskRunStageSnapshot
	} else if status == model.ScanTaskRunStatusCanceled {
		stage = model.ScanTaskRunStageCanceled
	}
	result, err := executor.DB.Exec(`
		UPDATE scan_task_runs
		SET
			status = CASE WHEN status = ? THEN ? ELSE ? END,
			stage = CASE WHEN status = ? THEN ? ELSE ? END,
			error_message = CASE WHEN status = ? THEN ? ELSE ? END,
			finished_at = datetime('now'),
			updated_at = datetime('now')
		WHERE id = ? AND status IN (?, ?)`,
		model.ScanTaskRunStatusCancelRequested,
		model.ScanTaskRunStatusCanceled,
		status,
		model.ScanTaskRunStatusCancelRequested,
		model.ScanTaskRunStageCanceled,
		stage,
		model.ScanTaskRunStatusCancelRequested,
		"canceled by request",
		message,
		runID,
		model.ScanTaskRunStatusRunning,
		model.ScanTaskRunStatusCancelRequested,
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("scan task run %d cannot transition to %s", runID, status)
	}
	return nil
}

func (executor *Executor) completeRun(runID int64, status, message string) error {
	return executor.markTerminal(runID, status, message)
}

// FinalizeSuccessfulRun publishes success only after report preparation. Run
// history is retained until a future explicit cleanup command requests pruning.
func (executor *Executor) FinalizeSuccessfulRun(runID int64, reportError string) error {
	return storage.FinalizeSuccessfulScanTaskRun(executor.DB, runID, reportError)
}

func (executor *Executor) isCancelRequested(runID int64) (bool, error) {
	var status string
	if err := executor.DB.QueryRow(`SELECT status FROM scan_task_runs WHERE id = ?`, runID).Scan(&status); err != nil {
		return false, err
	}
	return status == model.ScanTaskRunStatusCancelRequested, nil
}
