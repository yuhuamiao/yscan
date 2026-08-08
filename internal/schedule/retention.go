package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golandproject/yscan/internal/storage"
)

const DefaultRunRetention = 90 * 24 * time.Hour

// RetentionPolicy removes old immutable run history without touching the
// logical task or the current asset inventory. The most recent successful run
// of each task remains available as the next Diff baseline.
type RetentionPolicy struct {
	DB     *sql.DB
	Clock  Clock
	MaxAge time.Duration
}

type RetentionResult struct {
	DeletedRuns    int
	DeletedReports int
}

func NewRetentionPolicy(db *sql.DB, clock Clock) *RetentionPolicy {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	return &RetentionPolicy{DB: db, Clock: clock, MaxAge: DefaultRunRetention}
}

// Prune deletes only terminal runs older than MaxAge. A report is first moved
// out of its live path; if the database transaction cannot complete, it is
// restored so a retained run never points to a missing report.
func (policy *RetentionPolicy) Prune(ctx context.Context) (RetentionResult, error) {
	if err := ctx.Err(); err != nil {
		return RetentionResult{}, err
	}
	if policy.DB == nil {
		return RetentionResult{}, errors.New("retention database is required")
	}
	if policy.Clock == nil {
		return RetentionResult{}, errors.New("retention clock is required")
	}
	if policy.MaxAge <= 0 {
		return RetentionResult{}, errors.New("retention max age must be positive")
	}

	cutoff := policy.Clock.Now().UTC().Add(-policy.MaxAge)
	candidates, err := storage.ListExpiredTerminalScanTaskRuns(policy.DB, cutoff)
	if err != nil {
		return RetentionResult{}, err
	}

	result := RetentionResult{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		staged, err := stageReports([]string{candidate.ReportPath, candidate.AuditReportPath})
		if err != nil {
			return result, fmt.Errorf("stage reports for scan task run %d: %w", candidate.ID, err)
		}
		deleted, err := storage.DeleteExpiredTerminalScanTaskRun(policy.DB, candidate.ID, cutoff)
		if err != nil {
			return result, restoreStagedReports(staged, fmt.Errorf("delete scan task run %d: %w", candidate.ID, err))
		}
		if !deleted {
			if err := restoreStagedReports(staged, nil); err != nil {
				return result, err
			}
			continue
		}

		result.DeletedRuns++
		for _, report := range staged {
			if report.temporary == "" {
				continue
			}
			if err := os.Remove(report.temporary); err != nil {
				return result, fmt.Errorf("remove retired report for scan task run %d: %w", candidate.ID, err)
			}
			result.DeletedReports++
		}
	}
	return result, nil
}

type stagedReport struct {
	original  string
	temporary string
}

func stageReports(paths []string) ([]stagedReport, error) {
	staged := make([]stagedReport, 0, len(paths))
	for _, path := range paths {
		report, err := stageReport(path)
		if err != nil {
			return nil, restoreStagedReports(staged, err)
		}
		staged = append(staged, report)
	}
	return staged, nil
}

func stageReport(path string) (stagedReport, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return stagedReport{}, nil
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".yscan-retention-*.md")
	if errors.Is(err, os.ErrNotExist) {
		return stagedReport{}, nil
	}
	if err != nil {
		return stagedReport{}, err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return stagedReport{}, err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return stagedReport{}, err
	}
	if err := os.Rename(path, temporaryPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stagedReport{}, nil
		}
		return stagedReport{}, err
	}
	return stagedReport{original: path, temporary: temporaryPath}, nil
}

func restoreStagedReport(staged stagedReport, originalErr error) error {
	if staged.temporary == "" {
		return originalErr
	}
	if err := os.Rename(staged.temporary, staged.original); err != nil {
		if originalErr != nil {
			return fmt.Errorf("%w; restore staged report: %v", originalErr, err)
		}
		return fmt.Errorf("restore staged report: %w", err)
	}
	return originalErr
}

func restoreStagedReports(staged []stagedReport, originalErr error) error {
	result := originalErr
	for index := len(staged) - 1; index >= 0; index-- {
		result = restoreStagedReport(staged[index], result)
	}
	return result
}
