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
	DB              *sql.DB
	Clock           Clock
	MaxAge          time.Duration
	ReportDirectory string
}

type RetentionResult struct {
	DeletedRuns    int
	DeletedReports int
}

func NewRetentionPolicy(db *sql.DB, clock Clock, reportDirectory ...string) *RetentionPolicy {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	directory := ""
	if len(reportDirectory) > 0 {
		directory = filepath.Clean(strings.TrimSpace(reportDirectory[0]))
	}
	return &RetentionPolicy{DB: db, Clock: clock, MaxAge: DefaultRunRetention, ReportDirectory: directory}
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
		resolved := make([]string, 0, 2)
		for _, stored := range []string{candidate.ReportPath, candidate.AuditReportPath} {
			path, resolveErr := resolveRetainedReport(policy.ReportDirectory, stored)
			if resolveErr != nil {
				return result, fmt.Errorf("resolve report for scan task run %d: %w", candidate.ID, resolveErr)
			}
			resolved = append(resolved, path)
		}
		staged, err := stageReports(resolved)
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

func resolveRetainedReport(reportDirectory, stored string) (string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", nil
	}
	if strings.TrimSpace(reportDirectory) == "" {
		if filepath.IsAbs(stored) {
			return "", errors.New("retention report directory is required for absolute report paths")
		}
		return "", errors.New("retention report directory is required")
	}
	root, err := filepath.Abs(reportDirectory)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect retention report directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("retention report directory is not a regular directory: %s", root)
	}
	candidate := filepath.Clean(stored)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(filepath.Dir(root), candidate)
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("report path is outside %s", root)
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("report path contains symbolic link: %s", current)
		}
	}
	return candidate, nil
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
