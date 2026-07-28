package report

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golandproject/yscan/internal/diff"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func GenerateTaskReport(db *sql.DB, taskID int64, directory string) (string, error) {
	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		return "", err
	}

	changes, err := storage.GetTaskChangeSummary(db, taskID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		changes = emptyChanges(task)
	}
	findings, err := storage.ListVulnerabilitiesByTask(db, taskID)
	if err != nil {
		return "", err
	}

	return WriteTaskReport(directory, TaskReport{
		Task:        task,
		Changes:     changes,
		Findings:    findings,
		GeneratedAt: time.Now().UTC(),
	})
}

// ScanTaskRunReport is the v2 report model. It intentionally refers only to
// a logical ScanTask, its immutable run snapshot, and its task-local Diff.
type ScanTaskRunReport struct {
	Task        model.ScanTask
	Run         model.ScanTaskRun
	Changes     model.ScanTaskRunChanges
	Snapshot    model.ScanTaskRunSnapshot
	GeneratedAt time.Time
}

func GenerateScanTaskRunReport(db *sql.DB, scanTaskID, runID int64, directory string) (string, error) {
	task, err := storage.GetScanTask(db, scanTaskID)
	if err != nil {
		return "", err
	}
	run, err := storage.GetScanTaskRun(db, runID)
	if err != nil {
		return "", err
	}
	if run.ScanTaskID != task.ID {
		return "", fmt.Errorf("scan task run %d does not belong to scan task %d", runID, scanTaskID)
	}

	snapshot := emptyRunSnapshot(run.ID)
	loadedSnapshot, err := storage.GetScanTaskRunSnapshot(db, run.ID)
	if err == nil {
		snapshot = loadedSnapshot
	} else if !errors.Is(err, storage.ErrScanTaskRunSnapshotUnavailable) {
		return "", err
	}

	changes := emptyRunChanges(task.ID, run.ID)
	if run.Status == model.ScanTaskRunStatusSuccess {
		changes, err = diff.CompareRunWithPreviousSuccess(db, run.ID)
		if err != nil {
			return "", err
		}
	}

	path, err := WriteScanTaskRunReport(directory, ScanTaskRunReport{
		Task:        task,
		Run:         run,
		Changes:     changes,
		Snapshot:    snapshot,
		GeneratedAt: time.Now().UTC(),
	})
	if err != nil {
		return "", err
	}
	if err := storage.UpdateScanTaskRunReportPath(db, run.ID, path); err != nil {
		return "", err
	}
	return path, nil
}

func WriteTaskReport(directory string, report TaskReport) (string, error) {
	if report.Task.ID <= 0 {
		return "", fmt.Errorf("invalid task ID: %d", report.Task.ID)
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	if err := os.MkdirAll(directory, 0750); err != nil {
		return "", err
	}

	path := TaskReportPath(directory, report.Task.ID)
	temporary, err := os.CreateTemp(directory, ".yscan-report-*.md")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if _, err := temporary.WriteString(RenderMarkdown(report)); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func WriteScanTaskRunReport(directory string, report ScanTaskRunReport) (string, error) {
	if report.Task.ID <= 0 || report.Run.ID <= 0 || report.Run.ScanTaskID != report.Task.ID {
		return "", errors.New("valid scan task and matching run are required")
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	if err := os.MkdirAll(directory, 0750); err != nil {
		return "", err
	}

	path := ScanTaskRunReportPath(directory, report.Task.ID, report.Run.ID)
	temporary, err := os.CreateTemp(directory, ".yscan-run-report-*.md")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if _, err := temporary.WriteString(RenderScanTaskRunMarkdown(report)); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func ReadTaskReport(directory string, taskID int64) ([]byte, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("invalid task ID: %d", taskID)
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	return os.ReadFile(TaskReportPath(directory, taskID))
}

// ReadScanTaskRunReport reads the canonical report for a task-local run. The
// caller supplies IDs rather than a stored filesystem path to keep report
// access scoped to the logical task and its run.
func ReadScanTaskRunReport(directory string, scanTaskID, runID int64) ([]byte, error) {
	if scanTaskID <= 0 || runID <= 0 {
		return nil, fmt.Errorf("invalid scan task or run ID")
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	return os.ReadFile(ScanTaskRunReportPath(directory, scanTaskID, runID))
}

func TaskReportPath(directory string, taskID int64) string {
	return filepath.Join(directory, fmt.Sprintf("task-%d.md", taskID))
}

func ScanTaskRunReportPath(directory string, scanTaskID, runID int64) string {
	return filepath.Join(directory, fmt.Sprintf("scan-task-%d-run-%d.md", scanTaskID, runID))
}

func RenderMarkdown(report TaskReport) string {
	generatedAt := report.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	var builder strings.Builder
	builder.WriteString("# yscan CAASM Task Report\n\n")
	builder.WriteString("## Task Summary\n\n")
	builder.WriteString("| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&builder, "| Task ID | %d |\n", report.Task.ID)
	fmt.Fprintf(&builder, "| Type | %s |\n", markdownCell(report.Task.TaskType))
	fmt.Fprintf(&builder, "| Target | %s |\n", markdownCell(report.Task.Target))
	fmt.Fprintf(&builder, "| Status | %s |\n", markdownCell(report.Task.Status))
	fmt.Fprintf(&builder, "| Started | %s |\n", markdownCell(report.Task.StartedAt))
	fmt.Fprintf(&builder, "| Finished | %s |\n", markdownCell(report.Task.FinishedAt))
	fmt.Fprintf(&builder, "| Generated | %s |\n\n", generatedAt.Format(time.RFC3339))

	builder.WriteString("## Host Changes\n\n")
	writeStringList(&builder, "New hosts", report.Changes.HostChanges.NewHosts)
	writeStringList(&builder, "Inactive hosts", report.Changes.HostChanges.InactiveHosts)

	builder.WriteString("## Port Changes\n\n")
	writePortChanges(&builder, "Opened ports", report.Changes.PortChanges.Opened)
	writePortChanges(&builder, "Closed ports", report.Changes.PortChanges.Closed)

	builder.WriteString("## Vulnerability Summary\n\n")
	if len(report.Findings) == 0 {
		builder.WriteString("No vulnerability findings were recorded for this task.\n")
		return builder.String()
	}
	builder.WriteString("| Severity | Template | Target | Name |\n| --- | --- | --- | --- |\n")
	for _, finding := range report.Findings {
		target := finding.Target
		if target == "" {
			target = finding.TargetIP
		}
		fmt.Fprintf(&builder, "| %s | %s | %s | %s |\n",
			markdownCell(finding.Severity),
			markdownCell(finding.TemplateID),
			markdownCell(target),
			markdownCell(finding.Name),
		)
	}
	return builder.String()
}

func RenderScanTaskRunMarkdown(report ScanTaskRunReport) string {
	generatedAt := report.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	var builder strings.Builder
	builder.WriteString("# yscan CAASM Scan Task Run Report\n\n")
	builder.WriteString("## Run Summary\n\n")
	builder.WriteString("| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&builder, "| Logical Task ID | %d |\n", report.Task.ID)
	fmt.Fprintf(&builder, "| Run ID | %d |\n", report.Run.ID)
	fmt.Fprintf(&builder, "| Sequence | %d |\n", report.Run.Sequence)
	fmt.Fprintf(&builder, "| Target | %s |\n", markdownCell(report.Run.Target))
	fmt.Fprintf(&builder, "| Scan Type | %s |\n", markdownCell(report.Run.ScanType))
	fmt.Fprintf(&builder, "| Status | %s |\n", markdownCell(report.Run.Status))
	fmt.Fprintf(&builder, "| Scheduled For | %s |\n", markdownCell(report.Run.ScheduledFor))
	fmt.Fprintf(&builder, "| Started | %s |\n", markdownCell(report.Run.StartedAt))
	fmt.Fprintf(&builder, "| Finished | %s |\n", markdownCell(report.Run.FinishedAt))
	fmt.Fprintf(&builder, "| Baseline Run ID | %d |\n", report.Changes.BaselineRunID)
	fmt.Fprintf(&builder, "| Config Changed | %t |\n", report.Changes.ConfigChanged)
	fmt.Fprintf(&builder, "| Generated | %s |\n\n", generatedAt.Format(time.RFC3339))

	builder.WriteString("## Host Changes\n\n")
	writeStringList(&builder, "New hosts", report.Changes.HostChanges.NewHosts)
	writeStringList(&builder, "Inactive hosts", report.Changes.HostChanges.InactiveHosts)

	builder.WriteString("## Port Changes\n\n")
	writePortChanges(&builder, "Opened ports", report.Changes.PortChanges.Opened)
	writePortChanges(&builder, "Closed ports", report.Changes.PortChanges.Closed)

	builder.WriteString("## Vulnerability Summary\n\n")
	builder.WriteString("## Validation Plan\n\n")
	if len(report.Snapshot.TemplateCandidates) == 0 {
		builder.WriteString("No validation templates were selected.\n\n")
	} else {
		builder.WriteString("| Template | Source | Reason |\n| --- | --- | --- |\n")
		for _, candidate := range report.Snapshot.TemplateCandidates {
			fmt.Fprintf(&builder, "| %s | %s | %s |\n", markdownCell(candidate.TemplateID), markdownCell(candidate.Source), markdownCell(candidate.Reason))
		}
		builder.WriteString("\n")
	}
	if len(report.Snapshot.Vulnerabilities) == 0 {
		builder.WriteString("No vulnerability findings were recorded for this run.\n")
		return builder.String()
	}
	builder.WriteString("| Severity | Template | Target | Name |\n| --- | --- | --- | --- |\n")
	for _, finding := range report.Snapshot.Vulnerabilities {
		fmt.Fprintf(&builder, "| %s | %s | %s | %s |\n",
			markdownCell(finding.Severity),
			markdownCell(finding.TemplateID),
			markdownCell(finding.Target),
			markdownCell(finding.Name),
		)
	}
	return builder.String()
}

func emptyChanges(task model.Task) model.TaskChangeSummary {
	return model.TaskChangeSummary{
		TaskID: task.ID,
		Target: task.Target,
		HostChanges: model.HostChanges{
			NewHosts:      []string{},
			InactiveHosts: []string{},
		},
		PortChanges: model.PortChanges{
			Opened: []model.PortChange{},
			Closed: []model.PortChange{},
		},
	}
}

func emptyRunSnapshot(runID int64) model.ScanTaskRunSnapshot {
	return model.ScanTaskRunSnapshot{
		RunID:           runID,
		Hosts:           make([]model.ScanTaskRunHost, 0),
		Ports:           make([]model.ScanTaskRunPort, 0),
		Vulnerabilities: make([]model.ScanTaskRunVulnerability, 0),
	}
}

func emptyRunChanges(scanTaskID, runID int64) model.ScanTaskRunChanges {
	return model.ScanTaskRunChanges{
		ScanTaskID:   scanTaskID,
		CurrentRunID: runID,
		HostChanges:  model.HostChanges{NewHosts: make([]string, 0), InactiveHosts: make([]string, 0)},
		PortChanges:  model.PortChanges{Opened: make([]model.PortChange, 0), Closed: make([]model.PortChange, 0)},
		VulnerabilityChanges: model.VulnerabilityChanges{
			New:      make([]model.VulnerabilityChange, 0),
			Resolved: make([]model.VulnerabilityChange, 0),
		},
	}
}

func writeStringList(builder *strings.Builder, title string, values []string) {
	fmt.Fprintf(builder, "### %s\n\n", title)
	if len(values) == 0 {
		builder.WriteString("None.\n\n")
		return
	}
	for _, value := range values {
		fmt.Fprintf(builder, "- `%s`\n", markdownCell(value))
	}
	builder.WriteString("\n")
}

func writePortChanges(builder *strings.Builder, title string, changes []model.PortChange) {
	fmt.Fprintf(builder, "### %s\n\n", title)
	if len(changes) == 0 {
		builder.WriteString("None.\n\n")
		return
	}
	for _, change := range changes {
		fmt.Fprintf(builder, "- `%s:%d`\n", markdownCell(change.IP), change.Port)
	}
	builder.WriteString("\n")
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}
