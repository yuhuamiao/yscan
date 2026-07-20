package report

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

func ReadTaskReport(directory string, taskID int64) ([]byte, error) {
	if taskID <= 0 {
		return nil, fmt.Errorf("invalid task ID: %d", taskID)
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	return os.ReadFile(TaskReportPath(directory, taskID))
}

func TaskReportPath(directory string, taskID int64) string {
	return filepath.Join(directory, fmt.Sprintf("task-%d.md", taskID))
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
