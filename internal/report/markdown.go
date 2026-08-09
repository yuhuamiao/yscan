package report

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	Task                   model.ScanTask
	Run                    model.ScanTaskRun
	Changes                model.ScanTaskRunChanges
	Snapshot               model.ScanTaskRunSnapshot
	FingerprintImports     []model.FingerprintImport
	FingerprintMatches     []map[string]interface{}
	FingerprintConclusions []map[string]interface{}
	GeneratedAt            time.Time
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
	frozenImports, err := storage.ListFingerprintImportsForRun(db, run.ID)
	if err != nil && !isMissingFingerprintReportTable(err) {
		return "", err
	}
	fingerprintMatches, err := storage.ListFingerprintRunMatches(db, run.ID)
	if err != nil && !isMissingFingerprintReportTable(err) {
		return "", err
	}
	fingerprintConclusions, err := storage.ListFingerprintRunConclusions(db, run.ID)
	if err != nil && !isMissingFingerprintReportTable(err) {
		return "", err
	}

	transaction, err := prepareScanTaskRunReport(directory, ScanTaskRunReport{
		Task: task, Run: run, Changes: changes, Snapshot: snapshot,
		FingerprintImports: frozenImports, FingerprintMatches: fingerprintMatches,
		FingerprintConclusions: fingerprintConclusions, GeneratedAt: time.Now().UTC(),
	})
	if err != nil {
		return "", err
	}
	paths := transaction.paths
	if err := updateScanTaskRunReportPaths(db, run.ID, paths.User, paths.Audit); err != nil {
		_ = transaction.rollback()
		return "", err
	}
	transaction.commit()
	return paths.User, nil
}

func isMissingFingerprintReportTable(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such table") && strings.Contains(message, "fingerprint")
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

type ScanTaskRunReportPaths struct {
	User  string
	Audit string
}

var renameScanTaskRunReportFile = os.Rename
var updateScanTaskRunReportPaths = storage.UpdateScanTaskRunReportPaths

type scanTaskRunReportTransaction struct {
	paths        ScanTaskRunReportPaths
	journalPath  string
	userBackup   string
	auditBackup  string
	userExisted  bool
	auditExisted bool
}

type scanTaskRunReportJournal struct {
	UserPath     string `json:"user_path"`
	AuditPath    string `json:"audit_path"`
	UserBackup   string `json:"user_backup,omitempty"`
	AuditBackup  string `json:"audit_backup,omitempty"`
	UserExisted  bool   `json:"user_existed"`
	AuditExisted bool   `json:"audit_existed"`
}

func WriteScanTaskRunReport(directory string, report ScanTaskRunReport) (ScanTaskRunReportPaths, error) {
	transaction, err := prepareScanTaskRunReport(directory, report)
	if err != nil {
		return ScanTaskRunReportPaths{}, err
	}
	transaction.commit()
	return transaction.paths, nil
}

func prepareScanTaskRunReport(directory string, report ScanTaskRunReport) (*scanTaskRunReportTransaction, error) {
	if report.Task.ID <= 0 || report.Run.ID <= 0 || report.Run.ScanTaskID != report.Task.ID {
		return nil, errors.New("valid scan task and matching run are required")
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	paths := ScanTaskRunReportPaths{User: ScanTaskRunReportPath(directory, report.Task.ID, report.Run.ID), Audit: ScanTaskRunAuditReportPath(directory, report.Task.ID, report.Run.ID)}
	journalPath := scanTaskRunReportJournalPath(directory, report.Task.ID, report.Run.ID)
	if err := recoverScanTaskRunReportPair(journalPath); err != nil {
		return nil, err
	}
	userTemporaryPath, err := writeTemporaryScanTaskRunReport(directory, ".yscan-run-report-*.md", RenderScanTaskRunMarkdown(report))
	if err != nil {
		return nil, err
	}
	defer os.Remove(userTemporaryPath)
	auditTemporaryPath, err := writeTemporaryScanTaskRunReport(directory, ".yscan-run-audit-*.md", RenderScanTaskRunAuditMarkdown(report))
	if err != nil {
		return nil, err
	}
	defer os.Remove(auditTemporaryPath)
	transaction := &scanTaskRunReportTransaction{paths: paths, journalPath: journalPath}
	transaction.userBackup, transaction.userExisted, err = backupScanTaskRunReport(paths.User, directory)
	if err != nil {
		return nil, err
	}
	transaction.auditBackup, transaction.auditExisted, err = backupScanTaskRunReport(paths.Audit, directory)
	if err != nil {
		transaction.commit()
		return nil, err
	}
	if err := writeScanTaskRunReportJournal(transaction); err != nil {
		transaction.commit()
		return nil, err
	}
	if err := renameScanTaskRunReportFile(userTemporaryPath, paths.User); err != nil {
		_ = transaction.rollback()
		return nil, err
	}
	if err := renameScanTaskRunReportFile(auditTemporaryPath, paths.Audit); err != nil {
		_ = transaction.rollback()
		return nil, err
	}
	return transaction, nil
}

func backupScanTaskRunReport(path, directory string) (string, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	backup, err := os.CreateTemp(directory, ".yscan-run-report-backup-*.md")
	if err != nil {
		return "", false, err
	}
	backupPath := backup.Name()
	if _, err := backup.Write(content); err != nil {
		_ = backup.Close()
		_ = os.Remove(backupPath)
		return "", false, err
	}
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", false, err
	}
	return backupPath, true, nil
}

func writeScanTaskRunReportJournal(transaction *scanTaskRunReportTransaction) error {
	content, err := json.Marshal(scanTaskRunReportJournal{
		UserPath: transaction.paths.User, AuditPath: transaction.paths.Audit,
		UserBackup: transaction.userBackup, AuditBackup: transaction.auditBackup,
		UserExisted: transaction.userExisted, AuditExisted: transaction.auditExisted,
	})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(transaction.journalPath), ".yscan-run-report-journal-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, transaction.journalPath)
}

func (transaction *scanTaskRunReportTransaction) rollback() error {
	if transaction == nil {
		return nil
	}
	var rollbackErr error
	for _, item := range []struct {
		path, backup string
		existed      bool
	}{{transaction.paths.User, transaction.userBackup, transaction.userExisted}, {transaction.paths.Audit, transaction.auditBackup, transaction.auditExisted}} {
		if item.existed {
			if err := os.Rename(item.backup, item.path); err != nil && rollbackErr == nil {
				rollbackErr = err
			}
		} else if err := os.Remove(item.path); err != nil && !errors.Is(err, os.ErrNotExist) && rollbackErr == nil {
			rollbackErr = err
		}
	}
	if rollbackErr == nil {
		_ = os.Remove(transaction.journalPath)
	}
	return rollbackErr
}

func (transaction *scanTaskRunReportTransaction) commit() {
	if transaction == nil {
		return
	}
	_ = os.Remove(transaction.userBackup)
	_ = os.Remove(transaction.auditBackup)
	_ = os.Remove(transaction.journalPath)
}

func recoverScanTaskRunReportPair(journalPath string) error {
	content, err := os.ReadFile(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal scanTaskRunReportJournal
	if err := json.Unmarshal(content, &journal); err != nil {
		return err
	}
	transaction := &scanTaskRunReportTransaction{
		paths: ScanTaskRunReportPaths{User: journal.UserPath, Audit: journal.AuditPath}, journalPath: journalPath,
		userBackup: journal.UserBackup, auditBackup: journal.AuditBackup, userExisted: journal.UserExisted, auditExisted: journal.AuditExisted,
	}
	return transaction.rollback()
}

func scanTaskRunReportJournalPath(directory string, scanTaskID, runID int64) string {
	return filepath.Join(directory, fmt.Sprintf(".scan-task-%d-run-%d-report-pair.json", scanTaskID, runID))
}

func writeTemporaryScanTaskRunReport(directory, pattern, content string) (string, error) {
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	path := temporary.Name()
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(path)
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
	if err := recoverScanTaskRunReportPair(scanTaskRunReportJournalPath(directory, scanTaskID, runID)); err != nil {
		return nil, err
	}
	return os.ReadFile(ScanTaskRunReportPath(directory, scanTaskID, runID))
}

func ReadScanTaskRunAuditReport(directory string, scanTaskID, runID int64) ([]byte, error) {
	if scanTaskID <= 0 || runID <= 0 {
		return nil, fmt.Errorf("invalid scan task or run ID")
	}
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectory
	}
	if err := recoverScanTaskRunReportPair(scanTaskRunReportJournalPath(directory, scanTaskID, runID)); err != nil {
		return nil, err
	}
	return os.ReadFile(ScanTaskRunAuditReportPath(directory, scanTaskID, runID))
}

func TaskReportPath(directory string, taskID int64) string {
	return filepath.Join(directory, fmt.Sprintf("task-%d.md", taskID))
}

func ScanTaskRunReportPath(directory string, scanTaskID, runID int64) string {
	return filepath.Join(directory, fmt.Sprintf("scan-task-%d-run-%d.md", scanTaskID, runID))
}

func ScanTaskRunAuditReportPath(directory string, scanTaskID, runID int64) string {
	return filepath.Join(directory, fmt.Sprintf("scan-task-%d-run-%d-audit.md", scanTaskID, runID))
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
	fmt.Fprintf(&builder, "| Target | %s |\n", markdownCell(report.Run.Target))
	fmt.Fprintf(&builder, "| Run Status | %s |\n", markdownCell(report.Run.Status))
	fmt.Fprintf(&builder, "| Generated | %s |\n\n", generatedAt.Format(time.RFC3339))

	writeRunValidation(&builder, report.Snapshot.Validation, report.Snapshot.Vulnerabilities)
	writeRunEndpointProfiles(&builder, report)

	builder.WriteString("## Asset Changes\n\n")
	fmt.Fprintf(&builder, "Baseline run: %d. Configuration changed: %t.\n\n", report.Changes.BaselineRunID, report.Changes.ConfigChanged)
	writeStringList(&builder, "New hosts", report.Changes.HostChanges.NewHosts)
	writeStringList(&builder, "Inactive hosts", report.Changes.HostChanges.InactiveHosts)
	writePortChanges(&builder, "Opened ports", report.Changes.PortChanges.Opened)
	writePortChanges(&builder, "Closed ports", report.Changes.PortChanges.Closed)
	return builder.String()
}

func writeRunValidation(builder *strings.Builder, validation model.ScanTaskRunValidation, findings []model.ScanTaskRunVulnerability) {
	builder.WriteString("## Vulnerability Validation\n\n")
	status := validation.Status
	if status == "" {
		status = "unavailable"
	}
	severityCounts := make(map[string]int)
	for _, finding := range findings {
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		switch severity {
		case "critical", "high", "medium", "low", "info":
		default:
			severity = "unknown"
		}
		severityCounts[severity]++
	}
	builder.WriteString("| Status | Identified products | Mapped products | Candidate endpoints | Executed endpoints | Candidate templates | Executed templates | Findings |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(builder, "| %s | %d | %d | %d | %d | %d | %d | %d |\n\n", markdownCell(status), validation.IdentifiedProductCount, validation.MappedProductCount, validation.CandidateEndpointCount, validation.ExecutedEndpointCount, validation.TemplateCount, validation.ExecutedTemplateCount, len(findings))
	if len(validation.UnmappedProducts) > 0 {
		builder.WriteString("Unmapped products: " + markdownCell(strings.Join(validation.UnmappedProducts, ", ")) + ".\n\n")
	}
	switch status {
	case model.ScanTaskRunValidationDisabled:
		builder.WriteString("Vulnerability validation was not enabled for this run.\n\n")
	case model.ScanTaskRunValidationNotStarted:
		builder.WriteString("Vulnerability validation did not start because the scan stopped in an earlier phase. No security conclusion can be drawn.\n\n")
	case model.ScanTaskRunValidationNoCandidates:
		builder.WriteString("Validation was enabled, but no usable endpoint/template candidate was available. No security conclusion can be drawn.\n\n")
	case model.ScanTaskRunValidationFailed:
		fmt.Fprintf(builder, "Validation failed: %s\n\n", markdownCell(validation.Error))
	case model.ScanTaskRunValidationSuccess:
		if len(findings) == 0 {
			builder.WriteString("Validation executed successfully and recorded no findings.\n\n")
		} else {
			builder.WriteString("Validation executed successfully and recorded findings.\n\n")
		}
	default:
		builder.WriteString("Validation state is unavailable for this historical run.\n\n")
	}
	builder.WriteString("### Risk Summary\n\n")
	builder.WriteString("| Critical | High | Medium | Low | Info | Unknown |\n| ---: | ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(builder, "| %d | %d | %d | %d | %d | %d |\n\n", severityCounts["critical"], severityCounts["high"], severityCounts["medium"], severityCounts["low"], severityCounts["info"], severityCounts["unknown"])
	builder.WriteString("### Findings\n\n")
	if len(findings) == 0 {
		builder.WriteString("No vulnerability findings were recorded.\n\n")
		return
	}
	builder.WriteString("| Severity | Name | Endpoint | Template | Matched at | Summary |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, finding := range findings {
		fmt.Fprintf(builder, "| %s | %s | %s | %s | %s | %s |\n", markdownCell(finding.Severity), markdownCell(finding.Name), markdownCell(finding.Target), markdownCell(finding.TemplateID), markdownCell(finding.MatchedAt), markdownCell(finding.Description))
	}
	builder.WriteString("\n")
}

func writeRunEndpointProfiles(builder *strings.Builder, report ScanTaskRunReport) {
	builder.WriteString("## Endpoint Profiles\n\n")
	if len(report.Snapshot.Ports) == 0 {
		builder.WriteString("No open ports were recorded.\n\n")
		return
	}
	evidenceByPort := make(map[string][]model.ScanTaskRunProtocolEvidence)
	for _, evidence := range report.Snapshot.ProtocolEvidence {
		key := fmt.Sprintf("%s:%d", evidence.IP, evidence.Port)
		evidenceByPort[key] = append(evidenceByPort[key], evidence)
	}
	conclusionsByPort := make(map[string][]map[string]interface{})
	for _, conclusion := range report.FingerprintConclusions {
		key := fmt.Sprintf("%s:%d", reportMapString(conclusion, "ip"), reportMapInt(conclusion, "port"))
		conclusionsByPort[key] = append(conclusionsByPort[key], conclusion)
	}
	sourcesByProduct := endpointProductSources(report.FingerprintMatches)
	for _, port := range report.Snapshot.Ports {
		key := fmt.Sprintf("%s:%d", port.IP, port.Port)
		conclusions := conclusionsByPort[key]
		fmt.Fprintf(builder, "### %s\n\n", markdownCell(key))
		builder.WriteString("| Layer | Result |\n| --- | --- |\n")
		fmt.Fprintf(builder, "| Port and transport | open / TCP |\n")
		fmt.Fprintf(builder, "| Basic service | %s |\n", markdownCell(port.ServiceType))
		fmt.Fprintf(builder, "| Protocol response | %s |\n", markdownCell(protocolEvidenceSummary(evidenceByPort[key])))
		fmt.Fprintf(builder, "| Vulnerability validation | %s |\n\n", markdownCell(endpointValidationSummary(report.Snapshot, port, conclusions)))

		if len(conclusions) == 0 {
			builder.WriteString("Technology stack: no product fingerprint conclusion was recorded.\n\n")
		} else {
			sort.Slice(conclusions, func(left, right int) bool {
				leftRole, rightRole := reportMapString(conclusions[left], "product_role"), reportMapString(conclusions[right], "product_role")
				if fingerprintRoleRank(leftRole) != fingerprintRoleRank(rightRole) {
					return fingerprintRoleRank(leftRole) < fingerprintRoleRank(rightRole)
				}
				return reportMapString(conclusions[left], "product_key") < reportMapString(conclusions[right], "product_key")
			})
			builder.WriteString("| Technology role | Product | Version | CPE | Recognition sources | Evidence status |\n| --- | --- | --- | --- | --- | --- |\n")
			for _, conclusion := range conclusions {
				product := reportMapString(conclusion, "product_key")
				sourceKey := key + "\x00" + reportMapString(conclusion, "protocol") + "\x00" + product
				fmt.Fprintf(builder, "| %s | %s | %s | %s | %s | %s |\n",
					markdownCell(fingerprintRoleLabel(reportMapString(conclusion, "product_role"))), markdownCell(product),
					markdownCell(reportMapString(conclusion, "version")), markdownCell(reportMapString(conclusion, "cpe")),
					markdownCell(strings.Join(sourcesByProduct[sourceKey], ", ")), markdownCell(reportMapString(conclusion, "product_status")))
			}
			builder.WriteString("\n")
		}
		if reasons := endpointUnresolvedReasons(report.Snapshot, port, conclusions); len(reasons) > 0 {
			builder.WriteString("Unresolved reasons: " + markdownCell(strings.Join(reasons, "; ")) + ".\n\n")
		}
	}
}

func endpointProductSources(matches []map[string]interface{}) map[string][]string {
	sets := make(map[string]map[string]struct{})
	for _, match := range matches {
		if soft, ok := match["soft_match"].(bool); ok && soft {
			continue
		}
		key := fmt.Sprintf("%s:%d\x00%s\x00%s", reportMapString(match, "ip"), reportMapInt(match, "port"), reportMapString(match, "protocol"), reportMapString(match, "product_key"))
		if sets[key] == nil {
			sets[key] = make(map[string]struct{})
		}
		if source := strings.TrimSpace(reportMapString(match, "source_key")); source != "" {
			sets[key][source] = struct{}{}
		}
	}
	result := make(map[string][]string, len(sets))
	for key, values := range sets {
		for value := range values {
			result[key] = append(result[key], value)
		}
		sort.Strings(result[key])
	}
	return result
}

func fingerprintRoleRank(role string) int {
	order := map[string]int{"network_service": 0, "database": 1, "web_server": 2, "runtime": 3, "framework": 4, "middleware": 5, "cms_application": 6, "control_panel": 7, "frontend": 8, "operating_system": 9, "application": 10}
	if rank, ok := order[role]; ok {
		return rank
	}
	return 99
}

func fingerprintRoleLabel(role string) string {
	labels := map[string]string{"network_service": "Network service", "database": "Database", "web_server": "Web server", "runtime": "Runtime / language", "framework": "Framework", "middleware": "Middleware", "cms_application": "CMS / application", "control_panel": "Control panel", "frontend": "Frontend", "operating_system": "Operating system", "application": "Application"}
	if label := labels[role]; label != "" {
		return label
	}
	if role == "" {
		return "Application"
	}
	return role
}

func endpointValidationSummary(snapshot model.ScanTaskRunSnapshot, port model.ScanTaskRunPort, conclusions []map[string]interface{}) string {
	endpointSummaries := make([]string, 0)
	for _, validation := range snapshot.EndpointValidations {
		if validation.IP != port.IP || validation.Port != port.Port {
			continue
		}
		reason := ""
		if validation.Reason != "" {
			reason = "; reason=" + validation.Reason
		}
		endpointSummaries = append(endpointSummaries, fmt.Sprintf("%s: %s%s; candidate templates=%d; executed templates=%d; findings=%d", validation.Protocol, validation.Status, reason, validation.CandidateTemplateCount, validation.ExecutedTemplateCount, validation.FindingCount))
	}
	if len(endpointSummaries) > 0 {
		sort.Strings(endpointSummaries)
		return strings.Join(endpointSummaries, " | ")
	}
	candidates := make(map[string]struct{})
	executedTemplates := make(map[string]struct{})
	findings := 0
	for _, candidate := range snapshot.TemplateCandidates {
		if candidate.IP == port.IP && candidate.Port == port.Port {
			key := candidate.TemplateID + "\x00" + candidate.Path
			candidates[key] = struct{}{}
			if candidate.Executed {
				executedTemplates[key] = struct{}{}
			}
		}
	}
	for _, finding := range snapshot.Vulnerabilities {
		if finding.TargetIP == port.IP && finding.TargetPort == port.Port {
			findings++
		}
	}
	status := snapshot.Validation.Status
	if status == "" {
		status = "unavailable"
	} else if status == model.ScanTaskRunValidationSuccess && len(candidates) == 0 {
		status = model.ScanTaskRunValidationNoCandidates
	}
	reason := ""
	if status == model.ScanTaskRunValidationNoCandidates {
		if len(conclusions) == 0 {
			reason = "; reason=unidentified product"
		} else {
			reason = "; reason=no template mapping"
		}
	}
	return fmt.Sprintf("%s%s; candidate templates=%d; executed templates=%d; findings=%d", status, reason, len(candidates), len(executedTemplates), findings)
}

func endpointUnresolvedReasons(snapshot model.ScanTaskRunSnapshot, port model.ScanTaskRunPort, conclusions []map[string]interface{}) []string {
	reasons := make([]string, 0, 3)
	responded := false
	for _, evidence := range snapshot.ProtocolEvidence {
		if evidence.IP == port.IP && evidence.Port == port.Port && evidence.Responded {
			responded = true
			break
		}
	}
	if !responded {
		reasons = append(reasons, "no protocol response was captured")
	}
	if len(conclusions) == 0 {
		reasons = append(reasons, "product was not identified")
	}
	mappedProducts := make(map[string]struct{})
	for _, candidate := range snapshot.TemplateCandidates {
		if candidate.IP == port.IP && candidate.Port == port.Port && strings.TrimSpace(candidate.ProductKey) != "" {
			mappedProducts[strings.ToLower(strings.TrimSpace(candidate.ProductKey))] = struct{}{}
		}
	}
	for _, conclusion := range conclusions {
		product := strings.TrimSpace(reportMapString(conclusion, "product_key"))
		if product == "" {
			continue
		}
		if _, mapped := mappedProducts[strings.ToLower(product)]; !mapped {
			reasons = append(reasons, "no template mapping for "+product)
		}
	}
	endpointStateFound := false
	for _, validation := range snapshot.EndpointValidations {
		if validation.IP != port.IP || validation.Port != port.Port {
			continue
		}
		endpointStateFound = true
		if validation.Reason != "" {
			reasons = append(reasons, validation.Protocol+": "+validation.Reason)
		}
	}
	if endpointStateFound {
		return uniqueReportStrings(reasons)
	}
	switch snapshot.Validation.Status {
	case model.ScanTaskRunValidationDisabled:
		reasons = append(reasons, "vulnerability validation was disabled")
	case model.ScanTaskRunValidationNotStarted:
		reasons = append(reasons, "vulnerability validation did not start")
	case model.ScanTaskRunValidationNoCandidates:
		reasons = append(reasons, "no usable template mapping or candidate")
	case model.ScanTaskRunValidationFailed:
		reasons = append(reasons, "vulnerability validation failed")
	case model.ScanTaskRunValidationSuccess:
		if len(mappedProducts) == 0 {
			reasons = append(reasons, "no usable template mapping or candidate")
		}
	}
	return uniqueReportStrings(reasons)
}

func uniqueReportStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func protocolEvidenceSummary(evidence []model.ScanTaskRunProtocolEvidence) string {
	parts := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.EvidenceType == model.ProtocolEvidencePassiveBanner || (item.EvidenceType == "" && item.Protocol == "tcp") {
			if item.Responded {
				parts = append(parts, fmt.Sprintf("TCP banner %d bytes", item.BannerCapturedLength))
			}
			continue
		}
		if item.EvidenceType == model.ProtocolEvidenceActiveProbe {
			if item.Responded {
				parts = append(parts, fmt.Sprintf("TCP probe %s %d bytes", item.ProbeName, item.BannerCapturedLength))
			} else {
				outcome := item.Outcome
				if outcome == "" {
					outcome = model.ProtocolProbeOutcomeNoResponse
				}
				parts = append(parts, fmt.Sprintf("TCP probe %s %s", item.ProbeName, outcome))
			}
			continue
		}
		if !item.Responded {
			continue
		}
		value := strings.ToUpper(item.Protocol)
		if item.StatusCode > 0 {
			value += fmt.Sprintf(" %d", item.StatusCode)
		}
		if item.Server != "" {
			value += " server=" + item.Server
		}
		if item.Title != "" {
			value += " title=" + item.Title
		}
		value += fmt.Sprintf(" response=%d bytes", item.BodyCapturedLength)
		parts = append(parts, value)
	}
	if len(parts) == 0 {
		return "No protocol response summary; passive banner unavailable"
	}
	return strings.Join(parts, "; ")
}

func RenderScanTaskRunAuditMarkdown(report ScanTaskRunReport) string {
	generatedAt := report.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	var builder strings.Builder
	builder.WriteString("# yscan CAASM Scan Task Run Audit Report\n\n")
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

	builder.WriteString("## Frozen Fingerprint Revisions\n\n")
	if len(report.FingerprintImports) == 0 {
		builder.WriteString("No fingerprint revisions were frozen for this run.\n\n")
	} else {
		builder.WriteString("| Import | Source | Upstream Revision | Adapter | Projection SHA-256 |\n| --- | --- | --- | --- | --- |\n")
		for _, fingerprintImport := range report.FingerprintImports {
			fmt.Fprintf(&builder, "| %d | %d | %s | %s | %s |\n", fingerprintImport.ID, fingerprintImport.FingerprintSourceID, markdownCell(fingerprintImport.Commit), markdownCell(fingerprintImport.AdapterVersion), markdownCell(fingerprintImport.ProjectionSHA256))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Fingerprint Conclusions\n\n")
	if len(report.FingerprintConclusions) == 0 {
		builder.WriteString("No definite fingerprint conclusions were recorded.\n\n")
	} else {
		builder.WriteString("| Endpoint | Product | Role / Exclusive group | Product evidence status | Version evidence status | CPE evidence status | Tags |\n| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, conclusion := range report.FingerprintConclusions {
			fmt.Fprintf(&builder, "| %s:%d/%s | %s | %s / %s | %s (%d sources) | %s / %s (%d sources) | %s / %s (%d sources) | %s |\n",
				markdownCell(reportMapString(conclusion, "ip")), reportMapInt(conclusion, "port"), markdownCell(reportMapString(conclusion, "protocol")),
				markdownCell(reportMapString(conclusion, "product_key")), markdownCell(reportMapString(conclusion, "product_role")), markdownCell(reportMapString(conclusion, "exclusive_group")), markdownCell(reportMapString(conclusion, "product_status")), reportMapInt(conclusion, "product_source_count"),
				markdownCell(reportMapString(conclusion, "version")), markdownCell(reportMapString(conclusion, "version_status")), reportMapInt(conclusion, "version_source_count"),
				markdownCell(reportMapString(conclusion, "cpe")), markdownCell(reportMapString(conclusion, "cpe_status")), reportMapInt(conclusion, "cpe_source_count"),
				markdownCell(reportMapStringSlice(conclusion, "tags")))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Fingerprint Evidence\n\n")
	if len(report.FingerprintMatches) == 0 {
		builder.WriteString("No fingerprint matcher evidence was recorded.\n\n")
	} else {
		builder.WriteString("| Endpoint | Product | Source Rule | Matcher Evidence |\n| --- | --- | --- | --- |\n")
		for _, match := range report.FingerprintMatches {
			product := reportMapString(match, "product_key")
			if sourceProduct := reportMapString(match, "source_product"); sourceProduct != "" && !strings.EqualFold(sourceProduct, product) {
				product += " (source: " + sourceProduct + ")"
			}
			fmt.Fprintf(&builder, "| %s:%d/%s | %s | %s / %s | %s |\n",
				markdownCell(reportMapString(match, "ip")), reportMapInt(match, "port"), markdownCell(reportMapString(match, "protocol")),
				markdownCell(product), markdownCell(reportMapString(match, "source_key")), markdownCell(reportMapString(match, "source_rule_id")),
				markdownCell(reportMatcherEvidence(match)))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Validation Plan\n\n")
	if len(report.Snapshot.TemplateCandidates) == 0 {
		builder.WriteString("No validation templates were selected.\n\n")
	} else {
		builder.WriteString("| Endpoint | Product | Template | Source | Executed | Mapping Revision | Template SHA-256 | Reason |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, candidate := range report.Snapshot.TemplateCandidates {
			endpoint := "-"
			if candidate.IP != "" {
				endpoint = fmt.Sprintf("%s:%d/%s", candidate.IP, candidate.Port, candidate.Protocol)
			}
			fmt.Fprintf(&builder, "| %s | %s | %s | %s | %t | %s | %s | %s |\n", markdownCell(endpoint), markdownCell(candidate.ProductKey), markdownCell(candidate.TemplateID), markdownCell(candidate.Source), candidate.Executed, markdownCell(candidate.TemplateSetRevision), markdownCell(candidate.TemplateSHA256), markdownCell(candidate.Reason))
		}
		builder.WriteString("\n")
	}
	builder.WriteString("## Vulnerability Summary\n\n")
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

func reportMapString(value map[string]interface{}, key string) string {
	if value[key] == nil {
		return ""
	}
	if text, ok := value[key].(string); ok {
		return text
	}
	return fmt.Sprint(value[key])
}

func reportMapInt(value map[string]interface{}, key string) int {
	switch number := value[key].(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	default:
		return 0
	}
}

func reportMapStringSlice(value map[string]interface{}, key string) string {
	switch values := value[key].(type) {
	case []string:
		return strings.Join(values, ", ")
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, item := range values {
			out = append(out, fmt.Sprint(item))
		}
		return strings.Join(out, ", ")
	default:
		return ""
	}
}

func reportMatcherEvidence(match map[string]interface{}) string {
	values, ok := match["matcher_evidence"].([]map[string]interface{})
	if !ok {
		return ""
	}
	summaries := make([]string, 0, len(values))
	for _, evidence := range values {
		summaries = append(summaries, reportMapString(evidence, "summary"))
	}
	return strings.Join(summaries, "; ")
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
