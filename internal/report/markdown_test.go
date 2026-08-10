package report

import (
	"database/sql"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestRenderMarkdownIncludesRequiredSections(t *testing.T) {
	content := RenderMarkdown(TaskReport{
		Task: model.Task{ID: 3, TaskType: model.TaskTypeScanSubnet, Target: "192.168.1.0/24", Status: model.TaskStatusSuccess},
		Changes: model.TaskChangeSummary{
			HostChanges: model.HostChanges{NewHosts: []string{"192.168.1.10"}},
			PortChanges: model.PortChanges{Opened: []model.PortChange{{IP: "192.168.1.10", Port: 443}}},
		},
		Findings:    []model.Vulnerability{{Severity: "high", TemplateID: "test-template", TargetIP: "192.168.1.10", Name: "Test Finding"}},
		GeneratedAt: time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC),
	})

	for _, section := range []string{"## Task Summary", "## Host Changes", "## Port Changes", "## Vulnerability Summary", "192.168.1.10:443", "test-template"} {
		if !strings.Contains(content, section) {
			t.Fatalf("report does not contain %q", section)
		}
	}
}

func TestWriteAndReadTaskReport(t *testing.T) {
	directory := t.TempDir()
	path, err := WriteTaskReport(directory, TaskReport{Task: model.Task{ID: 8, Target: "10.0.0.0/24"}})
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat report: %v", err)
	}
	content, err := ReadTaskReport(directory, 8)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(content), "yscan CAASM Task Report") {
		t.Fatalf("unexpected report content: %s", content)
	}
}

func TestWriteAndReadScanTaskRunReport(t *testing.T) {
	directory := t.TempDir()
	report := ScanTaskRunReport{
		Task: model.ScanTask{ID: 7, Target: "192.168.1.0/24"},
		Run:  model.ScanTaskRun{ID: 9, ScanTaskID: 7, Status: model.ScanTaskRunStatusSuccess},
	}
	if _, err := WriteScanTaskRunReport(directory, report); err != nil {
		t.Fatalf("write scan task run report: %v", err)
	}
	content, err := ReadScanTaskRunReport(directory, 7, 9)
	if err != nil {
		t.Fatalf("read scan task run report: %v", err)
	}
	if !strings.Contains(string(content), "yscan CAASM Scan Task Run Report") {
		t.Fatalf("unexpected report content: %s", content)
	}
	audit, err := ReadScanTaskRunAuditReport(directory, 7, 9)
	if err != nil || !strings.Contains(string(audit), "yscan CAASM Scan Task Run Audit Report") {
		t.Fatalf("unexpected audit report content=%s err=%v", audit, err)
	}
}

func TestWriteScanTaskRunReportDoesNotLeaveOrphanWhenPairCommitFails(t *testing.T) {
	directory := t.TempDir()
	originalRename := renameScanTaskRunReportFile
	t.Cleanup(func() { renameScanTaskRunReportFile = originalRename })
	renameScanTaskRunReportFile = func(oldPath, newPath string) error {
		if strings.HasSuffix(newPath, "-audit.md") {
			return errors.New("forced audit rename failure")
		}
		return os.Rename(oldPath, newPath)
	}
	_, err := WriteScanTaskRunReport(directory, ScanTaskRunReport{Task: model.ScanTask{ID: 7}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7}})
	if err == nil {
		t.Fatal("paired report write must fail")
	}
	for _, path := range []string{ScanTaskRunReportPath(directory, 7, 9), ScanTaskRunAuditReportPath(directory, 7, 9)} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("orphan report remains at %s: %v", path, statErr)
		}
	}
}

func TestWriteScanTaskRunReportRestoresExistingPairWhenAuditCommitFails(t *testing.T) {
	directory := t.TempDir()
	oldReport := ScanTaskRunReport{Task: model.ScanTask{ID: 7, Target: "old-target"}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7}}
	paths, err := WriteScanTaskRunReport(directory, oldReport)
	if err != nil {
		t.Fatal(err)
	}
	oldUser, _ := os.ReadFile(paths.User)
	oldAudit, _ := os.ReadFile(paths.Audit)
	originalRename := renameScanTaskRunReportFile
	t.Cleanup(func() { renameScanTaskRunReportFile = originalRename })
	renameScanTaskRunReportFile = func(oldPath, newPath string) error {
		if strings.HasSuffix(newPath, "-audit.md") {
			return errors.New("forced audit overwrite failure")
		}
		return os.Rename(oldPath, newPath)
	}
	_, err = WriteScanTaskRunReport(directory, ScanTaskRunReport{Task: model.ScanTask{ID: 7, Target: "new-target"}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7}})
	if err == nil {
		t.Fatal("overwriting pair must fail")
	}
	user, userErr := os.ReadFile(paths.User)
	audit, auditErr := os.ReadFile(paths.Audit)
	if userErr != nil || auditErr != nil || string(user) != string(oldUser) || string(audit) != string(oldAudit) {
		t.Fatalf("old pair was not restored user_err=%v audit_err=%v", userErr, auditErr)
	}
}

func TestReadRecoversInterruptedReportPair(t *testing.T) {
	directory := t.TempDir()
	oldReport := ScanTaskRunReport{Task: model.ScanTask{ID: 7, Target: "old-target"}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7}}
	paths, err := WriteScanTaskRunReport(directory, oldReport)
	if err != nil {
		t.Fatal(err)
	}
	oldUser, _ := os.ReadFile(paths.User)
	oldAudit, _ := os.ReadFile(paths.Audit)
	if _, err := prepareScanTaskRunReport(directory, ScanTaskRunReport{Task: model.ScanTask{ID: 7, Target: "new-target"}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7}}); err != nil {
		t.Fatal(err)
	}
	user, userErr := ReadScanTaskRunReport(directory, 7, 9)
	audit, auditErr := ReadScanTaskRunAuditReport(directory, 7, 9)
	if userErr != nil || auditErr != nil || string(user) != string(oldUser) || string(audit) != string(oldAudit) {
		t.Fatalf("interrupted pair recovery user_err=%v audit_err=%v", userErr, auditErr)
	}
}

func TestRunReportRendersFrozenRevisionConclusionsEvidenceAndMapping(t *testing.T) {
	content := RenderScanTaskRunAuditMarkdown(ScanTaskRunReport{
		Task: model.ScanTask{ID: 7}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7},
		FingerprintImports:     []model.FingerprintImport{{ID: 11, FingerprintSourceID: 3, Commit: "upstream-r1", AdapterVersion: "adapter-v2", ProjectionSHA256: "projection-sha"}},
		FingerprintConclusions: []map[string]interface{}{{"ip": "192.168.75.1", "port": 443, "protocol": "https", "product_key": "openssh", "version": "9.6", "cpe": "cpe:/a:openbsd:openssh:9.6", "tags": []string{"ssh"}, "conclusion_status": "corroborated", "product_status": "corroborated", "product_source_count": 2, "version_status": "matched", "version_source_count": 1, "cpe_status": "matched", "cpe_source_count": 1}},
		FingerprintMatches:     []map[string]interface{}{{"ip": "192.168.75.1", "port": 443, "protocol": "https", "product_key": "openssh", "source_key": "nmap", "source_rule_id": "fixture", "matcher_evidence": []map[string]interface{}{{"summary": "tcp_banner banner bytes=16 sha256=redacted"}}}},
		Snapshot:               model.ScanTaskRunSnapshot{TemplateCandidates: []model.ScanTaskRunTemplateCandidate{{TemplateID: "openssh-check", Path: "tcp/openssh.yaml", Source: "fingerprint_mapping", Reason: "approved mapping", IP: "192.168.75.1", Port: 443, Protocol: "https", TemplateSetRevision: "templates-r1", TemplateSHA256: "template-sha"}}},
	})
	for _, expected := range []string{"## Frozen Fingerprint Revisions", "adapter-v2", "projection-sha", "## Fingerprint Conclusions", "Product evidence status", "Version evidence status", "CPE evidence status", "corroborated (2 sources)", "9.6 / matched (1 sources)", "cpe:/a:openbsd:openssh:9.6 / matched (1 sources)", "## Fingerprint Evidence", "tcp_banner banner bytes=16 sha256=redacted", "192.168.75.1:443/https", "templates-r1", "template-sha"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("report missing %q:\n%s", expected, content)
		}
	}
	if strings.Contains(content, "confidence") {
		t.Fatalf("report must use categorical evidence status terminology:\n%s", content)
	}
	if strings.Contains(content, "raw response") {
		t.Fatal("report exposed raw response")
	}
}

func TestRunUserReportLeadsWithValidationAndKeepsAuditDetailsOut(t *testing.T) {
	content := RenderScanTaskRunMarkdown(ScanTaskRunReport{
		Task: model.ScanTask{ID: 7}, Run: model.ScanTaskRun{ID: 9, ScanTaskID: 7, Target: "192.168.75.1", Status: model.ScanTaskRunStatusSuccess},
		Snapshot: model.ScanTaskRunSnapshot{
			Validation:         model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationSuccess, CandidateEndpointCount: 2, ExecutedEndpointCount: 2, TemplateCount: 3, FindingCount: 1},
			Ports:              []model.ScanTaskRunPort{{IP: "192.168.75.1", Port: 23333, ServiceType: "http", Product: "nginx"}},
			ProtocolEvidence:   []model.ScanTaskRunProtocolEvidence{{IP: "192.168.75.1", Port: 23333, Protocol: "http", Responded: true, StatusCode: 500, Server: "nginx", BodyCapturedLength: 2422}},
			Vulnerabilities:    []model.ScanTaskRunVulnerability{{FindingKey: "test", TemplateID: "test-template", Name: "Test vulnerability", Severity: "high", Target: "http://192.168.75.1:23333", MatchedAt: "/admin", Description: "Readable a | b vulnerability description", Evidence: `{"raw":"nuclei-json"}`}},
			TemplateCandidates: []model.ScanTaskRunTemplateCandidate{{TemplateID: "internal-only", Path: "private.yaml", Source: "fingerprint_mapping", Reason: "audit only"}},
		},
		FingerprintImports: []model.FingerprintImport{{ID: 11, ProjectionSHA256: "audit-sha"}},
		FingerprintConclusions: []map[string]interface{}{
			{"ip": "192.168.75.1", "port": 23333, "protocol": "http", "product_key": "nginx", "product_role": "web_server", "version": "1.24", "cpe": "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*", "product_status": "corroborated"},
			{"ip": "192.168.75.1", "port": 23333, "protocol": "http", "product_key": "php", "product_role": "runtime", "version": "8.1", "product_status": "matched"},
		},
		FingerprintMatches: []map[string]interface{}{
			{"ip": "192.168.75.1", "port": 23333, "protocol": "http", "product_key": "nginx", "source_key": "wappalyzer", "source_rule_id": "nginx-header"},
			{"ip": "192.168.75.1", "port": 23333, "protocol": "http", "product_key": "php", "source_key": "whatweb", "source_rule_id": "php-header"},
		},
	})
	validationIndex := strings.Index(content, "## Vulnerability Validation")
	serviceIndex := strings.Index(content, "## Endpoint Profiles")
	if validationIndex < 0 || serviceIndex < 0 || validationIndex > serviceIndex {
		t.Fatalf("user report does not lead with validation:\n%s", content)
	}
	for _, expected := range []string{"success", "Test vulnerability", `Readable a \| b vulnerability description`, "high", "HTTP 500 server=nginx response=2422 bytes", "Web server", "Runtime / language", "nginx", "php", "1.24", "cpe:2.3:a:nginx:nginx:1.24", "wappalyzer", "whatweb"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("user report missing %q:\n%s", expected, content)
		}
	}
	for _, forbidden := range []string{"Frozen Fingerprint Revisions", "audit-sha", "internal-only", "private.yaml", `{"raw":"nuclei-json"}`} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("user report exposed audit detail %q:\n%s", forbidden, content)
		}
	}
}

func TestEndpointReportMarksRunSuccessWithoutEndpointCandidatesAsUnmapped(t *testing.T) {
	port := model.ScanTaskRunPort{IP: "192.168.75.2", Port: 22222, ServiceType: "ssh"}
	snapshot := model.ScanTaskRunSnapshot{Validation: model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationSuccess}}
	conclusions := []map[string]interface{}{{"product_key": "dropbear"}}
	if summary := endpointValidationSummary(snapshot, port, conclusions); !strings.Contains(summary, "no_candidates") || !strings.Contains(summary, "no template mapping") {
		t.Fatalf("endpoint validation summary=%q", summary)
	}
	reasons := endpointUnresolvedReasons(snapshot, port, conclusions)
	if !strings.Contains(strings.Join(reasons, "|"), "no template mapping for dropbear") {
		t.Fatalf("endpoint unresolved reasons=%#v", reasons)
	}
}

func TestGenerateScanTaskRunReportUsesTaskLocalRunDiff(t *testing.T) {
	db := openRunReportDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.10.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create scan task: %v", err)
	}
	first := completeRunReportTest(t, db, task.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.10", Port: 80, ServiceType: "http"}},
	})
	second := completeRunReportTest(t, db, task.ID, "2026-07-25T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}, {IP: "192.168.10.20", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.10", Port: 443, ServiceType: "https"}},
		Vulnerabilities: []model.ScanTaskRunVulnerability{{
			FindingKey: "CVE-2026-0001|https://192.168.10.10|192.168.10.10|443",
			TemplateID: "CVE-2026-0001",
			Severity:   "high",
			Target:     "https://192.168.10.10",
			TargetIP:   "192.168.10.10",
			TargetPort: 443,
		}},
	})
	if first.ID == 0 {
		t.Fatal("first run must be created")
	}
	if err := storage.UpdateScanTaskRunReportError(db, second.ID, "previous write failed"); err != nil {
		t.Fatalf("seed report diagnostic: %v", err)
	}

	directory := t.TempDir()
	path, err := GenerateScanTaskRunReport(db, task.ID, second.ID, directory)
	if err != nil {
		t.Fatalf("generate run report: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read run report: %v", err)
	}
	for _, expected := range []string{
		"yscan CAASM Scan Task Run Report",
		"| Logical Task ID | " + strconv.FormatInt(task.ID, 10) + " |",
		"| Run ID | " + strconv.FormatInt(second.ID, 10) + " |",
		"192.168.10.20",
		"192.168.10.10:443",
		"CVE-2026-0001",
	} {
		if !strings.Contains(string(content), expected) {
			t.Fatalf("run report does not contain %q:\n%s", expected, content)
		}
	}
	persisted, err := storage.GetScanTaskRun(db, second.ID)
	if err != nil || persisted.ReportPath != path || persisted.AuditReportPath != ScanTaskRunAuditReportPath(directory, task.ID, second.ID) || persisted.ReportError != "" {
		t.Fatalf("persisted report = %#v, error = %v, want path %q and cleared diagnostic", persisted, err, path)
	}
}

func TestGenerateScanTaskRunReportRestoresExistingPairWhenDatabaseUpdateFails(t *testing.T) {
	db := openRunReportDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{Target: "192.168.20.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	run := completeRunReportTest(t, db, task.ID, "2026-07-26T02:00:00Z", model.ScanTaskRunSnapshot{})
	directory := t.TempDir()
	paths, err := WriteScanTaskRunReport(directory, ScanTaskRunReport{Task: task, Run: run, GeneratedAt: time.Date(2026, 7, 26, 3, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	oldUser, _ := os.ReadFile(paths.User)
	oldAudit, _ := os.ReadFile(paths.Audit)
	originalUpdate := updateScanTaskRunReportPaths
	t.Cleanup(func() { updateScanTaskRunReportPaths = originalUpdate })
	updateScanTaskRunReportPaths = func(*sql.DB, int64, string, string) error { return errors.New("forced database update failure") }
	if _, err := GenerateScanTaskRunReport(db, task.ID, run.ID, directory); err == nil {
		t.Fatal("database update failure must be returned")
	}
	user, userErr := os.ReadFile(paths.User)
	audit, auditErr := os.ReadFile(paths.Audit)
	if userErr != nil || auditErr != nil || string(user) != string(oldUser) || string(audit) != string(oldAudit) {
		t.Fatalf("database failure did not restore old pair user_err=%v audit_err=%v", userErr, auditErr)
	}
}

func TestGenerateScanTaskRunReportProjectsReportingRunAsSuccessful(t *testing.T) {
	db := openRunReportDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{Target: "192.168.21.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-27T02:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, stage = ?, progress = 95 WHERE id = ?`, model.ScanTaskRunStatusRunning, model.ScanTaskRunStageSnapshot, run.ID); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveScanTaskRunSnapshot(db, model.ScanTaskRunSnapshot{RunID: run.ID, Hosts: []model.ScanTaskRunHost{{IP: "192.168.21.10", IsActive: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.UpdateScanTaskRunProgress(db, run.ID, model.ScanTaskRunStageReporting, 99); err != nil {
		t.Fatal(err)
	}
	path, err := GenerateScanTaskRunReport(db, task.ID, run.ID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "| Run Status | success |") || !strings.Contains(string(content), "192.168.21.10") {
		t.Fatalf("report did not project successful outcome and Diff:\n%s", content)
	}
	persisted, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || persisted.Status != model.ScanTaskRunStatusRunning || persisted.Stage != model.ScanTaskRunStageReporting || persisted.Progress != 99 {
		t.Fatalf("report generation published terminal status: %#v err=%v", persisted, err)
	}
}

func openRunReportDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open report SQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT 'scheduled', stage TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, audit_report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
		`CREATE TABLE scan_task_run_hosts (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, is_active INTEGER NOT NULL, PRIMARY KEY(scan_task_run_id, ip))`,
		`CREATE TABLE scan_task_run_ports (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, product TEXT, banner TEXT, PRIMARY KEY(scan_task_run_id, ip, port))`,
		`CREATE TABLE scan_task_run_vulnerabilities (scan_task_run_id INTEGER NOT NULL, finding_key TEXT NOT NULL, template_id TEXT, name TEXT, severity TEXT, target TEXT NOT NULL, target_ip TEXT, target_port INTEGER, matched_at TEXT, description TEXT, evidence TEXT, PRIMARY KEY(scan_task_run_id, finding_key))`,
		`CREATE TABLE scan_task_run_template_candidates (scan_task_run_id INTEGER NOT NULL, template_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(scan_task_run_id, template_id, path))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create report schema: %v", err)
		}
	}
	return db
}

func completeRunReportTest(t *testing.T, db *sql.DB, taskID int64, scheduledFor string, snapshot model.ScanTaskRunSnapshot) model.ScanTaskRun {
	t.Helper()
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: taskID, ScheduledFor: scheduledFor})
	if err != nil {
		t.Fatalf("create report run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, run.ID); err != nil {
		t.Fatalf("start report run: %v", err)
	}
	snapshot.RunID = run.ID
	if err := storage.SaveScanTaskRunSnapshot(db, snapshot); err != nil {
		t.Fatalf("save report snapshot: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusSuccess, run.ID); err != nil {
		t.Fatalf("finish report run: %v", err)
	}
	return run
}
